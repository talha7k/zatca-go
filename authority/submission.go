// Invoice submission + status polling — the Go port of @talha7k/zatca
// dist/api (clearance.js, reporting.js, status.js, submission-response.js,
// diagnostics.js) as driven by the esellar drain engine
// (libsql-api/zatca/engine/application/authority-submit-port.ts): the
// server submits the client-minted bytes UNCHANGED and records whatever the
// gateway answers. Unlike the onboarding flows, transport failures DO
// surface as *TransportError — matching the TS, where request() rethrows
// ZatcaError on connection/timeout while parse outcomes stay results.
package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SubmitInvoiceRequest mirrors SubmitInvoiceRequest (types.d.ts) — the body
// of every submission call (clearance.js:19-22, reporting.js:37-41).
type SubmitInvoiceRequest struct {
	InvoiceHash string `json:"invoiceHash"`
	UUID        string `json:"uuid"`
	Invoice     string `json:"invoice"`
}

// APIErrorShape mirrors ZatcaApiError (types.d.ts).
type APIErrorShape struct {
	Code     string
	Category string
	Message  string
}

// SubmissionAlert mirrors ZatcaSubmissionAlert (types.d.ts).
type SubmissionAlert struct {
	Severity string // "error" | "warning"
	Code     string
	Category string
	Message  string
}

// SubmissionResponse mirrors ZatcaInvoiceResponse (types.d.ts). Absent
// optional fields are empty strings.
type SubmissionResponse struct {
	UUID              string
	InvoiceHash       string
	ClearedInvoice    string
	ClearanceDateTime string
	ClearanceStatus   string
	ReportingStatus   string
	Status            string // StatusAccepted | StatusRejected
	Error             *APIErrorShape
	Warnings          []APIErrorShape
}

// SubmitResult mirrors ZatcaSubmitResult (types.d.ts).
type SubmitResult struct {
	Success    bool
	Response   *SubmissionResponse
	Error      *APIErrorShape
	Alerts     []SubmissionAlert
	HTTPStatus int
	RawBody    string
}

// postSubmission performs one authenticated submission call with the
// Clearance-Status header (clearance.js:19-23, reporting.js:23-43).
func (c *Client) postSubmission(ctx context.Context, path string, credentials Credentials, request SubmitInvoiceRequest) (*httpResponse, *TransportError) {
	headers := c.baseHeaders()
	headers["Authorization"] = authHeader(credentials)
	headers["Clearance-Status"] = c.clearanceStatus
	body, _ := json.Marshal(request)
	return c.do(ctx, httpRequest{
		method:  http.MethodPost,
		url:     c.baseURL + path,
		headers: headers,
		body:    string(body),
	})
}

// ---- response parsing (submission-response.js + diagnostics.js) ----

// extractValidationDiagnostics ports extractValidationDiagnostics
// (diagnostics.js:16-44): error/warning message arrays normalize with
// default codes/categories, produce severity-tagged alerts, and aggregate
// the errors into a single combined error (codes joined by ",", messages
// "<code>: <message>" joined by "; ").
func extractValidationDiagnostics(validationResults map[string]any) (aggregated *APIErrorShape, warnings []APIErrorShape, alerts []SubmissionAlert) {
	var errorCodes, errorCategories []string
	var errorMessages []string
	for _, item := range sliceAt(validationResults, "errorMessages") {
		m, _ := item.(map[string]any)
		normalized := APIErrorShape{
			Code:     orDefault(strAt(m, "code"), "ZATCA_VALIDATION_ERROR"),
			Category: orDefault(strAt(m, "category"), "ZATCA"),
			Message:  orDefault(strAt(m, "message"), "ZATCA rejected the submitted document"),
		}
		errorCodes = append(errorCodes, normalized.Code)
		errorCategories = append(errorCategories, normalized.Category)
		errorMessages = append(errorMessages, normalized.Code+": "+normalized.Message)
		alerts = append(alerts, SubmissionAlert{Severity: "error", Code: normalized.Code, Category: normalized.Category, Message: normalized.Message})
	}
	for _, item := range sliceAt(validationResults, "warningMessages") {
		m, _ := item.(map[string]any)
		normalized := APIErrorShape{
			Code:     orDefault(strAt(m, "code"), "ZATCA_WARNING"),
			Category: orDefault(strAt(m, "category"), "ZATCA"),
			Message:  orDefault(strAt(m, "message"), "ZATCA returned a warning for the submitted document"),
		}
		warnings = append(warnings, normalized)
		alerts = append(alerts, SubmissionAlert{Severity: "warning", Code: normalized.Code, Category: normalized.Category, Message: normalized.Message})
	}
	if len(errorCodes) > 0 {
		aggregated = &APIErrorShape{
			Code:     strings.Join(errorCodes, ","),
			Category: strings.Join(errorCategories, ","),
			Message:  strings.Join(errorMessages, "; "),
		}
	}
	return aggregated, warnings, alerts
}

// parseInvoiceListResponse ports parseInvoiceListResponse
// (submission-response.js:32-66): the clearance-shaped response envelope.
// includeClearanceStatus / includeReportingStatus mirror the options
// object. Returns nil when no invoice entry is present (the caller then
// falls back to the {success: 2xx} shape).
func parseInvoiceListResponse(resp *httpResponse, data map[string]any, includeClearanceStatus bool, includeReportingStatus bool) *SubmitResult {
	var accepted map[string]any
	if list := sliceAt(data, "acceptedInvoices"); len(list) > 0 {
		accepted, _ = list[0].(map[string]any)
	}
	var rejected map[string]any
	if list := sliceAt(data, "rejectededInvoices"); len(list) > 0 {
		rejected, _ = list[0].(map[string]any)
	}
	if rejected == nil {
		// The alternate rejectedInvoices spelling (submission-response.js:34).
		if list := sliceAt(data, "rejectedInvoices"); len(list) > 0 {
			rejected, _ = list[0].(map[string]any)
		}
	}
	invoice := accepted
	if invoice == nil {
		invoice = rejected
	}
	if invoice == nil {
		return nil
	}

	aggregated, _, diagnosticAlerts := extractValidationDiagnostics(mapField(data, "validationResults"))

	var invoiceWarnings []APIErrorShape
	var invoiceAlerts []SubmissionAlert
	for _, item := range sliceAt(invoice, "warnings") {
		m, _ := item.(map[string]any)
		normalized := APIErrorShape{Code: strAt(m, "code"), Category: strAt(m, "category"), Message: strAt(m, "message")}
		invoiceWarnings = append(invoiceWarnings, normalized)
		invoiceAlerts = append(invoiceAlerts, SubmissionAlert{Severity: "warning", Code: normalized.Code, Category: normalized.Category, Message: normalized.Message})
	}

	// invoice.error overrides the diagnostics aggregate
	// (submission-response.js:46-47); a present-but-empty object still
	// normalizes (normalizeInvoiceError, lines 2-10).
	err := aggregated
	if invoiceError := mapField(invoice, "error"); invoiceError != nil {
		err = &APIErrorShape{
			Code:     strAt(invoiceError, "code"),
			Category: strAt(invoiceError, "category"),
			Message:  strAt(invoiceError, "message"),
		}
	}

	response := &SubmissionResponse{
		UUID:              strAt(invoice, "uuid"),
		InvoiceHash:       strAt(invoice, "invoiceHash"),
		ClearedInvoice:    strAt(invoice, "clearedInvoice"),
		ClearanceDateTime: strAt(invoice, "clearanceDateTime"),
		Warnings:          invoiceWarnings,
		Error:             err,
	}
	if includeClearanceStatus {
		response.ClearanceStatus = strAt(invoice, "clearanceStatus")
	}
	if includeReportingStatus {
		response.ReportingStatus = strAt(invoice, "reportingStatus")
	}
	response.Status = StatusRejected
	if accepted != nil {
		response.Status = StatusAccepted
	}

	return &SubmitResult{
		Success:    accepted != nil,
		HTTPStatus: resp.status,
		Error:      err,
		Alerts:     append(diagnosticAlerts, invoiceAlerts...),
		Response:   response,
		RawBody:    resp.body,
	}
}

// parseSubmissionResponse ports parseSubmissionResponse
// (submission-response.js:67-80): a JSON parse failure becomes a
// PARSE_ERROR/CLIENT result (never a Go error); a parse that yields no
// invoice envelope falls back to {success: 2xx, httpStatus, rawBody}. The
// submission parser accepts ANY JSON value as data (plain JSON.parse) — the
// object-only restriction is the onboarding plugin's ParseZatcaJSONObject.
func parseSubmissionResponse(resp *httpResponse, parseErrorMessage string, parseData func(map[string]any) *SubmitResult) *SubmitResult {
	var parsed any
	if err := json.Unmarshal([]byte(resp.body), &parsed); err != nil {
		parseErr := APIErrorShape{
			Code:     "PARSE_ERROR",
			Category: "CLIENT",
			Message:  fmt.Sprintf("%s: %v", parseErrorMessage, err),
		}
		return &SubmitResult{
			Success:    false,
			HTTPStatus: resp.status,
			Error:      &parseErr,
			Alerts:     []SubmissionAlert{{Severity: "error", Code: parseErr.Code, Category: parseErr.Category, Message: parseErr.Message}},
			RawBody:    resp.body,
		}
	}
	data, _ := parsed.(map[string]any)
	if result := parseData(data); result != nil {
		return result
	}
	return &SubmitResult{
		Success:    resp.status >= 200 && resp.status < 300,
		HTTPStatus: resp.status,
		RawBody:    resp.body,
	}
}

// SubmitForClearance ports ClearanceApi.clearInvoice (clearance.js:18-25):
// POST /invoices/clearance/single for standard (B2B) invoices —
// synchronous, must be cleared before delivery.
func (c *Client) SubmitForClearance(ctx context.Context, credentials Credentials, request SubmitInvoiceRequest) (*SubmitResult, error) {
	resp, transportErr := c.postSubmission(ctx, "/invoices/clearance/single", credentials, request)
	if transportErr != nil {
		return nil, transportErr
	}
	result := parseSubmissionResponse(resp, "Failed to parse clearance response", func(data map[string]any) *SubmitResult {
		return parseInvoiceListResponse(resp, data, true, false)
	})
	return result, nil
}

// parseReportingData is the parseData callback of parseReportingResponse
// (reporting.js:50-76): the reportingStatus branch first, then the
// clearance-shaped invoice-list fallback with reportingStatus pass-through.
func parseReportingData(resp *httpResponse, data map[string]any) *SubmitResult {
	if reportingStatus := strAt(data, "reportingStatus"); reportingStatus != "" {
		isSuccess := reportingStatus == "REPORTED"
		aggregated, warnings, alerts := extractValidationDiagnostics(mapField(data, "validationResults"))
		status := StatusRejected
		if isSuccess {
			status = StatusAccepted
		}
		return &SubmitResult{
			Success:    isSuccess,
			HTTPStatus: resp.status,
			Error:      aggregated,
			Alerts:     alerts,
			Response: &SubmissionResponse{
				UUID:            strAt(data, "uuid"),
				InvoiceHash:     strAt(data, "invoiceHash"),
				ReportingStatus: reportingStatus,
				Status:          status,
				Error:           aggregated,
				Warnings:        warnings,
			},
			RawBody: resp.body,
		}
	}
	return parseInvoiceListResponse(resp, data, false, true)
}

// isTerminalReportingResult ports isTerminalReportingResult
// (reporting.js:45-49): success, or a 4xx that is not 429, or an explicit
// ZATCA rejection — none of those may ever be retried.
func isTerminalReportingResult(result *SubmitResult) bool {
	if result.Success {
		return true
	}
	if result.HTTPStatus >= 400 && result.HTTPStatus < 500 && result.HTTPStatus != 429 {
		return true
	}
	return result.Response != nil && result.Response.Status == StatusRejected
}

// SubmitForReporting ports ReportingApi.reportInvoice (reporting.js:114-142)
// for simplified (B2C) invoices — asynchronous, must be reported within
// 24h. Retry policy (schedule.js:21-23): transport failures always retry;
// API failures only for HTTP >= 500 and only while the parse is not
// terminal (reporting.js:45-49 — a REJECTED parse on a 5xx is definitive).
// Non-terminal results below 500 (e.g. 429) stop the schedule and return
// the last parse, exactly like the Effect catchTag conversion. Once the
// schedule is exhausted, the LAST API outcome returns as a result
// (reporting.js:108-111) while a transport failure throws.
func (c *Client) SubmitForReporting(ctx context.Context, credentials Credentials, request SubmitInvoiceRequest) (*SubmitResult, error) {
	retries := c.retry.MaxRetries
	backoffs := c.retry.BackoffMS
	for attempt := 0; ; attempt++ {
		resp, transportErr := c.postSubmission(ctx, "/invoices/reporting/single", credentials, request)
		if transportErr != nil {
			if attempt >= retries {
				return nil, transportErr
			}
		} else {
			result := parseSubmissionResponse(resp, "Failed to parse ZATCA response", func(data map[string]any) *SubmitResult {
				return parseReportingData(resp, data)
			})
			if isTerminalReportingResult(result) {
				return result, nil
			}
			if result.HTTPStatus < 500 {
				return result, nil
			}
			if attempt >= retries {
				return result, nil
			}
		}
		time.Sleep(delayFor(backoffs, attempt+1))
	}
}

// AssertNoZatcaAlerts ports assertNoZatcaAlerts (diagnostics.js:45-61):
// strict-success wrapper — a successful submission that still carries
// alerts (or any failure) yields an error whose message joins the alerts
// ("SEVERITY code: message" by "; "), falling back to the error message and
// finally "HTTP <status>".
func AssertNoZatcaAlerts(result *SubmitResult, operation string) error {
	if result.Success && len(result.Alerts) == 0 {
		return nil
	}
	var diagnostics string
	if len(result.Alerts) > 0 {
		parts := make([]string, 0, len(result.Alerts))
		for _, alert := range result.Alerts {
			parts = append(parts, fmt.Sprintf("%s %s: %s", strings.ToUpper(alert.Severity), alert.Code, alert.Message))
		}
		diagnostics = strings.Join(parts, "; ")
	} else if result.Error != nil {
		diagnostics = result.Error.Message
	} else {
		diagnostics = fmt.Sprintf("HTTP %d", result.HTTPStatus)
	}
	return errors.New(operation + " failed: " + diagnostics)
}

// ---- status polling (status.js) ----

// StatusMessage is one entry of the status endpoint's validationResults
// message arrays (status.d.ts InvoiceStatusResult).
type StatusMessage struct {
	Code    string
	Message string
}

// InvoiceStatusValidationResults mirrors the normalized validationResults
// (status.js:63-70): every array defaults to empty, the inner status to "".
type InvoiceStatusValidationResults struct {
	Status          string
	ErrorMessages   []StatusMessage
	WarningMessages []StatusMessage
	InfoMessages    []StatusMessage
}

// InvoiceStatus mirrors InvoiceStatusResult (status.d.ts): the missing
// status defaults to "SUBMITTED" (status.js:62), Raw preserves the payload.
type InvoiceStatus struct {
	Status            string
	ValidationResults *InvoiceStatusValidationResults
	ClearanceStatus   string
	ReportingStatus   string
	Raw               map[string]any
}

// CheckInvoiceStatus ports StatusApi.checkStatus (status.js:16-29):
// GET /invoices/status/{uuid} with Basic auth. 404 → *APIError "Invoice
// not found"; an unparsable body → *APIError carrying the first 200 chars;
// transport failures → *TransportError.
func (c *Client) CheckInvoiceStatus(ctx context.Context, credentials Credentials, uuid string) (*InvoiceStatus, error) {
	headers := c.baseHeaders()
	headers["Authorization"] = authHeader(credentials)
	resp, transportErr := c.do(ctx, httpRequest{
		method:  http.MethodGet,
		url:     c.baseURL + "/invoices/status/" + uuid,
		headers: headers,
	})
	if transportErr != nil {
		return nil, transportErr
	}
	if resp.status == http.StatusNotFound {
		return nil, &APIError{
			Message:    fmt.Sprintf("Invoice not found: %s", uuid),
			HTTPStatus: resp.status,
			Body:       resp.body,
		}
	}
	var parsed any
	if err := json.Unmarshal([]byte(resp.body), &parsed); err != nil {
		return nil, &APIError{
			Message:    fmt.Sprintf("Failed to parse invoice status response (HTTP %d): %s", resp.status, truncateRunes(resp.body, 200)),
			HTTPStatus: resp.status,
			Body:       resp.body,
		}
	}
	// JSON.parse accepts arrays/scalars (status.js:23) — every field then
	// defaults, which a nil map yields naturally below.
	data, _ := parsed.(map[string]any)

	status := &InvoiceStatus{
		Status:          orDefault(strAt(data, "status"), "SUBMITTED"),
		ClearanceStatus: strAt(data, "clearanceStatus"),
		ReportingStatus: strAt(data, "reportingStatus"),
		Raw:             data,
	}
	if validationResults := mapField(data, "validationResults"); validationResults != nil {
		status.ValidationResults = &InvoiceStatusValidationResults{
			Status:          strAt(validationResults, "status"),
			ErrorMessages:   statusMessages(sliceAt(validationResults, "errorMessages")),
			WarningMessages: statusMessages(sliceAt(validationResults, "warningMessages")),
			InfoMessages:    statusMessages(sliceAt(validationResults, "infoMessages")),
		}
	}
	return status, nil
}

func statusMessages(items []any) []StatusMessage {
	out := make([]StatusMessage, 0, len(items))
	for _, item := range items {
		m, _ := item.(map[string]any)
		out = append(out, StatusMessage{Code: strAt(m, "code"), Message: strAt(m, "message")})
	}
	return out
}

// ---- untyped-JSON array/object/field helpers ----

func sliceAt(data map[string]any, key string) []any {
	if data == nil {
		return nil
	}
	value, _ := data[key].([]any)
	return value
}

func strAt(data map[string]any, key string) string {
	return stringField(data, key)
}

func orDefault(value string, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
