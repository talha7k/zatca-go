// Onboarding flows — the Go port of apps/api/src/plugins/zatca.ts (the
// source of truth): compliance CSID with OTP, production CSID from the
// compliance credentials, and compliance invoice verification. Wire
// behavior, response shaping, diagnostics and the never-throw-on-transport
// contract mirror the TS exactly; every helper cites its TS file:line.
//
// KEY CONTRACT (all three flows): transport failures NEVER surface as a Go
// error — the TS returns REJECTED/valid:false responses with REQUEST_FAILED
// diagnostics (zatca.ts:620-637, 722-739, 837-866), and so does this port.
// Timeouts carry the BUG-13 sentinel message.
package authority

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"time"
)

// Response status vocabulary (zatca.ts:59, 70; diagnostics response_status
// zatca.ts:59).
const (
	StatusAccepted      = "ACCEPTED"
	StatusRejected      = "REJECTED"
	StatusRequestFailed = "REQUEST_FAILED"
)

// DiagnosticMessage / Diagnostics shape the audit record the TS persists
// alongside every onboarding call (ZatcaComplianceCsidDiagnostics,
// zatca.ts:53-64).
type Diagnostics struct {
	Environment        Environment
	Endpoint           string
	HTTPStatus         int // 0 = no HTTP response (transport failure)
	DurationMS         int64
	RequestID          string
	ResponseStatus     string // StatusAccepted | StatusRejected | StatusRequestFailed
	ResponseKeys       []string
	Errors             []DiagnosticMessage
	Warnings           []DiagnosticMessage
	RawResponsePreview string
}

// CSIDError is the promoted first error on a CSID response (zatca.ts:71-75).
type CSIDError struct {
	Code     string
	Category string
	Message  string
}

// CSIDResponse mirrors ZatcaComplianceCsidResponse (zatca.ts:66-77), which
// ZatcaProductionCsidResponse aliases (zatca.ts:79).
type CSIDResponse struct {
	BinarySecurityToken string
	Secret              string
	RequestID           string // "" when absent
	Status              string // StatusAccepted | StatusRejected
	Error               *CSIDError
	Diagnostics         Diagnostics
}

// ComplianceInvoiceResponse mirrors ZatcaComplianceInvoiceResponse
// (zatca.ts:81-85).
type ComplianceInvoiceResponse struct {
	Valid       bool
	Messages    []string
	Diagnostics Diagnostics
}

// zatcaHTTPStatus ports getZatcaHttpStatus (zatca.ts:321-323).
func zatcaHTTPStatus(httpStatus int) string {
	if httpStatus >= 200 && httpStatus < 300 {
		return StatusAccepted
	}
	return StatusRejected
}

// buildDiagnostics ports buildZatcaDiagnostics (zatca.ts:325-353).
// Divergence: ResponseKeys is sorted (TS Object.keys preserves JSON
// document order, which Go maps cannot recover) — the field is an audit
// artifact, never parsed.
func buildDiagnostics(
	environment Environment,
	endpoint string,
	started time.Time,
	resp *httpResponse,
	requestID string,
	responseStatus string,
	data map[string]any,
	errs []DiagnosticMessage,
	warnings []DiagnosticMessage,
) Diagnostics {
	diagnostics := Diagnostics{
		Environment:    environment,
		Endpoint:       endpoint,
		DurationMS:     time.Since(started).Milliseconds(),
		RequestID:      requestID,
		ResponseStatus: responseStatus,
	}
	if resp != nil {
		diagnostics.HTTPStatus = resp.status
		diagnostics.RawResponsePreview = ResponsePreview(resp.body, data)
	}
	if data != nil {
		keys := make([]string, 0, len(data))
		for key := range data {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		diagnostics.ResponseKeys = keys
	}
	if len(errs) > 0 {
		diagnostics.Errors = errs
	}
	if len(warnings) > 0 {
		diagnostics.Warnings = warnings
	}
	return diagnostics
}

// requestFailureDiagnostics ports buildRequestFailureDiagnostics
// (zatca.ts:355-384). BUG-13: a timeout surfaces the distinct sentinel
// message so the BUG-14 retry classifier treats it as retryable FAILED
// rather than terminal REJECTED; connection failures keep the ORIGINAL
// error message — unwrapZatcaTransportError (zatca.ts:387-405) exists in
// the TS precisely to restore that raw-fetch-era string.
func requestFailureDiagnostics(
	environment Environment,
	endpoint string,
	started time.Time,
	transportErr *TransportError,
	fallbackMessage string,
) Diagnostics {
	message := fallbackMessage
	switch {
	case transportErr.Timeout:
		message = TimeoutSentinelMessage
	case transportErr.Err != nil:
		message = transportErr.Err.Error()
	case transportErr.Message != "":
		message = transportErr.Message
	}
	return Diagnostics{
		Environment:    environment,
		Endpoint:       endpoint,
		DurationMS:     time.Since(started).Milliseconds(),
		ResponseStatus: StatusRequestFailed,
		Errors: []DiagnosticMessage{{
			Code:     "REQUEST_FAILED",
			Category: "HTTP-Errors",
			Message:  message,
		}},
	}
}

// rejectedCSIDResponse ports buildRejectedCsidResponse (zatca.ts:452-466).
func rejectedCSIDResponse(diagnostics Diagnostics) CSIDResponse {
	message := "Request failed"
	if len(diagnostics.Errors) > 0 && diagnostics.Errors[0].Message != "" {
		message = diagnostics.Errors[0].Message
	}
	return CSIDResponse{
		Status:      StatusRejected,
		Error:       &CSIDError{Code: "REQUEST_FAILED", Category: "HTTP-Errors", Message: message},
		Diagnostics: diagnostics,
	}
}

// buildCSIDResponse ports buildCsidResponse (zatca.ts:468-494): token and
// secret default to "" when absent; the FIRST error is promoted with ""
// defaults.
func buildCSIDResponse(
	data map[string]any,
	requestID string,
	status string,
	errs []DiagnosticMessage,
	diagnostics Diagnostics,
) CSIDResponse {
	response := CSIDResponse{
		BinarySecurityToken: stringField(data, "binarySecurityToken"),
		Secret:              stringField(data, "secret"),
		RequestID:           requestID,
		Status:              status,
		Diagnostics:         diagnostics,
	}
	if len(errs) > 0 {
		first := errs[0]
		response.Error = &CSIDError{Code: first.Code, Category: first.Category, Message: first.Message}
	}
	return response
}

// authHeader adds the Basic credentials (buildAuthenticatedZatcaRequest,
// zatca.ts:516-537).
func authHeader(credentials Credentials) string {
	return "Basic " + BasicAuth(credentials)
}

// validationResultsWarnings merges data.warnings and
// data.validationResults.warningMessages (zatca.ts:591-598, 697-700).
func validationResultsWarnings(data map[string]any) []DiagnosticMessage {
	return append(
		MessageArray(fieldAt(data, "warnings")),
		MessageArray(fieldAt(mapField(data, "validationResults"), "warningMessages"))...)
}

// validationResultsErrors merges data.errors and
// data.validationResults.errorMessages (zatca.ts:672-678, 780-783).
func validationResultsErrors(data map[string]any) []DiagnosticMessage {
	return append(
		MessageArray(fieldAt(data, "errors")),
		MessageArray(fieldAt(mapField(data, "validationResults"), "errorMessages"))...)
}

// complianceCSIDBody / productionCSIDBody preserve the TS body field order
// (zatca.ts:566-568, 660-664).
type complianceCSIDBody struct {
	CSR string `json:"csr"`
}

type productionCSIDBody struct {
	ComplianceRequestID string `json:"compliance_request_id"`
}

// ComplianceCSID ports requestZatcaComplianceCsid (zatca.ts:539-637):
// POST {base}/compliance with the OTP header and {csr: base64(csr)}.
func (c *Client) ComplianceCSID(ctx context.Context, csr string, otp string) CSIDResponse {
	endpoint := c.baseURL + "/compliance"
	safeEndpoint := SafeEndpointForLogs(endpoint)
	started := time.Now()

	headers := c.baseHeaders()
	headers["OTP"] = otp
	body, _ := json.Marshal(complianceCSIDBody{CSR: base64.StdEncoding.EncodeToString([]byte(csr))})

	resp, transportErr := c.do(ctx, httpRequest{
		method:  http.MethodPost,
		url:     endpoint,
		headers: headers,
		body:    string(body),
	})
	if transportErr != nil {
		diagnostics := requestFailureDiagnostics(c.environment, safeEndpoint, started, transportErr,
			"ZATCA Compliance CSID request failed before a response was received")
		return rejectedCSIDResponse(diagnostics)
	}

	data := ParseZatcaJSONObject(resp.body)
	requestID := RequestIDFrom(data, resp.headers)
	status := zatcaHTTPStatus(resp.status)

	errs := MessageArray(fieldAt(data, "errors"))
	// dispositionMessage fallback when REJECTED carries no errors
	// (zatca.ts:580-590) — CSR_VALIDATION category on this flow.
	if len(errs) == 0 {
		if disposition := stringField(data, "dispositionMessage"); disposition != "" && status == StatusRejected {
			errs = append(errs, DiagnosticMessage{
				Code:     disposition,
				Category: "CSR_VALIDATION",
				Message:  disposition,
			})
		}
	}
	diagnostics := buildDiagnostics(c.environment, safeEndpoint, started, resp, requestID, status, data,
		errs, validationResultsWarnings(data))

	return buildCSIDResponse(data, requestID, status, errs, diagnostics)
}

// ProductionCSID ports requestZatcaProductionCsid (zatca.ts:639-739):
// POST {base}/production/csids, Basic auth over the compliance
// credentials, body {compliance_request_id}.
func (c *Client) ProductionCSID(ctx context.Context, credentials Credentials, complianceRequestID string) CSIDResponse {
	endpoint := c.baseURL + "/production/csids"
	safeEndpoint := SafeEndpointForLogs(endpoint)
	started := time.Now()

	headers := c.baseHeaders()
	headers["Authorization"] = authHeader(credentials)
	body, _ := json.Marshal(productionCSIDBody{ComplianceRequestID: complianceRequestID})

	resp, transportErr := c.do(ctx, httpRequest{
		method:  http.MethodPost,
		url:     endpoint,
		headers: headers,
		body:    string(body),
	})
	if transportErr != nil {
		diagnostics := requestFailureDiagnostics(c.environment, safeEndpoint, started, transportErr,
			"ZATCA Production CSID request failed before a response was received")
		return rejectedCSIDResponse(diagnostics)
	}

	data := ParseZatcaJSONObject(resp.body)
	requestID := RequestIDFrom(data, resp.headers)
	status := zatcaHTTPStatus(resp.status)

	errs := validationResultsErrors(data)
	// dispositionMessage fallback with PRODUCTION_CSID category
	// (zatca.ts:679-689)…
	if len(errs) == 0 {
		if disposition := stringField(data, "dispositionMessage"); disposition != "" && status == StatusRejected {
			errs = append(errs, DiagnosticMessage{
				Code:     disposition,
				Category: "PRODUCTION_CSID",
				Message:  disposition,
			})
		}
	}
	// …then the last-resort HTTP_<status> fallback carrying the raw body
	// (zatca.ts:690-696) — skipped when the body is empty.
	if len(errs) == 0 && status == StatusRejected && resp.body != "" {
		message := resp.body
		if data != nil {
			if encoded, err := json.Marshal(data); err == nil {
				message = string(encoded)
			}
		}
		errs = append(errs, DiagnosticMessage{
			Code:     fmt.Sprintf("HTTP_%d", resp.status),
			Category: "HTTP-Errors",
			Message:  message,
		})
	}
	diagnostics := buildDiagnostics(c.environment, safeEndpoint, started, resp, requestID, status, data,
		errs, validationResultsWarnings(data))

	return buildCSIDResponse(data, requestID, status, errs, diagnostics)
}

// VerifyComplianceInvoice ports verifyZatcaComplianceInvoice
// (zatca.ts:741-867): POST {base}/compliance/invoices, Basic auth, body
// {invoiceHash, uuid, invoice}.
func (c *Client) VerifyComplianceInvoice(ctx context.Context, credentials Credentials, invoiceHash string, uuid string, invoice string) ComplianceInvoiceResponse {
	endpoint := c.baseURL + "/compliance/invoices"
	safeEndpoint := SafeEndpointForLogs(endpoint)
	started := time.Now()

	headers := c.baseHeaders()
	headers["Authorization"] = authHeader(credentials)
	body, _ := json.Marshal(struct {
		InvoiceHash string `json:"invoiceHash"`
		UUID        string `json:"uuid"`
		Invoice     string `json:"invoice"`
	}{InvoiceHash: invoiceHash, UUID: uuid, Invoice: invoice})

	resp, transportErr := c.do(ctx, httpRequest{
		method:  http.MethodPost,
		url:     endpoint,
		headers: headers,
		body:    string(body),
	})
	if transportErr != nil {
		// zatca.ts:837-866 — the caller-visible message follows the
		// classified diagnostics entry: the BUG-13 sentinel for timeouts,
		// the original error message for connection failures.
		diagnostics := requestFailureDiagnostics(c.environment, safeEndpoint, started, transportErr,
			"ZATCA compliance invoice request failed before a response was received")
		message := "ZATCA compliance invoice request failed before a response was received"
		if len(diagnostics.Errors) > 0 && diagnostics.Errors[0].Message != "" {
			message = diagnostics.Errors[0].Message
		}
		return ComplianceInvoiceResponse{
			Valid:       false,
			Messages:    []string{"ERROR: " + message},
			Diagnostics: diagnostics,
		}
	}

	data := ParseZatcaJSONObject(resp.body)
	requestID := RequestIDFrom(data, resp.headers)

	errs := validationResultsErrors(data)
	// No errors yet and HTTP >= 400: build the HTTP error envelope
	// (zatca.ts:788-802).
	if len(errs) == 0 && resp.status >= 400 {
		code := fmt.Sprintf("HTTP_%d", resp.status)
		if candidate := stringField(data, "code"); candidate != "" {
			code = candidate
		}
		var message string
		if candidate := stringField(data, "message"); candidate != "" {
			message = candidate
		} else if data != nil {
			if encoded, err := json.Marshal(data); err == nil {
				message = string(encoded)
			}
		} else if resp.body != "" {
			message = resp.body
		} else {
			message = fmt.Sprintf("ZATCA returned HTTP %d with an empty response body", resp.status)
		}
		errs = append(errs, DiagnosticMessage{Code: code, Category: "HTTP-Errors", Message: message})
	}

	valid := resp.status >= 200 && resp.status < 300 && len(errs) == 0
	responseStatus := StatusRejected
	if valid {
		responseStatus = StatusAccepted
	}
	warnings := validationResultsWarnings(data)
	diagnostics := buildDiagnostics(c.environment, safeEndpoint, started, resp, requestID, responseStatus, data,
		errs, warnings)

	// messages prefix errors then warnings (zatca.ts:819-826).
	messages := make([]string, 0, len(errs)+len(warnings))
	for _, item := range errs {
		messages = append(messages, "ERROR: "+orUnknown(item.Message, item.Code, "Unknown error"))
	}
	for _, item := range warnings {
		messages = append(messages, "WARNING: "+orUnknown(item.Message, item.Code, "Warning"))
	}

	return ComplianceInvoiceResponse{Valid: valid, Messages: messages, Diagnostics: diagnostics}
}

// orUnknown ports the `item.message ?? item.code ?? "Unknown error"` chains
// (zatca.ts:821, 824). Divergence: TS `??` only skips null/undefined, so a
// present-but-empty string would survive; this port treats absent and empty
// alike (DiagnosticMessage cannot distinguish them), which only diverges
// for pathological explicitly-empty gateway messages.
func orUnknown(primary string, fallback string, last string) string {
	switch {
	case primary != "":
		return primary
	case fallback != "":
		return fallback
	default:
		return last
	}
}

// CertificatePEMToBase64Token ports certificatePemToBase64Token
// (device-csid-registration.ts:112-121): ZATCA's binarySecurityToken IS the
// base64(DER) body of the issued certificate, so armor-stripping the stored
// compliance certificate PEM reconstructs the Basic-auth username exactly —
// the token is public cert material, never a second secret to persist.
func CertificatePEMToBase64Token(certificatePEM string) (string, error) {
	body := certEndPattern.ReplaceAllString(
		certBeginPattern.ReplaceAllString(certificatePEM, ""), "")
	body = whitespacePattern.ReplaceAllString(body, "")
	if body == "" {
		return "", errors.New("Stored device certificate is empty")
	}
	return body, nil
}

var (
	certBeginPattern  = regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)
	certEndPattern    = regexp.MustCompile(`-----END CERTIFICATE-----`)
	whitespacePattern = regexp.MustCompile(`\s+`)
)
