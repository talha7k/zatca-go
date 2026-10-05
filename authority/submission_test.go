// Submission + status tests — clearance (standard B2B), reporting
// (simplified B2C, with the retry policy), and invoice status polling,
// mirroring @talha7k/zatca dist/api/{clearance,reporting,status,
// submission-response,diagnostics}.js as driven by the esellar drain engine
// (authority-submit-port.ts). Table-driven against an httptest.Server mock.
package authority_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/talha7k/zatca-go/authority"
)

func creds() authority.Credentials {
	return authority.Credentials{BinarySecurityToken: "tok", Secret: "sec"}
}

func submitClient(baseURL string, retry authority.RetryConfig) *authority.Client {
	return authority.New(authority.Config{
		Environment: authority.EnvironmentSandbox,
		BaseURL:     baseURL,
		Timeout:     2 * time.Second,
		Retry:       retry,
	})
}

func noRetry() authority.RetryConfig {
	return authority.RetryConfig{MaxRetries: 0, BackoffMS: []int{0}}
}

// ClearInvoice (clearance.js:18-25): POST /invoices/clearance/single with
// Clearance-Status header and the {invoiceHash, uuid, invoice} body.
func TestSubmitForClearanceWire(t *testing.T) {
	var gotReq *http.Request
	var gotBody string
	server := newMockServer(t, http.StatusOK, `{"acceptedInvoices":[]}`, &gotReq, &gotBody)
	defer server.Close()

	result, err := submitClient(server.URL, noRetry()).SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}

	if gotReq.URL.Path != "/invoices/clearance/single" {
		t.Fatalf("path = %q", gotReq.URL.Path)
	}
	if gotReq.Header.Get("Clearance-Status") != "1" {
		t.Fatalf("Clearance-Status = %q, want the \"1\" default", gotReq.Header.Get("Clearance-Status"))
	}
	if gotReq.Header.Get("Authorization") == "" {
		t.Fatal("missing basic auth")
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body unparsable: %v (%q)", err, gotBody)
	}
	if body["invoiceHash"] != "h" || body["uuid"] != "u" || body["invoice"] != "i" {
		t.Fatalf("body = %+v", body)
	}
	_ = result
}

// parseInvoiceListResponse accepted branch (submission-response.js:32-66).
func TestSubmitForClearanceAccepted(t *testing.T) {
	server := newMockServer(t, http.StatusOK, `{
		"acceptedInvoices":[{"uuid":"u-1","invoiceHash":"h-1","clearedInvoice":"CLEARED-XML","clearanceDateTime":"2026-10-06T10:00:00Z","clearanceStatus":"Cleared","warnings":[{"code":"W1","category":"CAT","message":"warned"}]}],
		"validationResults":{"status":"PASS","errorMessages":[],"warningMessages":[{"code":"W2","message":"gw-warn"}]}
	}`, nil, nil)
	defer server.Close()

	result, err := submitClient(server.URL, noRetry()).SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}

	if !result.Success {
		t.Fatalf("Success = false (%+v)", result)
	}
	if result.HTTPStatus != 200 {
		t.Fatalf("HTTPStatus = %d", result.HTTPStatus)
	}
	resp := result.Response
	if resp == nil || resp.Status != authority.StatusAccepted {
		t.Fatalf("response = %+v", resp)
	}
	if resp.UUID != "u-1" || resp.InvoiceHash != "h-1" {
		t.Fatalf("identity fields = %+v", resp)
	}
	if resp.ClearedInvoice != "CLEARED-XML" || resp.ClearanceDateTime != "2026-10-06T10:00:00Z" {
		t.Fatalf("clearance fields = %+v", resp)
	}
	if resp.ClearanceStatus != "Cleared" {
		t.Fatalf("ClearanceStatus = %q (includeClearanceStatus)", resp.ClearanceStatus)
	}
	if resp.ReportingStatus != "" {
		t.Fatalf("ReportingStatus must be absent on clearance parses: %q", resp.ReportingStatus)
	}
	// Alerts: diagnostics warnings first, then invoice-level warnings
	// (submission-response.js:52).
	if len(result.Alerts) != 2 {
		t.Fatalf("alerts = %+v", result.Alerts)
	}
	if result.Alerts[0].Severity != "warning" || result.Alerts[0].Code != "W2" ||
		result.Alerts[1].Code != "W1" || result.Alerts[1].Category != "CAT" {
		t.Fatalf("alerts = %+v", result.Alerts)
	}
	if len(resp.Warnings) != 1 || resp.Warnings[0].Code != "W1" {
		t.Fatalf("response warnings = %+v", resp.Warnings)
	}
}

// Rejected invoice: invoice.error wins over the aggregated diagnostics error
// (submission-response.js:46-47); diagnostics error aggregates codes.
func TestSubmitForClearanceRejected(t *testing.T) {
	server := newMockServer(t, http.StatusBadRequest, `{
		"rejectededInvoices":[{"uuid":"u-2","invoiceHash":"h-2","error":{"code":"E-INV","category":"INV","message":"invoice rejected"}}],
		"validationResults":{"errorMessages":[{"code":"E-1","message":"one"},{"code":"E-2","message":"two"}]}
	}`, nil, nil)
	defer server.Close()

	result, err := submitClient(server.URL, noRetry()).SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}

	if result.Success {
		t.Fatal("rejected invoice must not be successful")
	}
	resp := result.Response
	if resp == nil || resp.Status != authority.StatusRejected {
		t.Fatalf("response = %+v", resp)
	}
	// invoice.error takes precedence over the diagnostics aggregate.
	if result.Error == nil || result.Error.Code != "E-INV" || result.Error.Category != "INV" {
		t.Fatalf("error = %+v, want the invoice-level error", result.Error)
	}
	if resp.Error == nil || resp.Error.Code != "E-INV" {
		t.Fatalf("response error = %+v", resp.Error)
	}
	// The rejectedInvoice list itself is surfaced as an error alert too —
	// diagnostics alerts (E-1, E-2) precede invoice warnings.
	found := map[string]bool{}
	for _, a := range result.Alerts {
		found[a.Code] = true
	}
	if !found["E-1"] || !found["E-2"] {
		t.Fatalf("alerts missing diagnostics errors: %+v", result.Alerts)
	}
}

// The alternate rejectedInvoices spelling is honored
// (submission-response.js:34).
func TestSubmitForClearanceAlternateRejectedSpelling(t *testing.T) {
	server := newMockServer(t, http.StatusBadRequest,
		`{"rejectedInvoices":[{"uuid":"u-3","error":{"code":"E","category":"C","message":"m"}}]}`, nil, nil)
	defer server.Close()

	result, _ := submitClient(server.URL, noRetry()).SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if result.Success || result.Response == nil || result.Response.Status != authority.StatusRejected {
		t.Fatalf("result = %+v", result)
	}
}

// Unparsable body → PARSE_ERROR/CLIENT result, never an error return
// (submission-response.js:18-31, 77-79).
func TestSubmitForClearanceParseFailure(t *testing.T) {
	server := newMockServer(t, http.StatusServiceUnavailable, "<html>overloaded</html>", nil, nil)
	defer server.Close()

	result, err := submitClient(server.URL, noRetry()).SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("parse failure must be a result, not an error: %v", err)
	}
	if result.Success {
		t.Fatal("parse failure must not be successful")
	}
	if result.Error == nil || result.Error.Code != "PARSE_ERROR" || result.Error.Category != "CLIENT" {
		t.Fatalf("error = %+v, want PARSE_ERROR/CLIENT", result.Error)
	}
	if len(result.Alerts) != 1 || result.Alerts[0].Severity != "error" || result.Alerts[0].Code != "PARSE_ERROR" {
		t.Fatalf("alerts = %+v", result.Alerts)
	}
	if !strings.Contains(result.Error.Message, "Failed to parse clearance response") {
		t.Fatalf("parse error message = %q", result.Error.Message)
	}
}

// No invoice list at all → fallback result {success: 2xx} with rawBody
// (submission-response.js:71-75). An ARRAY body is valid JSON for the
// fallback path (the object-only restriction is the onboarding plugin's
// parse, not the submission parser).
func TestSubmitForClearanceFallbackResult(t *testing.T) {
	server := newMockServer(t, http.StatusOK, `[1,2,3]`, nil, nil)
	defer server.Close()

	result, err := submitClient(server.URL, noRetry()).SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if !result.Success {
		t.Fatalf("2xx fallback must be successful: %+v", result)
	}
	if result.Response != nil {
		t.Fatalf("fallback has no response envelope: %+v", result.Response)
	}
	if result.RawBody != "[1,2,3]" {
		t.Fatalf("rawBody = %q", result.RawBody)
	}

	server2 := newMockServer(t, http.StatusBadGateway, `{"note":"no lists here"}`, nil, nil)
	defer server2.Close()
	result2, _ := submitClient(server2.URL, noRetry()).SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if result2.Success {
		t.Fatal("non-2xx fallback must not be successful")
	}
}

// Transport failure THROWS for submissions (unlike onboarding):
// clearance.js relies on request() rethrowing ZatcaError
// API_CONNECTION_ERROR / API_TIMEOUT.
func TestSubmitForClearanceTransportError(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() { close(release); server.Close() }()

	client := authority.New(authority.Config{BaseURL: server.URL, Timeout: 50 * time.Millisecond})
	result, err := client.SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err == nil {
		t.Fatalf("want a transport error, got result %+v", result)
	}
	var terr *authority.TransportError
	if !errors.As(err, &terr) {
		t.Fatalf("error type = %T, want *authority.TransportError", err)
	}
	if !terr.Timeout || terr.Code != authority.CodeAPITimeout {
		t.Fatalf("transport error = %+v", terr)
	}
	// The upstream timeout message format feeds the BUG-14 classifier
	// (effect/http.js:33).
	if !authority.IsTimeoutSentinel(terr.Message) {
		t.Fatalf("timeout message must classify as sentinel: %q", terr.Message)
	}
}

func TestSubmitForClearanceConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	_, err := submitClient(url, noRetry()).SubmitForClearance(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	var terr *authority.TransportError
	if !errors.As(err, &terr) {
		t.Fatalf("error type = %T, want *authority.TransportError", err)
	}
	if terr.Timeout || terr.Code != authority.CodeAPIConnectionError {
		t.Fatalf("transport error = %+v", terr)
	}
	if !strings.HasPrefix(terr.Message, "ZATCA API connection failed:") {
		t.Fatalf("connection message = %q, want the upstream format (effect/http.js:31)", terr.Message)
	}
	if terr.Err == nil {
		t.Fatal("original error must be wrapped for the unwrap semantics (zatca.ts:396-405)")
	}
}

// reportInvoice (reporting.js:133-141): POST /invoices/reporting/single with
// the same auth + Clearance-Status headers.
func TestSubmitForReportingWire(t *testing.T) {
	var gotReq *http.Request
	server := newMockServer(t, http.StatusOK, `{"reportingStatus":"REPORTED","uuid":"u","invoiceHash":"h"}`, &gotReq, nil)
	defer server.Close()

	result, err := submitClient(server.URL, noRetry()).SubmitForReporting(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if gotReq.URL.Path != "/invoices/reporting/single" {
		t.Fatalf("path = %q", gotReq.URL.Path)
	}
	if gotReq.Header.Get("Clearance-Status") != "1" {
		t.Fatalf("Clearance-Status = %q", gotReq.Header.Get("Clearance-Status"))
	}
	if !result.Success || result.Response == nil || result.Response.ReportingStatus != "REPORTED" {
		t.Fatalf("result = %+v", result)
	}
	if result.Response.Status != authority.StatusAccepted {
		t.Fatalf("status = %q, want ACCEPTED for REPORTED", result.Response.Status)
	}
}

// Non-REPORTED reportingStatus → REJECTED and terminal
// (reporting.js:55-71).
func TestSubmitForReportingNotReported(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"reportingStatus":"NOT_REPORTED","uuid":"u","invoiceHash":"h","validationResults":{"errorMessages":[{"code":"X","message":"m"}]}}`))
	}))
	defer server.Close()

	result, err := submitClient(server.URL, authority.RetryConfig{MaxRetries: 2, BackoffMS: []int{0}}).
		SubmitForReporting(t.Context(), creds(), authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if result.Success || result.Response == nil || result.Response.Status != authority.StatusRejected {
		t.Fatalf("result = %+v", result)
	}
	if calls.Load() != 1 {
		t.Fatalf("REJECTED must be terminal, attempts = %d", calls.Load())
	}
}

// Clearance-shaped responses fall back to the invoice-list parse with
// reportingStatus pass-through (reporting.js:73-74).
func TestSubmitForReportingClearanceShapeFallback(t *testing.T) {
	server := newMockServer(t, http.StatusOK,
		`{"acceptedInvoices":[{"uuid":"u-9","invoiceHash":"h-9","reportingStatus":"REPORTED"}]}`, nil, nil)
	defer server.Close()

	result, err := submitClient(server.URL, noRetry()).SubmitForReporting(t.Context(), creds(),
		authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if !result.Success || result.Response == nil {
		t.Fatalf("result = %+v", result)
	}
	if result.Response.ReportingStatus != "REPORTED" {
		t.Fatalf("ReportingStatus = %q (includeReportingStatus fallback)", result.Response.ReportingStatus)
	}
	if result.Response.ClearanceStatus != "" {
		t.Fatalf("ClearanceStatus must be absent on reporting parses: %q", result.Response.ClearanceStatus)
	}
}

// Retry policy: 5xx without a terminal parse retries; the backoff array is
// taken verbatim and clamps to its last entry (schedule.js:33-39).
func TestSubmitForReportingRetries5xx(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"note":"transient"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"reportingStatus":"REPORTED","uuid":"u","invoiceHash":"h"}`))
	}))
	defer server.Close()

	result, err := submitClient(server.URL, authority.RetryConfig{MaxRetries: 3, BackoffMS: []int{0, 0, 0}}).
		SubmitForReporting(t.Context(), creds(), authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if !result.Success || calls.Load() != 3 {
		t.Fatalf("success = %v after %d attempts, want success after 3", result.Success, calls.Load())
	}
}

// 4xx (non-429) is terminal without retry (reporting.js:46-47).
func TestSubmitForReporting4xxTerminal(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"4002","message":"bad request"}`))
	}))
	defer server.Close()

	result, _ := submitClient(server.URL, authority.RetryConfig{MaxRetries: 3, BackoffMS: []int{0}}).
		SubmitForReporting(t.Context(), creds(), authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if result.Success {
		t.Fatalf("4xx must not be successful: %+v", result)
	}
	if calls.Load() != 1 {
		t.Fatalf("4xx must be terminal, attempts = %d", calls.Load())
	}
	// parseReportingResponse falls back to {success: 2xx} when the body has
	// neither reportingStatus nor invoice lists (submission-response.js:71-75)
	// — no error envelope on this path.
	if result.Error != nil {
		t.Fatalf("fallback result carries no error envelope, got %+v", result.Error)
	}
	if result.RawBody != `{"code":"4002","message":"bad request"}` {
		t.Fatalf("rawBody = %q", result.RawBody)
	}
}

// A REJECTED parse on a 5xx is terminal (reporting.js:48-49) — no retry on
// a definitive rejection even when the status is 5xx.
func TestSubmitForReportingRejected5xxTerminal(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"reportingStatus":"NOT_REPORTED","uuid":"u","invoiceHash":"h"}`))
	}))
	defer server.Close()

	result, _ := submitClient(server.URL, authority.RetryConfig{MaxRetries: 3, BackoffMS: []int{0}}).
		SubmitForReporting(t.Context(), creds(), authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if result.Success || calls.Load() != 1 {
		t.Fatalf("REJECTED 5xx must be terminal: success=%v attempts=%d", result.Success, calls.Load())
	}
}

// Transport failures retry, then the LAST transport error surfaces
// (reporting.js:97-111, schedule.js:21-23).
func TestSubmitForReportingRetriesTransportThenThrows(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		panic(http.ErrAbortHandler) // kill the connection without a response
	}))
	defer server.Close()

	result, err := submitClient(server.URL, authority.RetryConfig{MaxRetries: 2, BackoffMS: []int{0, 0}}).
		SubmitForReporting(t.Context(), creds(), authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err == nil {
		t.Fatalf("exhausted transport retries must throw, got %+v", result)
	}
	var terr *authority.TransportError
	if !errors.As(err, &terr) {
		t.Fatalf("error type = %T, want *authority.TransportError", err)
	}
	if calls.Load() != 3 { // 1 initial + 2 retries
		t.Fatalf("attempts = %d, want 3", calls.Load())
	}
}

// Retries exhausted on persistent 5xx → the LAST API outcome returns as a
// result (reporting.js:108-111).
func TestSubmitForReporting5xxExhausted(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"note":"still down"}`))
	}))
	defer server.Close()

	result, err := submitClient(server.URL, authority.RetryConfig{MaxRetries: 2, BackoffMS: []int{0}}).
		SubmitForReporting(t.Context(), creds(), authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if err != nil {
		t.Fatalf("exhausted 5xx retries return a result, not an error: %v", err)
	}
	if result.Success || result.HTTPStatus != http.StatusBadGateway || calls.Load() != 3 {
		t.Fatalf("result = %+v after %d attempts", result, calls.Load())
	}
}

// checkStatus (status.js:16-29): GET /invoices/status/{uuid} with basic
// auth; defaults and normalization per parseStatusResult (status.js:59-75).
func TestCheckInvoiceStatus(t *testing.T) {
	var gotReq *http.Request
	server := newMockServer(t, http.StatusOK, `{
		"status":"CLEARED",
		"clearanceStatus":"CLEARED",
		"reportingStatus":"REPORTED",
		"validationResults":{"status":"PASS","errorMessages":[],"warningMessages":[],"infoMessages":[{"code":"I1","message":"info"}]}
	}`, &gotReq, nil)
	defer server.Close()

	status, err := submitClient(server.URL, noRetry()).CheckInvoiceStatus(t.Context(), creds(), "uuid-7")
	if err != nil {
		t.Fatalf("errored: %v", err)
	}

	if gotReq.URL.Path != "/invoices/status/uuid-7" {
		t.Fatalf("path = %q", gotReq.URL.Path)
	}
	if gotReq.Method != http.MethodGet {
		t.Fatalf("method = %q, want GET", gotReq.Method)
	}
	if status.Status != "CLEARED" || status.ClearanceStatus != "CLEARED" || status.ReportingStatus != "REPORTED" {
		t.Fatalf("status = %+v", status)
	}
	if status.ValidationResults == nil || status.ValidationResults.Status != "PASS" || len(status.ValidationResults.InfoMessages) != 1 {
		t.Fatalf("validation results = %+v", status.ValidationResults)
	}
	if status.Raw == nil {
		t.Fatal("raw payload must be preserved")
	}
}

// Missing status defaults to SUBMITTED (status.js:62).
func TestCheckInvoiceStatusDefaultSubmitted(t *testing.T) {
	server := newMockServer(t, http.StatusOK, `{}`, nil, nil)
	defer server.Close()

	status, err := submitClient(server.URL, noRetry()).CheckInvoiceStatus(t.Context(), creds(), "u")
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if status.Status != "SUBMITTED" {
		t.Fatalf("status = %q, want SUBMITTED default", status.Status)
	}
	if status.ValidationResults != nil || status.ClearanceStatus != "" || status.ReportingStatus != "" {
		t.Fatalf("status = %+v", status)
	}
}

// 404 → "Invoice not found: <uuid>" (status.js:18-20).
func TestCheckInvoiceStatus404(t *testing.T) {
	server := newMockServer(t, http.StatusNotFound, `{"message":"nope"}`, nil, nil)
	defer server.Close()

	status, err := submitClient(server.URL, noRetry()).CheckInvoiceStatus(t.Context(), creds(), "ghost")
	if err == nil {
		t.Fatalf("want an error, got %+v", status)
	}
	var apiErr *authority.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T, want *authority.APIError", err)
	}
	if apiErr.Message != "Invoice not found: ghost" {
		t.Fatalf("message = %q", apiErr.Message)
	}
}

// Unparsable body → parse error carrying the first 200 chars
// (status.js:22-27).
func TestCheckInvoiceStatusParseFailure(t *testing.T) {
	long := strings.Repeat("x", 500)
	server := newMockServer(t, http.StatusOK, "<html>"+long+"</html>", nil, nil)
	defer server.Close()

	_, err := submitClient(server.URL, noRetry()).CheckInvoiceStatus(t.Context(), creds(), "u")
	var apiErr *authority.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error type = %T, want *authority.APIError", err)
	}
	if !strings.HasPrefix(apiErr.Message, "Failed to parse invoice status response (HTTP 200): ") {
		t.Fatalf("message = %q", apiErr.Message)
	}
	// substring(0, 200) of the body
	if !strings.Contains(apiErr.Message, strings.Repeat("x", 100)) {
		t.Fatalf("message should carry the body prefix: %q", apiErr.Message[:80])
	}
	if strings.Contains(apiErr.Message, long) {
		t.Fatal("message must be truncated at 200 chars of the body")
	}
}

// Transport failure surfaces as *TransportError (status.js via request()).
func TestCheckInvoiceStatusTransportError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	_, err := submitClient(url, noRetry()).CheckInvoiceStatus(t.Context(), creds(), "u")
	var terr *authority.TransportError
	if !errors.As(err, &terr) || terr.Timeout {
		t.Fatalf("error = %v, want a non-timeout *TransportError", err)
	}
}

// Clearable Clearance-Status override ("0" is the historical pre-clearance
// flag; client.js:24 allows '0' | '1').
func TestClearanceStatusOverride(t *testing.T) {
	var gotReq *http.Request
	server := newMockServer(t, http.StatusOK, `{"acceptedInvoices":[]}`, &gotReq, nil)
	defer server.Close()

	client := authority.New(authority.Config{BaseURL: server.URL, Timeout: 2 * time.Second, ClearanceStatus: "0", Retry: noRetry()})
	_, _ = client.SubmitForClearance(t.Context(), creds(), authority.SubmitInvoiceRequest{InvoiceHash: "h", UUID: "u", Invoice: "i"})
	if gotReq.Header.Get("Clearance-Status") != "0" {
		t.Fatalf("Clearance-Status = %q, want overridden \"0\"", gotReq.Header.Get("Clearance-Status"))
	}
}

// assertNoZatcaAlerts port (diagnostics.js:45-61).
func TestAssertNoZatcaAlerts(t *testing.T) {
	t.Run("clean success passes", func(t *testing.T) {
		result := &authority.SubmitResult{Success: true, HTTPStatus: 200}
		if err := authority.AssertNoZatcaAlerts(result, "ZATCA reporting"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("success with alerts throws", func(t *testing.T) {
		result := &authority.SubmitResult{
			Success:    true,
			HTTPStatus: 200,
			Alerts: []authority.SubmissionAlert{
				{Severity: "warning", Code: "W1", Category: "C", Message: "watch"},
			},
		}
		err := authority.AssertNoZatcaAlerts(result, "ZATCA reporting")
		if err == nil {
			t.Fatal("want an error")
		}
		want := "ZATCA reporting failed: WARNING W1: watch"
		if err.Error() != want {
			t.Fatalf("error = %q, want %q", err.Error(), want)
		}
	})

	t.Run("failure falls back to error message then HTTP status", func(t *testing.T) {
		withError := &authority.SubmitResult{Success: false, HTTPStatus: 400, Error: &authority.APIErrorShape{Code: "E", Category: "C", Message: "bad"}}
		if err := authority.AssertNoZatcaAlerts(withError, "ZATCA clearance"); err == nil || err.Error() != "ZATCA clearance failed: bad" {
			t.Fatalf("error = %v", err)
		}
		bare := &authority.SubmitResult{Success: false, HTTPStatus: 503}
		if err := authority.AssertNoZatcaAlerts(bare, "ZATCA clearance"); err == nil || err.Error() != "ZATCA clearance failed: HTTP 503" {
			t.Fatalf("error = %v", err)
		}
	})
}

// RetryConfig defaults mirror the TS schedule: 3 retries over
// [5000, 30000, 300000] (schedule.js:18-19).
func TestDefaultRetryConfig(t *testing.T) {
	rc := authority.DefaultRetryConfig()
	if rc.MaxRetries != 3 {
		t.Fatalf("MaxRetries = %d, want 3", rc.MaxRetries)
	}
	if len(rc.BackoffMS) != 3 || rc.BackoffMS[0] != 5000 || rc.BackoffMS[1] != 30000 || rc.BackoffMS[2] != 300000 {
		t.Fatalf("BackoffMS = %v", rc.BackoffMS)
	}
}

// Zero-value Config gets the TS defaults (?? fallbacks in client.js:23-24,
// reporting.js:119-120); a fully-specified Retry is honored verbatim.
func TestNewAppliesTSTypeDefaults(t *testing.T) {
	client := authority.New(authority.Config{BaseURL: "https://example.invalid"})
	if client.Timeout() != authority.DefaultTimeout {
		t.Fatalf("timeout = %v", client.Timeout())
	}
	if got := client.RetryConfig(); got.MaxRetries != 3 || len(got.BackoffMS) != 3 {
		t.Fatalf("retry = %+v, want the TS defaults", got)
	}
}
