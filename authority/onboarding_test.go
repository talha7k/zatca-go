// Onboarding flow tests — compliance CSID (OTP), production CSID, and
// compliance invoice verification, mirroring apps/api/src/plugins/zatca.ts
// (the source of truth): endpoints, headers, response shaping, diagnostics,
// and the transport-failure/never-throw semantics. Table-driven against an
// httptest.Server mock — no live network.
package authority_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/talha7k/zatca-go/authority"
)

func testClient(baseURL string) *authority.Client {
	return authority.New(authority.Config{
		Environment: authority.EnvironmentSandbox,
		BaseURL:     baseURL,
		Timeout:     2 * time.Second,
	})
}

func newMockServer(t *testing.T, status int, body string, captured **http.Request, capturedBody *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if captured != nil {
			*captured = r
		}
		if capturedBody != nil {
			buf, _ := io.ReadAll(r.Body)
			*capturedBody = string(buf)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// requestZatcaComplianceCsid happy path (zatca.ts:539-637): POST
// {base}/compliance, OTP header, body {csr: base64(csr)}, 2xx → ACCEPTED
// with token/secret extracted.
func TestComplianceCSIDAccepted(t *testing.T) {
	var gotReq *http.Request
	var gotBody string
	server := newMockServer(t, http.StatusOK,
		`{"binarySecurityToken":"TOKEN123","secret":"SECRET456","requestID":"req-1","dispositionMessage":"ignored"}`,
		&gotReq, &gotBody)
	defer server.Close()

	resp := testClient(server.URL).ComplianceCSID(t.Context(), "csr-data", "OTP-1")

	if resp.Status != authority.StatusAccepted {
		t.Fatalf("Status = %q, want ACCEPTED", resp.Status)
	}
	if resp.BinarySecurityToken != "TOKEN123" || resp.Secret != "SECRET456" {
		t.Fatalf("credentials = %q/%q", resp.BinarySecurityToken, resp.Secret)
	}
	if resp.RequestID != "req-1" {
		t.Fatalf("RequestID = %q", resp.RequestID)
	}
	if resp.Error != nil {
		t.Fatalf("Error = %+v, want nil", resp.Error)
	}

	if gotReq.URL.Path != "/compliance" {
		t.Fatalf("path = %q, want /compliance", gotReq.URL.Path)
	}
	if gotReq.Method != http.MethodPost {
		t.Fatalf("method = %q", gotReq.Method)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("request body unparsable: %v (%q)", err, gotBody)
	}
	if want := base64.StdEncoding.EncodeToString([]byte("csr-data")); body["csr"] != want {
		t.Fatalf("csr body = %q, want base64 %q", body["csr"], want)
	}

	d := resp.Diagnostics
	if d.Endpoint != server.URL+"/compliance" {
		t.Fatalf("diagnostics endpoint = %q", d.Endpoint)
	}
	if d.HTTPStatus != http.StatusOK || d.ResponseStatus != authority.StatusAccepted {
		t.Fatalf("diagnostics status = %d/%q", d.HTTPStatus, d.ResponseStatus)
	}
	if d.DurationMS < 0 {
		t.Fatalf("duration = %d", d.DurationMS)
	}
	if len(d.ResponseKeys) == 0 {
		t.Fatalf("response keys missing: %+v", d)
	}
	if len(d.Errors) != 0 || len(d.Warnings) != 0 {
		t.Fatalf("unexpected diagnostics errors/warnings: %+v", d)
	}
}

// Rejected with an errors array (zatca.ts:579, 475-494): non-2xx → REJECTED,
// first error promoted to the response error with "" defaults.
func TestComplianceCSIDRejectedWithErrors(t *testing.T) {
	server := newMockServer(t, http.StatusBadRequest,
		`{"errors":[{"code":"1004","category":"OTP_INVALID","message":"Invalid OTP"}]}`,
		nil, nil)
	defer server.Close()

	resp := testClient(server.URL).ComplianceCSID(t.Context(), "csr", "bad-otp")

	if resp.Status != authority.StatusRejected {
		t.Fatalf("Status = %q, want REJECTED", resp.Status)
	}
	if resp.BinarySecurityToken != "" || resp.Secret != "" {
		t.Fatalf("credentials must be empty on rejection: %q/%q", resp.BinarySecurityToken, resp.Secret)
	}
	if resp.Error == nil || resp.Error.Code != "1004" || resp.Error.Category != "OTP_INVALID" || resp.Error.Message != "Invalid OTP" {
		t.Fatalf("Error = %+v", resp.Error)
	}
	if resp.Diagnostics.ResponseStatus != authority.StatusRejected || resp.Diagnostics.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("diagnostics = %+v", resp.Diagnostics)
	}
}

// String-shaped error items coerce to ZATCA_VALIDATION_ERROR/CSR_VALIDATION
// (zatca.ts:234-241).
func TestComplianceCSIDStringErrorItems(t *testing.T) {
	server := newMockServer(t, http.StatusBadRequest, `{"errors":["CSR subject failed validation"]}`, nil, nil)
	defer server.Close()

	resp := testClient(server.URL).ComplianceCSID(t.Context(), "csr", "otp")

	if len(resp.Diagnostics.Errors) != 1 {
		t.Fatalf("errors = %+v", resp.Diagnostics.Errors)
	}
	e := resp.Diagnostics.Errors[0]
	if e.Code != "ZATCA_VALIDATION_ERROR" || e.Category != "CSR_VALIDATION" || e.Message != "CSR subject failed validation" {
		t.Fatalf("error item = %+v", e)
	}
	if resp.Error == nil || resp.Error.Message != "CSR subject failed validation" {
		t.Fatalf("promoted error = %+v", resp.Error)
	}
}

// dispositionMessage fallback when REJECTED carries no errors
// (zatca.ts:580-590) — category CSR_VALIDATION on the compliance flow.
func TestComplianceCSIDDispositionMessageFallback(t *testing.T) {
	server := newMockServer(t, http.StatusUnauthorized, `{"dispositionMessage":"DISPO-X"}`, nil, nil)
	defer server.Close()

	resp := testClient(server.URL).ComplianceCSID(t.Context(), "csr", "otp")

	if len(resp.Diagnostics.Errors) != 1 {
		t.Fatalf("errors = %+v, want the disposition fallback", resp.Diagnostics.Errors)
	}
	e := resp.Diagnostics.Errors[0]
	if e.Code != "DISPO-X" || e.Category != "CSR_VALIDATION" || e.Message != "DISPO-X" {
		t.Fatalf("fallback error = %+v", e)
	}
}

// Warnings merge from data.warnings AND
// data.validationResults.warningMessages (zatca.ts:591-598).
func TestComplianceCSIDWarningsMerged(t *testing.T) {
	server := newMockServer(t, http.StatusOK,
		`{"binarySecurityToken":"t","secret":"s","warnings":[{"code":"W1","message":"w-one"}],"validationResults":{"warningMessages":["w-two"]}}`,
		nil, nil)
	defer server.Close()

	resp := testClient(server.URL).ComplianceCSID(t.Context(), "csr", "otp")

	if len(resp.Diagnostics.Warnings) != 2 {
		t.Fatalf("warnings = %+v, want 2", resp.Diagnostics.Warnings)
	}
	if resp.Diagnostics.Warnings[0].Code != "W1" || resp.Diagnostics.Warnings[1].Message != "w-two" {
		t.Fatalf("warnings = %+v", resp.Diagnostics.Warnings)
	}
}

// HTML error page under load (zatca.ts:302-309): body parses to nil — status
// still follows HTTP, response keys are absent, preview passes through raw.
func TestComplianceCSIDHTMLBody(t *testing.T) {
	server := newMockServer(t, http.StatusBadGateway, "<html>502 Service Unavailable</html>", nil, nil)
	defer server.Close()

	resp := testClient(server.URL).ComplianceCSID(t.Context(), "csr", "otp")

	if resp.Status != authority.StatusRejected {
		t.Fatalf("Status = %q", resp.Status)
	}
	if resp.Diagnostics.ResponseKeys != nil {
		t.Fatalf("response keys = %+v, want nil for unparsable body", resp.Diagnostics.ResponseKeys)
	}
	if resp.Diagnostics.RawResponsePreview != "<html>502 Service Unavailable</html>" {
		t.Fatalf("preview = %q", resp.Diagnostics.RawResponsePreview)
	}
	if len(resp.Diagnostics.Errors) != 0 {
		t.Fatalf("errors = %+v", resp.Diagnostics.Errors)
	}
}

// BUG-13: a hung call aborts at the configured budget and surfaces the
// distinct sentinel message so the BUG-14 retry classifier treats it as
// retryable FAILED, never terminal REJECTED (zatca.ts:23-34, 362-369).
func TestComplianceCSIDTimeoutSurfacesSentinel(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() { close(release); server.Close() }()

	client := authority.New(authority.Config{BaseURL: server.URL, Timeout: 50 * time.Millisecond})
	resp := client.ComplianceCSID(t.Context(), "csr", "otp")

	if resp.Status != authority.StatusRejected || resp.Diagnostics.ResponseStatus != "REQUEST_FAILED" {
		t.Fatalf("status = %q/%q, want REJECTED/REQUEST_FAILED", resp.Status, resp.Diagnostics.ResponseStatus)
	}
	errs := resp.Diagnostics.Errors
	if len(errs) != 1 || errs[0].Code != "REQUEST_FAILED" || errs[0].Category != "HTTP-Errors" {
		t.Fatalf("errors = %+v, want the REQUEST_FAILED/HTTP-Errors taxonomy", errs)
	}
	// The sentinel string itself — not the environment-specific abort text.
	if errs[0].Message != authority.TimeoutSentinelMessage {
		t.Fatalf("timeout message = %q, want the BUG-13 sentinel %q", errs[0].Message, authority.TimeoutSentinelMessage)
	}
	if resp.Error == nil || resp.Error.Code != "REQUEST_FAILED" || resp.Error.Message != authority.TimeoutSentinelMessage {
		t.Fatalf("response error = %+v", resp.Error)
	}
	if !authority.IsTimeoutSentinel(resp.Error.Message) {
		t.Fatal("the surfaced message must classify as the timeout sentinel for BUG-14")
	}
}

// Transport failure (connection refused) keeps the ORIGINAL error message —
// the unwrap step preserves raw-fetch-era strings (zatca.ts:387-405,
// 365-369) — and still never throws: REJECTED response.
func TestComplianceCSIDConnectionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close() // free the port → connection refused

	resp := testClient(url).ComplianceCSID(t.Context(), "csr", "otp")

	if resp.Status != authority.StatusRejected || resp.Diagnostics.ResponseStatus != "REQUEST_FAILED" {
		t.Fatalf("status = %q/%q", resp.Status, resp.Diagnostics.ResponseStatus)
	}
	msg := resp.Diagnostics.Errors[0].Message
	if authority.IsTimeoutSentinel(msg) {
		t.Fatalf("connection failure must not classify as timeout: %q", msg)
	}
	if strings.HasPrefix(msg, "ZATCA API connection failed") {
		t.Fatalf("diagnostics must carry the UNWRAPPED original error, got %q (zatca.ts:396-405)", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Fatalf("original dial error expected, got %q", msg)
	}
}

// Request id falls back to response headers (zatca.ts:270-278).
func TestComplianceCSIDRequestIDFromHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "hdr-9")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"binarySecurityToken":"t","secret":"s"}`))
	}))
	defer server.Close()

	resp := testClient(server.URL).ComplianceCSID(t.Context(), "csr", "otp")
	if resp.RequestID != "hdr-9" {
		t.Fatalf("RequestID = %q, want hdr-9", resp.RequestID)
	}
}

// requestZatcaProductionCsid (zatca.ts:639-739): POST {base}/production/csids
// with Basic auth over the compliance credentials and body
// {compliance_request_id}.
func TestProductionCSIDAccepted(t *testing.T) {
	var gotReq *http.Request
	var gotBody string
	server := newMockServer(t, http.StatusOK,
		`{"binarySecurityToken":"PROD-TOK","secret":"PROD-SEC","requestID":"pr-1"}`,
		&gotReq, &gotBody)
	defer server.Close()

	resp := testClient(server.URL).ProductionCSID(t.Context(),
		authority.Credentials{BinarySecurityToken: "comp-tok", Secret: "comp-sec"}, "crid-1")

	if resp.Status != authority.StatusAccepted || resp.BinarySecurityToken != "PROD-TOK" || resp.Secret != "PROD-SEC" {
		t.Fatalf("resp = %+v", resp)
	}
	if gotReq.URL.Path != "/production/csids" {
		t.Fatalf("path = %q", gotReq.URL.Path)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("comp-tok:comp-sec"))
	if gotReq.Header.Get("Authorization") != wantAuth {
		t.Fatalf("Authorization = %q, want %q", gotReq.Header.Get("Authorization"), wantAuth)
	}
	if gotReq.Header.Get("OTP") != "" {
		t.Fatal("production CSID must not send an OTP header")
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil || body["compliance_request_id"] != "crid-1" {
		t.Fatalf("body = %q (%v)", gotBody, err)
	}
}

// Production CSID merges data.errors AND
// validationResults.errorMessages (zatca.ts:672-678).
func TestProductionCSIDMergedValidationErrors(t *testing.T) {
	server := newMockServer(t, http.StatusBadRequest,
		`{"errors":[{"code":"E0","message":"top"}],"validationResults":{"errorMessages":[{"code":"E1","message":"nested"}]}}`,
		nil, nil)
	defer server.Close()

	resp := testClient(server.URL).ProductionCSID(t.Context(),
		authority.Credentials{BinarySecurityToken: "t", Secret: "s"}, "crid")

	errs := resp.Diagnostics.Errors
	if len(errs) != 2 || errs[0].Code != "E0" || errs[1].Code != "E1" {
		t.Fatalf("errors = %+v, want E0 then E1", errs)
	}
	if resp.Error == nil || resp.Error.Code != "E0" {
		t.Fatalf("first error promoted: %+v", resp.Error)
	}
}

// Production CSID dispositionMessage fallback uses category PRODUCTION_CSID
// (zatca.ts:679-689).
func TestProductionCSIDDispositionFallback(t *testing.T) {
	server := newMockServer(t, http.StatusForbidden, `{"dispositionMessage":"NOT-READY"}`, nil, nil)
	defer server.Close()

	resp := testClient(server.URL).ProductionCSID(t.Context(),
		authority.Credentials{BinarySecurityToken: "t", Secret: "s"}, "crid")

	e := resp.Diagnostics.Errors[0]
	if e.Code != "NOT-READY" || e.Category != "PRODUCTION_CSID" {
		t.Fatalf("fallback = %+v, want PRODUCTION_CSID category", e)
	}
}

// Last-resort HTTP_<status> fallback carries the raw body JSON
// (zatca.ts:690-696); an empty body yields NO fallback error at all.
func TestProductionCSIDHTTPStatusFallback(t *testing.T) {
	t.Run("json body", func(t *testing.T) {
		server := newMockServer(t, http.StatusNotFound, `{"foo":"bar"}`, nil, nil)
		defer server.Close()
		resp := testClient(server.URL).ProductionCSID(t.Context(),
			authority.Credentials{BinarySecurityToken: "t", Secret: "s"}, "crid")
		e := resp.Diagnostics.Errors[0]
		if e.Code != "HTTP_404" || e.Category != "HTTP-Errors" {
			t.Fatalf("fallback = %+v", e)
		}
		if !strings.Contains(e.Message, `"foo":"bar"`) {
			t.Fatalf("message should embed the raw body JSON: %q", e.Message)
		}
	})

	t.Run("plain body", func(t *testing.T) {
		server := newMockServer(t, http.StatusInternalServerError, "gateway exploded", nil, nil)
		defer server.Close()
		resp := testClient(server.URL).ProductionCSID(t.Context(),
			authority.Credentials{BinarySecurityToken: "t", Secret: "s"}, "crid")
		e := resp.Diagnostics.Errors[0]
		if e.Code != "HTTP_500" || e.Message != "gateway exploded" {
			t.Fatalf("fallback = %+v", e)
		}
	})

	t.Run("empty body skips the fallback", func(t *testing.T) {
		server := newMockServer(t, http.StatusBadGateway, "", nil, nil)
		defer server.Close()
		resp := testClient(server.URL).ProductionCSID(t.Context(),
			authority.Credentials{BinarySecurityToken: "t", Secret: "s"}, "crid")
		if resp.Diagnostics.Errors != nil || resp.Error != nil {
			t.Fatalf("errors = %+v / error = %+v, want none (zatca.ts:690 requires a body)", resp.Diagnostics.Errors, resp.Error)
		}
	})
}

// verifyZatcaComplianceInvoice (zatca.ts:741-867): POST
// {base}/compliance/invoices, basic auth, body {invoiceHash, uuid, invoice}.
func TestVerifyComplianceInvoiceWire(t *testing.T) {
	var gotReq *http.Request
	var gotBody string
	server := newMockServer(t, http.StatusOK,
		`{"validationResults":{"status":"PASS","errorMessages":[],"warningMessages":[]}}`,
		&gotReq, &gotBody)
	defer server.Close()

	resp := testClient(server.URL).VerifyComplianceInvoice(t.Context(),
		authority.Credentials{BinarySecurityToken: "tok", Secret: "sec"}, "hash-1", "uuid-1", "b64-invoice")

	if !resp.Valid {
		t.Fatalf("expected valid, got %+v", resp)
	}
	if gotReq.URL.Path != "/compliance/invoices" {
		t.Fatalf("path = %q", gotReq.URL.Path)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("tok:sec"))
	if gotReq.Header.Get("Authorization") != wantAuth {
		t.Fatalf("Authorization = %q", gotReq.Header.Get("Authorization"))
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body unparsable: %v", err)
	}
	if body["invoiceHash"] != "hash-1" || body["uuid"] != "uuid-1" || body["invoice"] != "b64-invoice" {
		t.Fatalf("body = %+v", body)
	}
}

func TestVerifyComplianceInvoiceOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantValid bool
		wantMsgs  []string
	}{
		{
			name:      "validation errors reject",
			status:    200,
			body:      `{"validationResults":{"errorMessages":[{"code":"2057","message":"bad hash"}]}}`,
			wantValid: false,
			wantMsgs:  []string{"ERROR: bad hash"},
		},
		{
			name:      "warnings keep valid",
			status:    200,
			body:      `{"validationResults":{"warningMessages":[{"code":"W","message":"watch it"}]}}`,
			wantValid: true,
			wantMsgs:  []string{"WARNING: watch it"},
		},
		{
			name:      "4xx json error envelope",
			status:    400,
			body:      `{"code":"2057","message":"Invalid invoice hash"}`,
			wantValid: false,
			wantMsgs:  []string{"ERROR: Invalid invoice hash"},
		},
		{
			name:      "4xx non-json body",
			status:    400,
			body:      "not-json",
			wantValid: false,
			wantMsgs:  []string{"ERROR: not-json"},
		},
		{
			name:      "5xx empty body",
			status:    500,
			body:      "",
			wantValid: false,
			wantMsgs:  []string{"ERROR: ZATCA returned HTTP 500 with an empty response body"},
		},
		{
			name:      "top-level errors array also rejects",
			status:    400,
			body:      `{"errors":[{"code":"X","message":"top-level"}]}`,
			wantValid: false,
			wantMsgs:  []string{"ERROR: top-level"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newMockServer(t, tt.status, tt.body, nil, nil)
			defer server.Close()
			resp := testClient(server.URL).VerifyComplianceInvoice(t.Context(),
				authority.Credentials{BinarySecurityToken: "t", Secret: "s"}, "h", "u", "i")
			if resp.Valid != tt.wantValid {
				t.Fatalf("Valid = %v, want %v (messages: %v)", resp.Valid, tt.wantValid, resp.Messages)
			}
			if len(resp.Messages) != len(tt.wantMsgs) {
				t.Fatalf("messages = %v, want %v", resp.Messages, tt.wantMsgs)
			}
			for i := range tt.wantMsgs {
				if resp.Messages[i] != tt.wantMsgs[i] {
					t.Fatalf("messages[%d] = %q, want %q", i, resp.Messages[i], tt.wantMsgs[i])
				}
			}
		})
	}
}

// The compliance-invoice failure path surfaces the classified diagnostics
// message — the BUG-13 sentinel for timeouts (zatca.ts:837-866).
func TestVerifyComplianceInvoiceTimeoutSentinel(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() { close(release); server.Close() }()

	client := authority.New(authority.Config{BaseURL: server.URL, Timeout: 40 * time.Millisecond})
	resp := client.VerifyComplianceInvoice(t.Context(),
		authority.Credentials{BinarySecurityToken: "t", Secret: "s"}, "h", "u", "i")

	if resp.Valid {
		t.Fatal("timeout must not be valid")
	}
	want := "ERROR: " + authority.TimeoutSentinelMessage
	if len(resp.Messages) != 1 || resp.Messages[0] != want {
		t.Fatalf("messages = %v, want [%q]", resp.Messages, want)
	}
}

// BUG-13 applies to every direct ZATCA call — including production CSID.
func TestProductionCSIDTimeoutSurfacesSentinel(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
	}))
	defer func() { close(release); server.Close() }()

	client := authority.New(authority.Config{BaseURL: server.URL, Timeout: 40 * time.Millisecond})
	resp := client.ProductionCSID(t.Context(),
		authority.Credentials{BinarySecurityToken: "t", Secret: "s"}, "crid")

	if got := calls.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1 (onboarding flows never retry)", got)
	}
	if resp.Diagnostics.Errors[0].Message != authority.TimeoutSentinelMessage {
		t.Fatalf("message = %+v", resp.Diagnostics.Errors[0])
	}
}
