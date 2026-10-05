// Sentinel/edge-case semantics tests — the BUG-13 family the esellar TS
// plugin encodes (timeout sentinel, object-only gateway JSON, request-id
// extraction, preview redaction, diagnostic-message coercion). Every case
// cites the TS file:line it pins.
package authority_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/talha7k/zatca-go/authority"
)

// The BUG-13 sentinel string is load-bearing: the BUG-14 retry classifier
// matches it to treat a hung gateway call as retryable FAILED instead of
// terminal REJECTED (zatca.ts:31-34, 362-369).
func TestTimeoutSentinelMessageExactString(t *testing.T) {
	if got := authority.TimeoutSentinelMessage; got != "ZATCA request timed out after 25s" {
		t.Fatalf("TimeoutSentinelMessage = %q, want %q", got, "ZATCA request timed out after 25s")
	}
}

// isAbortOrTimeoutError port (zatca.ts:411-427): name-based AbortError /
// TimeoutError or message containing aborted / timed out / timeout
// (case-insensitive).
func TestIsTimeoutSentinel(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    bool
	}{
		{name: "exact sentinel", message: authority.TimeoutSentinelMessage, want: true},
		{name: "upstream transport timeout format", message: "ZATCA API request timed out after 25000ms", want: true},
		{name: "aborted", message: "The operation was aborted.", want: true},
		{name: "AbortError name", message: "AbortError: signal is aborted without reason", want: true},
		{name: "TimeoutError DOMException", message: "TimeoutError: The operation timed out.", want: true},
		{name: "mixed case TIMEOUT", message: "Gateway TIMEOUT occurred", want: true},
		{name: "connection refused is not a sentinel", message: `Post "https://x": dial tcp: connect: connection refused`, want: false},
		{name: "empty", message: "", want: false},
		{name: "unrelated", message: "invalid CSR payload", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authority.IsTimeoutSentinel(tt.message); got != tt.want {
				t.Fatalf("IsTimeoutSentinel(%q) = %v, want %v", tt.message, got, tt.want)
			}
		})
	}
}

// parseZatcaJsonObject (zatca.ts:310-319, W4 Schema boundary): the Fatoora
// portal answers with HTML error pages and truncated bodies under load —
// only a plain JSON object passes; arrays, scalars, null and unparsable
// bodies all reject to nil.
func TestParseZatcaJSONObject(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantObj bool
	}{
		{name: "object", body: `{"a":1}`, wantObj: true},
		{name: "empty object", body: `{}`, wantObj: true},
		{name: "array rejects", body: `[1,2]`, wantObj: false},
		{name: "string scalar rejects", body: `"text"`, wantObj: false},
		{name: "number scalar rejects", body: `42`, wantObj: false},
		{name: "null rejects", body: `null`, wantObj: false},
		{name: "html error page rejects", body: `<html><body>502 Service Unavailable</body></html>`, wantObj: false},
		{name: "truncated body rejects", body: `{"binarySecurityToken":"abc`, wantObj: false},
		{name: "empty body rejects", body: ``, wantObj: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authority.ParseZatcaJSONObject(tt.body)
			if tt.wantObj && got == nil {
				t.Fatalf("ParseZatcaJSONObject(%q) = nil, want an object", tt.body)
			}
			if !tt.wantObj && got != nil {
				t.Fatalf("ParseZatcaJSONObject(%q) = %v, want nil", tt.body, got)
			}
		})
	}
}

// getRequestId (zatca.ts:258-279): body requestID / requestId (string or
// finite number), else lowercase header lookups x-request-id / request-id /
// x-correlation-id.
func TestRequestIDFrom(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		headers map[string]string
		want    string
	}{
		{name: "requestID string", body: `{"requestID":"rid-1"}`, want: "rid-1"},
		{name: "requestId string", body: `{"requestId":"rid-2"}`, want: "rid-2"},
		{name: "requestID number", body: `{"requestID":4242}`, want: "4242"},
		{name: "empty string body id falls through to headers", body: `{"requestID":""}`, headers: map[string]string{"x-request-id": "hdr-1"}, want: "hdr-1"},
		{name: "x-request-id header", body: `{}`, headers: map[string]string{"x-request-id": "hdr-2"}, want: "hdr-2"},
		{name: "request-id header", body: `{}`, headers: map[string]string{"request-id": "hdr-3"}, want: "hdr-3"},
		{name: "x-correlation-id header", body: `{}`, headers: map[string]string{"x-correlation-id": "hdr-4"}, want: "hdr-4"},
		{name: "header precedence", body: `{}`, headers: map[string]string{"x-request-id": "a", "request-id": "b", "x-correlation-id": "c"}, want: "a"},
		{name: "body wins over headers", body: `{"requestID":"body"}`, headers: map[string]string{"x-request-id": "hdr"}, want: "body"},
		{name: "absent", body: `{}`, want: ""},
		{name: "nil data", body: "", headers: map[string]string{}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := authority.ParseZatcaJSONObject(tt.body)
			got := authority.RequestIDFrom(data, tt.headers)
			if got != tt.want {
				t.Fatalf("RequestIDFrom = %q, want %q", got, tt.want)
			}
		})
	}
}

// getMessageArray (zatca.ts:230-256): string items become
// ZATCA_VALIDATION_ERROR / CSR_VALIDATION entries; object items are
// field-coerced; numbers/bools/null are dropped; non-arrays yield empty.
func TestMessageArray(t *testing.T) {
	t.Run("string items map to CSR_VALIDATION defaults", func(t *testing.T) {
		got := authority.MessageArray(json.RawMessage(`["first msg", "second msg"]`))
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2", len(got))
		}
		if got[0].Code != "ZATCA_VALIDATION_ERROR" || got[0].Category != "CSR_VALIDATION" || got[0].Message != "first msg" {
			t.Fatalf("got[0] = %+v", got[0])
		}
	})

	t.Run("object items are field-coerced", func(t *testing.T) {
		got := authority.MessageArray(json.RawMessage(`[{"code":"1004","category":"OTP_INVALID","message":"bad","type":"ERROR","status":"ERROR"}]`))
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		want := authority.DiagnosticMessage{Code: "1004", Category: "OTP_INVALID", Message: "bad", Type: "ERROR", Status: "ERROR"}
		if got[0] != want {
			t.Fatalf("got = %+v, want %+v", got[0], want)
		}
	})

	t.Run("junk items dropped", func(t *testing.T) {
		got := authority.MessageArray(json.RawMessage(`[42, true, null, {"code":"ok"}, "str"]`))
		if len(got) != 2 {
			t.Fatalf("len = %d, want 2 (object + string), got %+v", len(got), got)
		}
		if got[0].Code != "ok" || got[1].Message != "str" {
			t.Fatalf("got = %+v", got)
		}
	})

	t.Run("non-array yields empty", func(t *testing.T) {
		for _, raw := range []json.RawMessage{json.RawMessage(`{"code":"x"}`), json.RawMessage(`"s"`), json.RawMessage(`null`), json.RawMessage(``)} {
			if got := authority.MessageArray(raw); len(got) != 0 {
				t.Fatalf("MessageArray(%s) = %+v, want empty", raw, got)
			}
		}
	})
}

// getResponsePreview (zatca.ts:281-299): object bodies are re-serialized
// with secret-ish keys redacted; non-object bodies pass through raw; both
// are capped at 2000 chars.
func TestResponsePreview(t *testing.T) {
	t.Run("redacts sensitive keys", func(t *testing.T) {
		body := `{"binarySecurityToken":"TOKEN","secret":"SECRET","certificate":"CERT","privateKey":"PK","csr":"CSR","otp":"OTP","vatNumber":"310"}
		`
		data := authority.ParseZatcaJSONObject(body)
		preview := authority.ResponsePreview(body, data)
		for _, leaked := range []string{"TOKEN", "SECRET", "CERT", "PK", "CSR"} {
			if strings.Contains(preview, leaked) {
				t.Fatalf("preview leaks %q: %s", leaked, preview)
			}
		}
		if !strings.Contains(preview, "OTP") || !strings.Contains(preview, "310") {
			t.Fatalf("preview dropped non-sensitive fields: %s", preview)
		}
		if !strings.Contains(preview, "[redacted]") {
			t.Fatalf("preview missing [redacted] marker: %s", preview)
		}
	})

	t.Run("redaction is recursive", func(t *testing.T) {
		body := `{"validationResults":{"errorMessages":[],"secret":"NESTED"}}`
		data := authority.ParseZatcaJSONObject(body)
		preview := authority.ResponsePreview(body, data)
		if strings.Contains(preview, "NESTED") {
			t.Fatalf("preview leaks nested secret: %s", preview)
		}
	})

	t.Run("non-object body passes through raw", func(t *testing.T) {
		preview := authority.ResponsePreview("<html>boom</html>", nil)
		if preview != "<html>boom</html>" {
			t.Fatalf("preview = %q", preview)
		}
	})

	t.Run("capped at 2000 chars", func(t *testing.T) {
		long := strings.Repeat("a", 5000)
		preview := authority.ResponsePreview(long, nil)
		if len([]rune(preview)) != 2000 {
			t.Fatalf("preview length = %d, want 2000", len([]rune(preview)))
		}
	})

	t.Run("empty body yields empty preview", func(t *testing.T) {
		if preview := authority.ResponsePreview("", nil); preview != "" {
			t.Fatalf("preview = %q, want empty", preview)
		}
	})
}
