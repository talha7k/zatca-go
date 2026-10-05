// BUG-13 sentinel + gateway edge-case semantics, ported from
// apps/api/src/plugins/zatca.ts. Every symbol cites the TS file:line it
// pins. These are load-bearing behaviors, not conveniences: the retry
// classifier (BUG-14), the audit trail (diagnostics previews) and the
// gateway's HTML-under-load reality all depend on them.
package authority

import (
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// TimeoutSentinelMessage is the sentinel error message surfaced whenever a
// ZATCA call aborts after its timeout budget (zatca.ts:34). BUG-13: a
// distinct sentinel lets the BUG-14 retry classifier treat the outcome as
// retryable FAILED rather than terminal REJECTED (zatca.ts:362-369).
const TimeoutSentinelMessage = "ZATCA request timed out after 25s"

// IsTimeoutSentinel ports isAbortOrTimeoutError (zatca.ts:411-427): true
// when the message is the AbortError/TimeoutError family — "aborted",
// "timed out" or "timeout", case-insensitive. The TS also matches by
// error.name ("AbortError" | "TimeoutError"); those names contain the same
// substrings, so the message heuristic covers them.
func IsTimeoutSentinel(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "aborted") ||
		strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "timeout")
}

// ParseZatcaJSONObject ports parseZatcaJsonObject (zatca.ts:310-319, W4
// boundary): the Fatoora portal answers with HTML error pages and truncated
// bodies under load, so ONLY a plain JSON object passes. Arrays, scalars,
// null and unparsable bodies all yield nil (JSON null unmarshals to a nil
// map without error — same net result as the Schema.JsonObject reject).
func ParseZatcaJSONObject(body string) map[string]any {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return nil
	}
	return parsed
}

// RequestIDFrom ports getRequestId (zatca.ts:258-279): body requestID /
// requestId (string, or a finite number stringified), else the lowercase
// header lookups x-request-id → request-id → x-correlation-id (the TS
// transport lowercases response header names, zatca.ts:270-272).
func RequestIDFrom(data map[string]any, headers map[string]string) string {
	if data != nil {
		for _, key := range []string{"requestID", "requestId"} {
			value, ok := data[key]
			if !ok || value == nil {
				continue
			}
			switch typed := value.(type) {
			case string:
				if typed != "" {
					return typed
				}
			case float64:
				if !math.IsNaN(typed) && !math.IsInf(typed, 0) {
					return strconv.FormatFloat(typed, 'f', -1, 64)
				}
			}
		}
	}
	for _, header := range []string{"x-request-id", "request-id", "x-correlation-id"} {
		if v := headers[header]; v != "" {
			return v
		}
	}
	return ""
}

// DiagnosticMessage ports ZatcaCsidDiagnosticMessage (zatca.ts:45-51).
// Absent fields are empty strings.
type DiagnosticMessage struct {
	Code     string
	Category string
	Message  string
	Type     string
	Status   string
}

// MessageArray ports getMessageArray (zatca.ts:230-256): string items
// become ZATCA_VALIDATION_ERROR / CSR_VALIDATION entries; object items are
// field-coerced (non-string fields dropped); numbers, bools and null items
// are dropped; non-arrays yield nil. Accepts either a decoded value (as the
// TS call sites pass `data?.errors`) or raw JSON bytes.
func MessageArray(raw any) []DiagnosticMessage {
	switch typed := raw.(type) {
	case json.RawMessage:
		return messageArrayFromJSON(typed)
	case []byte:
		return messageArrayFromJSON(json.RawMessage(typed))
	case []any:
		return messageArrayFromItems(typed)
	default:
		return nil
	}
}

func messageArrayFromJSON(raw json.RawMessage) []DiagnosticMessage {
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	return MessageArray(parsed)
}

func messageArrayFromItems(items []any) []DiagnosticMessage {
	out := make([]DiagnosticMessage, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, DiagnosticMessage{
				Code:     "ZATCA_VALIDATION_ERROR",
				Category: "CSR_VALIDATION",
				Message:  text,
			})
			continue
		}
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, DiagnosticMessage{
			Code:     stringField(obj, "code"),
			Category: stringField(obj, "category"),
			Message:  stringField(obj, "message"),
			Type:     stringField(obj, "type"),
			Status:   stringField(obj, "status"),
		})
	}
	return out
}

// sensitiveKeyPattern is the redaction match from getResponsePreview
// (zatca.ts:286-293) — binarySecurityToken is redundant (contains "token")
// but kept verbatim for documentation parity.
var sensitiveKeyPattern = regexp.MustCompile(`(?i)token|secret|certificate|private|csr|binarySecurityToken`)

// responsePreviewLimit caps raw_response_preview (zatca.ts:298).
const responsePreviewLimit = 2000

// ResponsePreview ports getResponsePreview (zatca.ts:281-299): object
// bodies are re-serialized with sensitive keys replaced by "[redacted]"
// (recursively); non-object bodies pass through raw; everything is capped
// at 2000 characters. The redaction works on a fresh re-parse of the body —
// JSON.stringify(data, replacer) never mutates the parsed payload, and the
// shared map must stay intact for response extraction. Divergence: Go's
// json.Marshal sorts map keys while JSON.stringify preserves insertion
// order — the preview is a log/audit artifact, never a parsed field, so key
// order carries no behavior.
func ResponsePreview(body string, data map[string]any) string {
	if body == "" {
		return ""
	}
	sanitized := body
	if data != nil {
		var clone any
		if err := json.Unmarshal([]byte(body), &clone); err == nil {
			redactSensitive(clone)
			if encoded, err := json.Marshal(clone); err == nil {
				sanitized = string(encoded)
			}
		}
	}
	runes := []rune(sanitized)
	if len(runes) > responsePreviewLimit {
		return string(runes[:responsePreviewLimit])
	}
	return sanitized
}

func redactSensitive(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, inner := range typed {
			if sensitiveKeyPattern.MatchString(key) {
				typed[key] = "[redacted]"
				continue
			}
			typed[key] = redactSensitive(inner)
		}
	case []any:
		for i := range typed {
			typed[i] = redactSensitive(typed[i])
		}
	}
	return value
}

// ---- shared untyped-JSON field helpers ----

// stringField coerces a JSON object field to a string, "" when absent or
// non-string (the TS `typeof item.x === "string" ? item.x : undefined`
// pattern, zatca.ts:248-252).
func stringField(data map[string]any, key string) string {
	if data == nil {
		return ""
	}
	value, ok := data[key]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

// mapField returns a nested object, nil when absent or not an object.
func mapField(data map[string]any, key string) map[string]any {
	if data == nil {
		return nil
	}
	value, _ := data[key].(map[string]any)
	return value
}

// fieldAt returns a field as a decoded JSON value (any) — the accessor for
// array-shaped fields (data.errors, data.warnings, validationResults.*)
// that mapField would nil out.
func fieldAt(data map[string]any, key string) any {
	if data == nil {
		return nil
	}
	return data[key]
}

// truncateRunes mirrors JS String.prototype.substring(0, n) used by
// status.js:26.
func truncateRunes(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit])
}
