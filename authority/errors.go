// Error taxonomy — the transport half of the TS ZatcaError hierarchy
// (errors.js:4-24) plus the API-level errors the status endpoint throws
// (status.js:18-27). Submission/onboarding outcomes that the TS surfaces as
// return VALUES (rejected CSIDs, PARSE_ERROR results) stay values here —
// see the constructors' citations.
package authority

import "errors"

// Transport error codes mirror ZatcaErrorCode (errors.js:6-9).
const (
	CodeAPIError           = "API_ERR"
	CodeAPIConnectionError = "API_CONN_ERR"
	CodeAPITimeout         = "API_TIMEOUT_ERR"
)

// TransportError is a connection failure or a timeout — the two failure
// classes the TS transport raises (effect/http.js:34-46 map AbortError →
// ZatcaTimeoutError, everything else → ZatcaConnectionError). The ORIGINAL
// network error stays wrapped in Err so the esellar unwrap semantics
// (unwrapZatcaTransportError, zatca.ts:396-405 — connection errors carry
// the original fetch failure so classification and surfaced messages stay
// byte-identical to the raw-fetch era) port directly: read Err, not
// Message, when feeding the diagnostics/BUG-14 classifier.
type TransportError struct {
	// Code is CodeAPITimeout or CodeAPIConnectionError.
	Code string
	// Message is the transport-layer message ("ZATCA API request timed out
	// after <ms>ms" / "ZATCA API connection failed: …").
	Message string
	// Timeout is true exactly when the BUG-13 budget aborted the call.
	Timeout bool
	// Err is the ORIGINAL wrapped network error.
	Err error
}

func (e *TransportError) Error() string { return e.Message }

func (e *TransportError) Unwrap() error { return e.Err }

// APIError is an API-level failure the TS throws as
// ZatcaError(API_ERROR): the status endpoint's 404 and its unparseable
// response body (status.js:18-27).
type APIError struct {
	Message    string
	HTTPStatus int
	Body       string
}

func (e *APIError) Error() string { return e.Message }

// Compile-time shape guards.
var (
	_ error = (*TransportError)(nil)
	_ error = (*APIError)(nil)
	_ error = errors.ErrUnsupported // keep the errors import anchored to docs
)
