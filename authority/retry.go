// Reporting retry schedule — the Go port of @talha7k/zatca
// dist/effect/schedule.js: only transport failures and 5xx API responses
// are retryable; everything else fails fast. Delays are explicit and
// deterministic: the Effect workflow applies Schedule.jittered (each delay
// scaled by a random factor in [0.8, 1.2)) which a deterministic library
// port drops by design — tests and the drain engine depend on reproducible
// timing, and the clamped-verbatim delay array is the load-bearing part.
package authority

import "time"

// RetryConfig configures the reporting retry loop (reporting.js:118-121,
// schedule.js:18-19): MaxRetries retries AFTER the initial attempt;
// BackoffMS supplies per-attempt delays verbatim, clamping to the last
// entry when retries exceed the array length; an empty array means no
// delay.
type RetryConfig struct {
	MaxRetries int
	BackoffMS  []int
}

// DefaultRetryConfig mirrors the TS defaults: 3 retries with
// [5000, 30000, 300000] backoff (schedule.js:18-19).
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{MaxRetries: 3, BackoffMS: []int{5000, 30000, 300000}}
}

// delayFor ports schedule.js:36-38 — 1-based attempt index, clamped to the
// last entry, zero when the array is empty.
func delayFor(backoffs []int, attempt int) time.Duration {
	if len(backoffs) == 0 {
		return 0
	}
	index := attempt - 1
	if index > len(backoffs)-1 {
		index = len(backoffs) - 1
	}
	if index < 0 {
		index = 0
	}
	return time.Duration(backoffs[index]) * time.Millisecond
}
