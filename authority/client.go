// Package authority is the ZATCA Fatoora gateway HTTP client: CSID
// onboarding (compliance + production), invoice submission (clearance for
// standard B2B, reporting for simplified B2C) and status polling.
//
// It is a stdlib-only port of the production-proven TypeScript stack —
// apps/api/src/plugins/zatca.ts (the esellar authority plugin: onboarding
// flows, diagnostics, BUG-13 timeout sentinel) driving the upstream
// @talha7k/zatca dist/api client (clearance / reporting / status + the
// Effect retry schedule). Wire behavior — endpoints, headers, the 25s
// timeout budget, error taxonomy and the sentinel semantics — is preserved;
// only the transport owner moved to net/http.
//
// Divergences are called out at their site with a TS citation. Everything
// else mirrors the TS observable behavior, including the rule that
// onboarding flows NEVER fail on transport errors (they return a REJECTED
// response carrying REQUEST_FAILED diagnostics) while submission flows DO
// surface transport failures as *TransportError.
package authority

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultTimeout is the BUG-13 budget: every direct ZATCA HTTP call must
// abort after 25s. The TS queue consumer is capped at 60s by the platform —
// without a timeout, a hung ZATCA call eats the whole budget and gets
// killed, leaving the ambiguous "did ZATCA receive it?" state that feeds
// duplicate-submission bugs (BUG-09). The upstream library defaults to 30s
// (effect/http.js:17); the esellar plugin overrides to 25s (zatca.ts:23-31)
// and that override is the default here.
const DefaultTimeout = 25 * time.Second

const defaultClearanceStatus = "1"

// Environment mirrors ZatcaEnvironment (zatca.ts:21).
type Environment string

const (
	EnvironmentSandbox    Environment = "SANDBOX"
	EnvironmentProduction Environment = "PRODUCTION"
)

// ErrInvalidEnvironment wraps every ResolveEnvironment failure so callers
// can errors.Is against it.
var ErrInvalidEnvironment = errors.New("invalid ZATCA environment")

// ResolveEnvironment ports resolveZatcaEnvironment (zatca.ts:104-118):
// trim + lowercase, accept only sandbox/production, error otherwise with
// the offending value in the message.
func ResolveEnvironment(raw string) (Environment, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(raw)); normalized {
	case "sandbox":
		return EnvironmentSandbox, nil
	case "production":
		return EnvironmentProduction, nil
	default:
		return "", fmt.Errorf("%w %q. Expected SANDBOX or PRODUCTION.", ErrInvalidEnvironment, raw)
	}
}

// DefaultEnvironment ports the `environment ?? process.env.ZATCA_DEFAULT_ENV
// ?? "SANDBOX"` fallback (zatca.ts:107) — including the throw on a bogus
// env value (zatca.ts:115-117).
func DefaultEnvironment() (Environment, error) {
	raw, ok := os.LookupEnv("ZATCA_DEFAULT_ENV")
	if !ok {
		raw = "SANDBOX"
	}
	return ResolveEnvironment(raw)
}

// Gateway URL presets — the DEFAULT_* constants (zatca.ts:36-43).
const (
	DeveloperPortalBaseURL = "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal"
	SimulationBaseURL      = "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation"
	// Production CSID and invoice traffic both live under /core
	// (zatca.ts:40-43) — the upstream library's /core-portal default is
	// normalized away by NormalizeProductionInvoiceBaseURL.
	ProductionBaseURL = "https://gw-fatoora.zatca.gov.sa/e-invoicing/core"
)

// Credentials are the CSID pair the gateway issues — the Basic-auth
// username is the binarySecurityToken, the password the secret
// (zatca.ts:516-537).
type Credentials struct {
	BinarySecurityToken string
	Secret              string
}

// BasicAuth builds the Authorization header value:
// base64("<binarySecurityToken>:<secret>") (zatca.ts:521-523).
func BasicAuth(credentials Credentials) string {
	return base64.StdEncoding.EncodeToString(
		[]byte(credentials.BinarySecurityToken + ":" + credentials.Secret))
}

// Config configures a Client. Zero values get the TS defaults: Timeout →
// DefaultTimeout (BUG-13), ClearanceStatus → "1", Environment → SANDBOX,
// Retry → DefaultRetryConfig. A fully-specified Retry is honored verbatim
// (partial retry configs are not merged — set Retry: DefaultRetryConfig()
// and tweak, mirroring the TS `??` fallbacks).
type Config struct {
	Environment     Environment
	BaseURL         string
	Timeout         time.Duration
	ClearanceStatus string
	Retry           RetryConfig
	HTTPClient      *http.Client
}

// SandboxConfig targets the simulation gateway — POS Reporting/Clearance
// smoke must target simulation: the developer-portal sandbox can issue
// compliance material but its generated PCSID path is not reliable for
// final simplified invoice reporting (zatca.ts:149-155).
func SandboxConfig() Config {
	return Config{Environment: EnvironmentSandbox, BaseURL: SimulationBaseURL}
}

// DeveloperPortalConfig targets the developer-portal sandbox
// (ZATCA_SANDBOX_MODE=developer-portal, zatca.ts:152-154).
func DeveloperPortalConfig() Config {
	return Config{Environment: EnvironmentSandbox, BaseURL: DeveloperPortalBaseURL}
}

// ProductionConfig targets the ZATCA core gateway.
func ProductionConfig() Config {
	return Config{Environment: EnvironmentProduction, BaseURL: ProductionBaseURL}
}

// NormalizeProductionInvoiceBaseURL ports normalizeProductionInvoiceBaseUrl
// (zatca.ts:165-175): the upstream library defaults production invoice
// traffic to /core-portal, but ZATCA Core Solution invoice APIs are under
// /core/invoices/... — rewrite the suffix and strip trailing slashes.
func NormalizeProductionInvoiceBaseURL(baseURL string) string {
	trimmed := strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(trimmed, "/e-invoicing/core-portal") {
		trimmed = strings.TrimSuffix(trimmed, "/core-portal") + "/core"
	}
	return trimmed
}

// sandboxBaseURLFromEnv ports getZatcaSandboxBaseUrl (zatca.ts:144-155):
// ZATCA_SANDBOX_URL wins when SET (unset ≠ empty — LookupEnv, not Getenv),
// else developer-portal when ZATCA_SANDBOX_MODE=developer-portal, else
// simulation.
func sandboxBaseURLFromEnv() string {
	if v, ok := os.LookupEnv("ZATCA_SANDBOX_URL"); ok {
		return v
	}
	if os.Getenv("ZATCA_SANDBOX_MODE") == "developer-portal" {
		return DeveloperPortalBaseURL
	}
	return SimulationBaseURL
}

// ConfigFromEnv ports buildZatcaApiConfig + getZatcaInvoiceBaseUrl
// (zatca.ts:120-132, 177-190): the invoice base URL resolves from
// ZATCA_SANDBOX_INVOICE_URL / ZATCA_SANDBOX_URL / ZATCA_SANDBOX_MODE for
// sandbox, and ZATCA_PRODUCTION_INVOICE_URL / ZATCA_PRODUCTION_URL
// (normalized) for production. The esellar plugin resolves ONBOARDING
// endpoints from a separate base (getZatcaBaseUrl, zatca.ts:157-163) — that
// split is a deployment-env concern; callers construct the Config they need
// (e.g. BaseURL: firstNonEmpty(os.Getenv("ZATCA_PRODUCTION_URL"),
// ProductionBaseURL)).
func ConfigFromEnv(environment Environment) Config {
	cfg := Config{Environment: environment, Timeout: DefaultTimeout}
	if environment == EnvironmentProduction {
		base, ok := os.LookupEnv("ZATCA_PRODUCTION_INVOICE_URL")
		if !ok {
			base, ok = os.LookupEnv("ZATCA_PRODUCTION_URL")
			if !ok {
				base = ProductionBaseURL
			}
		}
		cfg.BaseURL = NormalizeProductionInvoiceBaseURL(base)
		return cfg
	}
	base, ok := os.LookupEnv("ZATCA_SANDBOX_INVOICE_URL")
	if !ok {
		base = sandboxBaseURLFromEnv()
	}
	cfg.BaseURL = strings.TrimRight(base, "/")
	return cfg
}

// EndpointMode classifies the resolved invoice endpoint
// (ZatcaEndpointMode, zatca.ts:192-196).
type EndpointMode string

const (
	ModeSimulation      EndpointMode = "SIMULATION"
	ModeDeveloperPortal EndpointMode = "DEVELOPER_PORTAL"
	ModeProduction      EndpointMode = "PRODUCTION"
	ModeCustom          EndpointMode = "CUSTOM"
)

// EndpointAuditInfo ports getZatcaEndpointAuditInfo (zatca.ts:198-223): the
// endpoint mode plus a log-safe fingerprint. On production the mode is
// PRODUCTION only when the endpoint equals the normalized default; sandbox
// classifies by the /simulation and /developer-portal path markers.
func EndpointAuditInfo(environment Environment) (EndpointMode, string) {
	endpoint := ConfigFromEnv(environment).BaseURL
	safe := SafeEndpointForLogs(endpoint)
	if environment == EnvironmentProduction {
		if endpoint == NormalizeProductionInvoiceBaseURL(ProductionBaseURL) {
			return ModeProduction, safe
		}
		return ModeCustom, safe
	}
	lower := strings.ToLower(endpoint)
	switch {
	case strings.Contains(lower, "/simulation"):
		return ModeSimulation, safe
	case strings.Contains(lower, "/developer-portal"):
		return ModeDeveloperPortal, safe
	default:
		return ModeCustom, safe
	}
}

// SafeEndpointForLogs ports getSafeEndpointForLogs (zatca.ts:225-228):
// origin + path only — credentials must never leak through query strings
// into logs.
func SafeEndpointForLogs(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// Client is a configured ZATCA Fatoora gateway client. It is safe for
// concurrent use.
type Client struct {
	baseURL         string
	environment     Environment
	timeout         time.Duration
	clearanceStatus string
	retry           RetryConfig
	http            *http.Client
}

// New builds a Client, applying the TS defaults to zero-valued Config
// fields (client.js:23-24 `??`, reporting.js:119-120).
func New(config Config) *Client {
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	clearanceStatus := config.ClearanceStatus
	if clearanceStatus == "" {
		clearanceStatus = defaultClearanceStatus
	}
	environment := config.Environment
	if environment == "" {
		environment = EnvironmentSandbox
	}
	retry := config.Retry
	if retry.MaxRetries == 0 && retry.BackoffMS == nil {
		retry = DefaultRetryConfig()
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{
		baseURL:         strings.TrimRight(config.BaseURL, "/"),
		environment:     environment,
		timeout:         timeout,
		clearanceStatus: clearanceStatus,
		retry:           retry,
		http:            httpClient,
	}
}

func (c *Client) Timeout() time.Duration   { return c.timeout }
func (c *Client) ClearanceStatus() string  { return c.clearanceStatus }
func (c *Client) RetryConfig() RetryConfig { return c.retry }
func (c *Client) BaseURL() string          { return c.baseURL }
func (c *Client) Environment() Environment { return c.environment }

// baseHeaders ports the four headers every request carries
// (client.js:14-19, zatca.ts:528-534).
func (c *Client) baseHeaders() map[string]string {
	return map[string]string{
		"Content-Type":    "application/json",
		"Accept":          "application/json",
		"Accept-Language": "en",
		"Accept-Version":  "V2",
	}
}

// ---- transport ----

type httpRequest struct {
	method  string
	url     string
	headers map[string]string
	body    string
}

type httpResponse struct {
	status  int
	body    string
	headers map[string]string // lowercased keys (zatca.ts:270-272)
}

// do performs one HTTP call under the BUG-13 budget. Transport failures
// return *TransportError and never a generic error, so callers can
// classify timeouts (the BUG-13 sentinel) vs connection failures exactly
// like the TS Effect transport does (effect/http.js:34-46).
func (c *Client) do(ctx context.Context, r httpRequest) (*httpResponse, *TransportError) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var reader io.Reader
	if r.body != "" {
		reader = strings.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, r.url, reader)
	if err != nil {
		return nil, &TransportError{Code: CodeAPIConnectionError, Message: connectionMessage(err), Err: err}
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if isTimeoutErr(err) {
			// effect/http.js:33 — "ZATCA API request timed out after <timeout>ms".
			return nil, &TransportError{
				Code:    CodeAPITimeout,
				Timeout: true,
				Message: fmt.Sprintf("ZATCA API request timed out after %dms", c.timeout.Milliseconds()),
				Err:     err,
			}
		}
		return nil, &TransportError{Code: CodeAPIConnectionError, Message: connectionMessage(err), Err: err}
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		// effect/http.js readBody fallback (line 69): the raw status line.
		body = []byte(fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
	headers := make(map[string]string, len(resp.Header))
	for k, values := range resp.Header {
		if len(values) > 0 {
			headers[strings.ToLower(k)] = values[0]
		}
	}
	return &httpResponse{status: resp.StatusCode, body: string(body), headers: headers}, nil
}

// connectionMessage ports the upstream connection-error format
// (effect/http.js:25-32). Go error chains already carry the syscall detail
// in their text, so the structured `(code: syscall hostname)` suffix has no
// Go equivalent to extract — the joined message keeps the same prefix.
func connectionMessage(err error) string {
	return "ZATCA API connection failed: " + err.Error()
}

// isTimeoutErr maps AbortError/TimeoutError semantics onto Go transports:
// a deadline hit on OUR budget, or a net timeout.
func isTimeoutErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
