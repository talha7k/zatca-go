// Client configuration tests — environment resolution, base-URL presets and
// normalization, wire header assembly, and the BUG-13 default timeout.
// Citations reference apps/api/src/plugins/zatca.ts and the upstream
// @talha7k/zatca dist the plugin drives.
package authority_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/talha7k/zatca-go/authority"
)

// unsetenv removes an env var for the duration of the test (t.Setenv can
// only set — the TS plugin distinguishes unset from empty via
// `process.env.X !== undefined`, zatca.ts:145/180).
func unsetenv(t *testing.T, key string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("Unsetenv(%q): %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, old)
		}
	})
}

// resolveZatcaEnvironment (zatca.ts:104-118): trim + lowercase, only
// sandbox/production accepted, anything else (including empty) errors with
// the offending value in the message.
func TestResolveEnvironment(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    authority.Environment
		wantErr bool
	}{
		{name: "SANDBOX", raw: "SANDBOX", want: authority.EnvironmentSandbox},
		{name: "production mixed case", raw: " Production ", want: authority.EnvironmentProduction},
		{name: "sandbox lowercase", raw: "sandbox", want: authority.EnvironmentSandbox},
		{name: "invalid", raw: "staging", wantErr: true},
		{name: "empty", raw: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authority.ResolveEnvironment(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveEnvironment(%q) = %v, want error", tt.raw, got)
				}
				if !errors.Is(err, authority.ErrInvalidEnvironment) {
					t.Fatalf("error = %v, want ErrInvalidEnvironment", err)
				}
				if tt.raw != "" && !contains(err.Error(), tt.raw) {
					t.Fatalf("error message %q should mention the offending value %q", err.Error(), tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveEnvironment(%q) errored: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("ResolveEnvironment(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// normalizeProductionInvoiceBaseUrl (zatca.ts:165-175): the upstream library
// defaults production invoice traffic to /core-portal, but ZATCA Core
// Solution invoice APIs live under /core.
func TestNormalizeProductionInvoiceBaseURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "core-portal rewritten to core", input: "https://gw/e-invoicing/core-portal", want: "https://gw/e-invoicing/core"},
		{name: "core unchanged", input: "https://gw/e-invoicing/core", want: "https://gw/e-invoicing/core"},
		{name: "trailing slashes stripped", input: "https://gw/e-invoicing/core///", want: "https://gw/e-invoicing/core"},
		{name: "core-portal with trailing slashes", input: "https://gw/e-invoicing/core-portal/", want: "https://gw/e-invoicing/core"},
		{name: "custom host untouched", input: "https://proxy.internal/gateway", want: "https://proxy.internal/gateway"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authority.NormalizeProductionInvoiceBaseURL(tt.input); got != tt.want {
				t.Fatalf("NormalizeProductionInvoiceBaseURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// Gateway URL presets — DEFAULT_* constants (zatca.ts:36-43).
func TestConfigPresets(t *testing.T) {
	if got := authority.DeveloperPortalBaseURL; got != "https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal" {
		t.Fatalf("DeveloperPortalBaseURL = %q", got)
	}
	if got := authority.SimulationBaseURL; got != "https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation" {
		t.Fatalf("SimulationBaseURL = %q", got)
	}
	if got := authority.ProductionBaseURL; got != "https://gw-fatoora.zatca.gov.sa/e-invoicing/core" {
		t.Fatalf("ProductionBaseURL = %q", got)
	}

	sandbox := authority.SandboxConfig()
	if sandbox.BaseURL != authority.SimulationBaseURL || sandbox.Environment != authority.EnvironmentSandbox {
		t.Fatalf("SandboxConfig() = %+v", sandbox)
	}
	// POS Reporting/Clearance smoke defaults to simulation, NOT the
	// developer portal (zatca.ts:149-155).
	portal := authority.DeveloperPortalConfig()
	if portal.BaseURL != authority.DeveloperPortalBaseURL || portal.Environment != authority.EnvironmentSandbox {
		t.Fatalf("DeveloperPortalConfig() = %+v", portal)
	}
	prod := authority.ProductionConfig()
	if prod.BaseURL != authority.ProductionBaseURL || prod.Environment != authority.EnvironmentProduction {
		t.Fatalf("ProductionConfig() = %+v", prod)
	}
}

// DefaultClientSettings: BUG-13 25s budget (zatca.ts:23-31) and the
// Clearance-Status default "1" (client.js:24, clearanceStatus ?? '1').
func TestDefaultClientSettings(t *testing.T) {
	if got := authority.DefaultTimeout; got != 25*time.Second {
		t.Fatalf("DefaultTimeout = %v, want 25s", got)
	}
	client := authority.New(authority.Config{BaseURL: "https://example.invalid"})
	if client.Timeout() != authority.DefaultTimeout {
		t.Fatalf("client timeout = %v, want the 25s BUG-13 default", client.Timeout())
	}
	if got := client.ClearanceStatus(); got != "1" {
		t.Fatalf("ClearanceStatus = %q, want \"1\"", got)
	}
}

// getSafeEndpointForLogs (zatca.ts:225-228): origin + path only —
// credentials must never leak through query strings into logs.
func TestSafeEndpointForLogs(t *testing.T) {
	got := authority.SafeEndpointForLogs("https://gw-fatoora.zatca.gov.sa/e-invoicing/core/invoices/status/x?token=leak")
	want := "https://gw-fatoora.zatca.gov.sa/e-invoicing/core/invoices/status/x"
	if got != want {
		t.Fatalf("SafeEndpointForLogs = %q, want %q", got, want)
	}
}

// getZatcaEndpointAuditInfo (zatca.ts:198-223).
func TestEndpointAuditInfo(t *testing.T) {
	t.Run("sandbox default is SIMULATION", func(t *testing.T) {
		unsetenv(t, "ZATCA_SANDBOX_URL")
		unsetenv(t, "ZATCA_SANDBOX_MODE")
		unsetenv(t, "ZATCA_SANDBOX_INVOICE_URL")
		mode, fingerprint := authority.EndpointAuditInfo(authority.EnvironmentSandbox)
		if mode != authority.ModeSimulation {
			t.Fatalf("mode = %v, want SIMULATION", mode)
		}
		if fingerprint != authority.SimulationBaseURL {
			t.Fatalf("fingerprint = %q, want %q", fingerprint, authority.SimulationBaseURL)
		}
	})

	t.Run("developer-portal mode", func(t *testing.T) {
		t.Setenv("ZATCA_SANDBOX_MODE", "developer-portal")
		mode, _ := authority.EndpointAuditInfo(authority.EnvironmentSandbox)
		if mode != authority.ModeDeveloperPortal {
			t.Fatalf("mode = %v, want DEVELOPER_PORTAL", mode)
		}
	})

	t.Run("custom sandbox endpoint", func(t *testing.T) {
		t.Setenv("ZATCA_SANDBOX_INVOICE_URL", "https://proxy.internal/gw")
		mode, fingerprint := authority.EndpointAuditInfo(authority.EnvironmentSandbox)
		if mode != authority.ModeCustom {
			t.Fatalf("mode = %v, want CUSTOM", mode)
		}
		if fingerprint != "https://proxy.internal/gw" {
			t.Fatalf("fingerprint = %q", fingerprint)
		}
	})

	t.Run("production default is PRODUCTION", func(t *testing.T) {
		unsetenv(t, "ZATCA_PRODUCTION_URL")
		unsetenv(t, "ZATCA_PRODUCTION_INVOICE_URL")
		mode, fingerprint := authority.EndpointAuditInfo(authority.EnvironmentProduction)
		if mode != authority.ModeProduction {
			t.Fatalf("mode = %v, want PRODUCTION", mode)
		}
		if fingerprint != authority.ProductionBaseURL {
			t.Fatalf("fingerprint = %q, want %q", fingerprint, authority.ProductionBaseURL)
		}
	})

	t.Run("production core-portal env var is normalized", func(t *testing.T) {
		// zatca.ts:205-211: PRODUCTION mode requires the endpoint to equal
		// the normalized DEFAULT (the gateway host) — a core-portal URL on
		// the default host normalizes back to /core and counts as
		// PRODUCTION.
		t.Setenv("ZATCA_PRODUCTION_INVOICE_URL", "https://gw-fatoora.zatca.gov.sa/e-invoicing/core-portal")
		mode, fingerprint := authority.EndpointAuditInfo(authority.EnvironmentProduction)
		if mode != authority.ModeProduction {
			t.Fatalf("core-portal env must normalize to the PRODUCTION mode, got %v", mode)
		}
		if fingerprint != authority.ProductionBaseURL {
			t.Fatalf("fingerprint = %q, want %q", fingerprint, authority.ProductionBaseURL)
		}
	})

	t.Run("production custom host is CUSTOM even when core-portal-normalized", func(t *testing.T) {
		t.Setenv("ZATCA_PRODUCTION_INVOICE_URL", "https://proxy.internal/e-invoicing/core-portal")
		mode, fingerprint := authority.EndpointAuditInfo(authority.EnvironmentProduction)
		if mode != authority.ModeCustom {
			t.Fatalf("custom host must stay CUSTOM, got %v", mode)
		}
		if fingerprint != "https://proxy.internal/e-invoicing/core" {
			t.Fatalf("fingerprint must carry the normalized path, got %q", fingerprint)
		}
	})
}

// getZatcaSandboxBaseUrl / getZatcaInvoiceBaseUrl / getZatcaBaseUrl env
// resolution (zatca.ts:144-190).
func TestConfigFromEnv(t *testing.T) {
	t.Run("sandbox defaults to simulation", func(t *testing.T) {
		unsetenv(t, "ZATCA_SANDBOX_URL")
		unsetenv(t, "ZATCA_SANDBOX_MODE")
		unsetenv(t, "ZATCA_SANDBOX_INVOICE_URL")
		cfg := authority.ConfigFromEnv(authority.EnvironmentSandbox)
		if cfg.BaseURL != authority.SimulationBaseURL {
			t.Fatalf("BaseURL = %q, want simulation", cfg.BaseURL)
		}
	})

	t.Run("ZATCA_SANDBOX_URL wins", func(t *testing.T) {
		t.Setenv("ZATCA_SANDBOX_URL", "https://override.internal/gw")
		cfg := authority.ConfigFromEnv(authority.EnvironmentSandbox)
		if cfg.BaseURL != "https://override.internal/gw" {
			t.Fatalf("BaseURL = %q", cfg.BaseURL)
		}
	})

	t.Run("ZATCA_SANDBOX_MODE=developer-portal", func(t *testing.T) {
		unsetenv(t, "ZATCA_SANDBOX_URL")
		t.Setenv("ZATCA_SANDBOX_MODE", "developer-portal")
		cfg := authority.ConfigFromEnv(authority.EnvironmentSandbox)
		if cfg.BaseURL != authority.DeveloperPortalBaseURL {
			t.Fatalf("BaseURL = %q, want developer-portal", cfg.BaseURL)
		}
	})

	t.Run("invoice URL override strips trailing slashes", func(t *testing.T) {
		t.Setenv("ZATCA_SANDBOX_INVOICE_URL", "https://gw/simulation///")
		cfg := authority.ConfigFromEnv(authority.EnvironmentSandbox)
		if cfg.BaseURL != "https://gw/simulation" {
			t.Fatalf("BaseURL = %q", cfg.BaseURL)
		}
	})

	t.Run("production invoice URL wins and is normalized", func(t *testing.T) {
		t.Setenv("ZATCA_PRODUCTION_INVOICE_URL", "https://gw/e-invoicing/core-portal")
		t.Setenv("ZATCA_PRODUCTION_URL", "https://other.internal/x")
		cfg := authority.ConfigFromEnv(authority.EnvironmentProduction)
		if cfg.BaseURL != "https://gw/e-invoicing/core" {
			t.Fatalf("BaseURL = %q", cfg.BaseURL)
		}
	})

	t.Run("production falls back to ZATCA_PRODUCTION_URL", func(t *testing.T) {
		unsetenv(t, "ZATCA_PRODUCTION_INVOICE_URL")
		t.Setenv("ZATCA_PRODUCTION_URL", "https://other.internal/x")
		cfg := authority.ConfigFromEnv(authority.EnvironmentProduction)
		if cfg.BaseURL != "https://other.internal/x" {
			t.Fatalf("BaseURL = %q", cfg.BaseURL)
		}
	})

	t.Run("production default is core", func(t *testing.T) {
		unsetenv(t, "ZATCA_PRODUCTION_INVOICE_URL")
		unsetenv(t, "ZATCA_PRODUCTION_URL")
		cfg := authority.ConfigFromEnv(authority.EnvironmentProduction)
		if cfg.BaseURL != authority.ProductionBaseURL {
			t.Fatalf("BaseURL = %q, want core", cfg.BaseURL)
		}
	})
}

// Basic auth is base64("binarySecurityToken:secret") —
// buildAuthenticatedZatcaRequest (zatca.ts:521-523).
func TestBasicAuth(t *testing.T) {
	got := authority.BasicAuth(authority.Credentials{BinarySecurityToken: "tok", Secret: "sec"})
	want := base64.StdEncoding.EncodeToString([]byte("tok:sec"))
	if got != want {
		t.Fatalf("BasicAuth = %q, want %q", got, want)
	}
}

// certificatePemToBase64Token (device-csid-registration.ts:112-121): the
// ZATCA binarySecurityToken IS the base64(DER) body of the issued
// certificate — armor-stripping the stored PEM reconstructs the Basic-auth
// username exactly.
func TestCertificatePEMToBase64Token(t *testing.T) {
	got, err := authority.CertificatePEMToBase64Token("-----BEGIN CERTIFICATE-----\nAbC\nDeF\n-----END CERTIFICATE-----\n")
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if got != "AbCDeF" {
		t.Fatalf("token = %q, want %q", got, "AbCDeF")
	}

	if _, err := authority.CertificatePEMToBase64Token("-----BEGIN CERTIFICATE----------END CERTIFICATE-----"); err == nil {
		t.Fatal("empty certificate body must error")
	}
}

// Every request carries the four base headers (client.js:14-19,
// zatca.ts:528-534); OTP replaces Basic auth on the compliance CSID call
// (client.js:22-27, zatca.ts:556-565); Clearance-Status rides only on
// clearance/reporting submissions (clearance.js:23).
func TestWireHeaders(t *testing.T) {
	var got http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := authority.New(authority.Config{BaseURL: server.URL, Timeout: 2 * time.Second})
	client.ComplianceCSID(t.Context(), "csr-data", "OTP-1")

	if got.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", got.Get("Content-Type"))
	}
	if got.Get("Accept") != "application/json" {
		t.Fatalf("Accept = %q", got.Get("Accept"))
	}
	if got.Get("Accept-Language") != "en" {
		t.Fatalf("Accept-Language = %q", got.Get("Accept-Language"))
	}
	if got.Get("Accept-Version") != "V2" {
		t.Fatalf("Accept-Version = %q", got.Get("Accept-Version"))
	}
	if got.Get("OTP") != "OTP-1" {
		t.Fatalf("OTP = %q", got.Get("OTP"))
	}
	// OTP wins over Basic auth — the compliance endpoint must never see
	// credentials (client.js:22-27 else-if).
	if got.Get("Authorization") != "" {
		t.Fatalf("Authorization must be absent on the OTP flow, got %q", got.Get("Authorization"))
	}
}
