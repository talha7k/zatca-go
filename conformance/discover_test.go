// Discovery + config bootstrap + fixture unit tests (no SDK required).
package conformance

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestWriteSDKConfigUsesAbsolutePaths(t *testing.T) {
	sdkHome := t.TempDir()
	for _, relative := range SDKConfigRelativePaths {
		if err := os.MkdirAll(filepath.Join(sdkHome, filepath.Dir(relative)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	path, err := WriteSDKConfig(sdkHome, dir)
	if err != nil {
		t.Fatalf("WriteSDKConfig: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, "\\\\") || strings.Contains(content, "D:") {
		t.Error("config must never carry Windows paths")
	}
	for _, key := range []string{"xsdPath", "enSchematron", "zatcaSchematron", "certPath", "privateKeyPath", "pihPath", "inputPath", "usagePathFile", "certPassword"} {
		if !strings.Contains(content, `"`+key+`"`) {
			t.Errorf("config missing key %q", key)
		}
	}
	if !strings.Contains(content, sdkHome+string(filepath.Separator)) {
		t.Error("config paths must be absolute under the SDK home")
	}
	if !strings.Contains(content, SDKConfigPassword) {
		t.Error("certPassword missing")
	}
}

func TestDiscoverSDKFromEnv(t *testing.T) {
	sdkHome := t.TempDir()
	apps := filepath.Join(sdkHome, "Apps")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(apps, "cli-3.0.8-jar-with-dependencies.jar")
	if err := os.WriteFile(jar, []byte("jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZATCA_SDK_HOME", sdkHome)
	inst, reason := DiscoverSDK(t.TempDir())
	if inst == nil {
		t.Fatalf("SDK must be discovered from env, reason=%q", reason)
	}
	if inst.CliJar != jar || inst.Version != "3.0.8" {
		t.Errorf("installation = %+v", inst)
	}
}

func TestDiscoverSDKFromRepoRoot(t *testing.T) {
	t.Setenv("ZATCA_SDK_HOME", "")
	repo := t.TempDir()
	apps := filepath.Join(repo, "zatca-envoice-sdk-203", "Apps")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		t.Fatal(err)
	}
	jar := filepath.Join(apps, "cli-3.0.8-jar-with-dependencies.jar")
	if err := os.WriteFile(jar, []byte("jar"), 0o600); err != nil {
		t.Fatal(err)
	}
	inst, reason := DiscoverSDK(repo)
	if inst == nil {
		t.Fatalf("SDK dir must be auto-discovered, reason=%q", reason)
	}
	if inst.Home != filepath.Join(repo, "zatca-envoice-sdk-203") {
		t.Errorf("home = %q", inst.Home)
	}
}

func TestDiscoverSDKAbsent(t *testing.T) {
	t.Setenv("ZATCA_SDK_HOME", "")
	inst, reason := DiscoverSDK(t.TempDir())
	if inst != nil {
		t.Fatalf("empty repo must not discover an SDK: %+v", inst)
	}
	if !strings.Contains(reason, "SDK not found") {
		t.Errorf("reason must carry install instructions, got %q", reason)
	}
}

func TestDiscoverSDKEnvWithoutAppsRejected(t *testing.T) {
	t.Setenv("ZATCA_SDK_HOME", t.TempDir())
	inst, reason := DiscoverSDK(t.TempDir())
	if inst != nil {
		t.Fatal("env dir without Apps/ must be rejected")
	}
	if !strings.Contains(reason, "Apps") {
		t.Errorf("reason must name the missing Apps/ layout, got %q", reason)
	}
}

func TestFixturesParseAndVerify(t *testing.T) {
	key, err := TestPrivateKey()
	if err != nil {
		t.Fatalf("TestPrivateKey: %v", err)
	}
	cert, err := TestCertificate()
	if err != nil {
		t.Fatalf("TestCertificate: %v", err)
	}
	certKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key is %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if key.Curve.Params().Name != certKey.Curve.Params().Name {
		t.Error("fixture key and certificate must share the curve")
	}
	if certKey.X.Cmp(key.X) != 0 || certKey.Y.Cmp(key.Y) != 0 {
		t.Error("certificate public key differs from the fixture key")
	}
	if cert.Subject.CommonName != "testca" {
		t.Errorf("cert CN = %q", cert.Subject.CommonName)
	}
}

func TestFixturesNoPEMPrivateKeyBlockInSource(t *testing.T) {
	// Gitleaks discipline: the committed source must not carry an armored
	// private-key BLOCK (header + base64 body + footer). The unarmored body
	// const plus a constructed armor string is the approved pattern (same as
	// testdata/golden-vectors.json).
	raw, err := os.ReadFile("fixtures.go")
	if err != nil {
		t.Fatal(err)
	}
	blockPattern := regexp.MustCompile(`(?s)-----BEGIN EC PRIVATE KEY-----\s*[A-Za-z0-9+/=]+\s*-----END EC PRIVATE KEY-----`)
	if blockPattern.Match(raw) {
		t.Error("fixtures.go must not embed an armored private-key block")
	}
	if strings.Contains(TestPrivateKeySEC1Body, "BEGIN") {
		t.Error("the stored key body must be unarmored")
	}
	if _, err := TestPrivateKeyPEM(); err != nil {
		t.Errorf("re-arming must still work: %v", err)
	}
}
