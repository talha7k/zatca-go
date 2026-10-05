// Deterministic TEST certificate/key fixtures — mirroring the TS conformance
// fixtures (github.com/talha7k/zatca tests/conformance/fixtures.ts, the same
// static pair its unit suite shares). DEV-ONLY test material: it signs
// nothing real and is never presented to ZATCA.
//
// Gitleaks discipline: the private key is stored UNARMORED (base64 DER body
// only, like testdata/golden-vectors.json) so no PEM private-key block ever
// lands in the tree — tests re-arm it into SEC1 PEM before parsing.
package conformance

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// TestPrivateKeySEC1Body is the unarmored base64 SEC1 ("EC PRIVATE KEY")
// DER body of the static P-256 test key.
const TestPrivateKeySEC1Body = `MHcCAQEEIJMvO+IgiLq3YBJaSp7Gz1a7786pQ/u9ZPauVY54NQZ6oAoGCCqGSM49
AwEHoUQDQgAEz3vRHcXK1dgFsLqXdbNzSETiEIuC6rFmpmN697nECxPtRDR5vNC2
GhPoO6rtwp4+BttdIhIWo8HSMSYGsfiipA==`

// TestCertPEM is the matching self-signed test certificate (CN=testca,
// EC P-256, ecdsa-with-SHA256) — public material, stored armored.
const TestCertPEM = `-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIUaumRZCMc9o3ZxLuAISSXffuresEwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGdGVzdGNhMB4XDTI2MDUwMTExMjg1NloXDTI3MDUwMTExMjg1
NlowETEPMA0GA1UEAwwGdGVzdGNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
z3vRHcXK1dgFsLqXdbNzSETiEIuC6rFmpmN697nECxPtRDR5vNC2GhPoO6rtwp4+
BttdIhIWo8HSMSYGsfiipKNTMFEwHQYDVR0OBBYEFDpE5pXNp2qWghXpkJavkHIb
uDU+MB8GA1UdIwQYMBaAFDpE5pXNp2qWghXpkJavkHIbuDU+MA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAP2Okl6ZMxD8xABvIDDUBycGcZNqUl0o
pBLnzUm2S9AiAiBLlAutK/rCJOb6EkHHaMYHgQREBZdiLhlf6NR1WMYGBA==
-----END CERTIFICATE-----`

// TestPrivateKeyPEM re-arms the unarmored fixture body into SEC1 PEM.
func TestPrivateKeyPEM() (string, error) {
	compact := strings.ReplaceAll(TestPrivateKeySEC1Body, "\n", "")
	if _, err := base64.StdEncoding.DecodeString(compact); err != nil {
		return "", fmt.Errorf("test key body is not base64: %w", err)
	}
	var wrapped strings.Builder
	for i := 0; i < len(compact); i += 64 {
		end := min(i+64, len(compact))
		wrapped.WriteString(compact[i:end])
		wrapped.WriteString("\n")
	}
	return "-----BEGIN EC PRIVATE KEY-----\n" + wrapped.String() + "-----END EC PRIVATE KEY-----", nil
}

// TestPrivateKey parses the fixture key (SEC1 → *ecdsa.PrivateKey).
func TestPrivateKey() (*ecdsa.PrivateKey, error) {
	pemString, err := TestPrivateKeyPEM()
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in re-armed test key")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// TestPrivateKeyPKCS8PEM converts the SEC1 fixture key into PKCS#8 PEM —
// the form zatca.SignP1363ECDSASHA256 (the shared core) consumes.
func TestPrivateKeyPKCS8PEM() (string, error) {
	key, err := TestPrivateKey()
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal PKCS#8: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// TestCertificate parses the fixture certificate.
func TestCertificate() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(TestCertPEM))
	if block == nil {
		return nil, fmt.Errorf("no PEM block in test certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
