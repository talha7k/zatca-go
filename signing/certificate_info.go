// Certificate info — the TS getCertificateInfo twin: the XAdES
// SigningCertificate digest, issuer serial and the double-encoded
// digestValue quirk (base64 OF the hex digest text — mirrored byte-exactly
// because ZATCA hash parity depends on it).
package signing

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	zatca "github.com/talha7k/zatca-go"
)

// PemBody strips the PEM armor and all whitespace, leaving base64 DER — the
// TS pemBody twin.
func PemBody(certificatePEM string) string {
	replacer := strings.NewReplacer(
		"-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
	)
	compact := replacer.Replace(certificatePEM)
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, compact)
}

// CertificateInfo carries the XAdES SigningCertificate fields as the TS
// signing path derives them.
type CertificateInfo struct {
	// DigestValue is base64(hex(SHA-256(pemBody))) — the TS double encoding.
	DigestValue string
	// IssuerName is the certificate issuer rendered the way Node renders
	// X509Certificate.issuer: OpenSSL short names, one RDN per line in
	// certificate order — reversed and comma-joined by the TS pipeline.
	IssuerName string
	// SerialNumber is the decimal serial (Node BigInt('0x…').toString(10)).
	SerialNumber string
}

// opensslShortNames maps the DER attribute OIDs to the OpenSSL/Node short
// names the reversed issuer string uses. Values outside the map fall back to
// the dotted OID (Node prints the unknown-OID dotted form too).
var opensslShortNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "street",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"2.5.4.15":                   "businessCategory",
	"0.9.2342.19200300.100.1.1":  "UID",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"1.2.840.113549.1.9.2":       "unstructuredName",
	"1.2.840.113549.1.9.8":       "unstructuredAddress",
}

// renderNodeIssuer renders the RDN sequence the way Node's
// X509Certificate.issuer does: OpenSSL short names, "TYPE=value", one RDN
// per line in certificate order, multi-value RDNs joined by '+'.
func renderNodeIssuer(sequence pkix.RDNSequence) string {
	lines := make([]string, 0, len(sequence))
	for _, rdn := range sequence {
		parts := make([]string, 0, len(rdn))
		for _, atv := range rdn {
			oid := atv.Type.String()
			name, known := opensslShortNames[oid]
			if !known {
				name = oid
			}
			value, _ := atv.Value.(string)
			parts = append(parts, name+"="+value)
		}
		lines = append(lines, strings.Join(parts, "+"))
	}
	return strings.Join(lines, "\n")
}

// GetCertificateInfo derives the TS signing-path certificate info from a
// PEM certificate. The DigestValue hashes the PEM BODY TEXT (not the DER),
// mirroring getCertificateInfo exactly. IssuerName reproduces the TS
// `cert.issuer.split('\n').reverse().join(', ')` transformation.
func GetCertificateInfo(certificatePEM string) (*CertificateInfo, error) {
	cert, err := zatca.ParseCertificatePEM(certificatePEM)
	if err != nil {
		return nil, err
	}
	// Go parses the issuer into pkix.Name; the RAW RDN sequence (preserving
	// grouping) is re-read from the DER for the Node rendering.
	var issuerSequence pkix.RDNSequence
	if _, err := asn1.Unmarshal(cert.RawIssuer, &issuerSequence); err != nil {
		return nil, fmt.Errorf("signing: unmarshal issuer sequence: %w", err)
	}
	nodeIssuer := renderNodeIssuer(issuerSequence)
	lines := strings.Split(nodeIssuer, "\n")
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return &CertificateInfo{
		DigestValue:  base64OfUtf8(sha256HexOf(PemBody(certificatePEM))),
		IssuerName:   strings.Join(lines, ", "),
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// NormalizeCertificatePEM coerces PEM / bare-base64 / double-encoded
// certificate input into the standard 64-column PEM form — the TS
// normalizeCertificatePem twin.
func NormalizeCertificatePEM(certificate string) (string, error) {
	compact := certificate
	if strings.Contains(certificate, "BEGIN CERTIFICATE") {
		compact = PemBody(certificate)
	} else {
		compact = stripWhitespace(certificate)
	}
	directDER, err := lenientBase64Decode(compact)
	if err != nil {
		return "", fmt.Errorf("signing: certificate is not base64: %w", err)
	}
	if len(directDER) > 0 && directDER[0] == 0x30 {
		return wrapCertificateBody(compact), nil
	}
	decoded := strings.TrimSpace(string(directDER))
	if strings.Contains(decoded, "BEGIN CERTIFICATE") {
		return NormalizeCertificatePEM(decoded)
	}
	decodedCompact := stripWhitespace(decoded)
	if base64Shape.MatchString(decodedCompact) {
		nestedDER, err := lenientBase64Decode(decodedCompact)
		if err == nil && len(nestedDER) > 0 && nestedDER[0] == 0x30 {
			return wrapCertificateBody(decodedCompact), nil
		}
	}
	return wrapCertificateBody(compact), nil
}

func wrapCertificateBody(body string) string {
	wrapped := ""
	for i := 0; i < len(body); i += 64 {
		end := min(i+64, len(body))
		if i > 0 {
			wrapped += "\n"
		}
		wrapped += body[i:end]
	}
	return "-----BEGIN CERTIFICATE-----\n" + wrapped + "\n-----END CERTIFICATE-----"
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' {
			return -1
		}
		return r
	}, s)
}

var base64Shape = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

// lenientBase64Decode decodes standard base64, tolerating missing padding —
// the Node Buffer.from semantics this pipeline relies on.
func lenientBase64Decode(value string) ([]byte, error) {
	if value == "" {
		return []byte{}, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

// parseAnyPrivateKeyPEM parses a PEM private key in PKCS#8 or SEC1 form —
// the flexibility Node's createSign accepts.
func parseAnyPrivateKeyPEM(privateKeyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("signing: no PEM block in private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, fmt.Errorf("signing: private key is %T, want ECDSA", key)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse private key: %w", err)
	}
	return key, nil
}

// parsePublicKeyPEM parses a PEM certificate (its public key is extracted,
// like Node's crypto.verify({key: certificatePem})) or an SPKI public key.
func parsePublicKeyPEM(publicKeyOrCertPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyOrCertPEM))
	if block == nil {
		return nil, fmt.Errorf("signing: no PEM block in public key material")
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signing: certificate key is %T, want ECDSA", cert.PublicKey)
		}
		return key, nil
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing: parse public key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing: public key is %T, want ECDSA", parsed)
	}
	return key, nil
}

// x509MarshalPKIX marshals a public key to SPKI DER (the QR tag-8 bytes).
func x509MarshalPKIX(key *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

// sha256HexOf hashes text to the lowercase hex digest.
func sha256HexOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", sum)
}

// base64OfUtf8 base64-encodes the UTF-8 text — the second half of the TS
// double-encoded digest quirk.
func base64OfUtf8(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}

// does (identical decimal rendering; big.Int already parsed from DER).
