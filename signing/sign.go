// Invoice signing — the ZATCA signed-payload pipeline (the TS signInvoice
// twin): compute the canonical invoice hash, build the XAdES/XMLDSig
// structure, sign the canonical SignedInfo with ECDSA-SHA256 (DER), embed
// the QR and splice the signature into the ext:UBLExtensions placeholder.
//
// TS quirks mirrored byte-exactly (see README § signed path):
//   - digest values are base64 OF the hex digest text (double encoding),
//   - signing time is Z-less and millisecond-less,
//   - the SignatureValue is the ASN.1 DER ECDSA form,
//   - the invoice hash is re-derived after assembly and the document is
//     rebuilt once when it moved (the stabilization second pass).
package signing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	zatca "github.com/talha7k/zatca-go"
)

// QRSignData carries the QR fields the signing pipeline derives from the
// document context (tags 1..5 + 9; tags 6..8 come from the signing itself).
type QRSignData struct {
	// SellerName is QR tag 1 — MUST equal the XML cbc:RegistrationName.
	SellerName string
	// VATNumber is QR tag 2.
	VATNumber string
	// Timestamp is QR tag 3 — MUST equal cbc:IssueDate + 'T' + cbc:IssueTime.
	Timestamp string
	// TotalWithVAT is QR tag 4.
	TotalWithVAT string
	// VATTotal is QR tag 5 (empty renders as "0.00", the TS convention).
	VATTotal string
	// CertificateSignatureBase64 is QR tag 9 — the certificate's raw
	// signatureValue (CA signature over the CSID cert).
	CertificateSignatureBase64 string
}

// SignParams carries the signing inputs. SigningTime and
// SignatureValueDERBase64 are optional: empty SigningTime stamps the current
// UTC second; a provided SignatureValueDERBase64 (the external-signer /
// deterministic-fixture seam) is embedded instead of signing fresh.
type SignParams struct {
	// XML is the unsigned UBL document with an ext:UBLExtensions block.
	XML string
	// PrivateKeyPEM is the PKCS#8 or SEC1 ECDSA P-256 private key.
	PrivateKeyPEM string
	// CertificatePEM is the matching CSID certificate.
	CertificatePEM string
	// QRData embeds the Phase-2 QR (BR-KSA-27) when non-nil.
	QRData *QRSignData
	// SigningTime pins the XAdES SigningTime (deterministic fixtures/tests).
	SigningTime string
	// SignatureValueDERBase64 pins the DER signature (byte-parity fixtures;
	// the TS external-signer seam).
	SignatureValueDERBase64 string
}

// SignResult is the TS SignResult twin: the signed XML, the invoice hash it
// embeds (base64) and the DER signature value (base64).
type SignResult struct {
	SignedXML      string
	InvoiceHash    string
	SignatureValue string
}

// FormatSigningTime strips milliseconds and the Z suffix from an instant —
// the ZATCA signing time format (the TS formatSigningTime twin, which
// produces e.g. "2026-10-06T14:30:00" from a UTC instant).
func FormatSigningTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05")
}

// signingContext is the immutable per-sign state (the TS
// buildSigningContext output).
type signingContext struct {
	xml             string
	ublRoot         UBLRoot
	normalizedCert  string
	certificateB64  string
	certificateInfo CertificateInfo
	publicKeyB64    string
	qrData          *QRSignData
}

// SignInvoice signs a ZATCA invoice XML with ECDSA-SHA256, mirroring the TS
// signInvoice pipeline:
//
//  1. compute the invoice hash (canonical form minus the signature blocks),
//  2. build the XMLDSig structure (exclusion transforms, references),
//  3. sign the canonical SignedInfo (DER),
//  4. build the UBL DocumentSignatures wrapper,
//  5. replace the UBLExtensions placeholder and embed the QR,
//  6. re-hash; when the hash moved, rebuild once with the final hash.
func SignInvoice(params SignParams) (*SignResult, error) {
	normalizedCert, err := NormalizeCertificatePEM(params.CertificatePEM)
	if err != nil {
		return nil, err
	}
	cert, err := zatca.ParseCertificatePEM(normalizedCert)
	if err != nil {
		return nil, err
	}
	if !HasUBLExtensionsPlaceholder(params.XML) {
		return nil, fmt.Errorf("signing: invoice XML must contain ext:UBLExtensions placeholder")
	}
	ublRoot, err := GetUBLRoot(params.XML)
	if err != nil {
		return nil, err
	}
	privateKey, err := parseAnyPrivateKeyPEM(params.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	publicKeyB64, err := extractQrPublicKey(cert, privateKey)
	if err != nil {
		return nil, err
	}
	certInfo, err := GetCertificateInfo(normalizedCert)
	if err != nil {
		return nil, err
	}
	ctx := signingContext{
		xml:             params.XML,
		ublRoot:         ublRoot,
		normalizedCert:  normalizedCert,
		certificateB64:  PemBody(normalizedCert),
		certificateInfo: *certInfo,
		publicKeyB64:    publicKeyB64,
		qrData:          params.QRData,
	}

	// build mirrors one buildSignedXml pass; each pass stamps its own
	// signing time when not pinned (the TS quirk: createSignedInfoForHash
	// re-stamps on the stabilization rebuild).
	build := func(invoiceHash string) (*SignResult, error) {
		signingTime := params.SigningTime
		if signingTime == "" {
			signingTime = FormatSigningTime(time.Now())
		}
		signatureValue := params.SignatureValueDERBase64
		if signatureValue == "" {
			signedInfoXML := BuildSignedInfo(invoiceHash, DigestSdkSignedProperties(ctx.certificateInfo, signingTime))
			canonicalSignedInfo, err := CanonicalizeXML(signedInfoXML)
			if err != nil {
				return nil, err
			}
			signatureValue, err = signCanonicalSignedInfo(privateKey, canonicalSignedInfo)
			if err != nil {
				return nil, err
			}
		}
		return buildSignedXMLWithSignature(ctx, invoiceHash, signatureValue, signingTime)
	}

	first, err := CanonicalizeForHash(params.XML)
	if err != nil {
		return nil, err
	}
	result, err := build(first.HashBase64)
	if err != nil {
		return nil, err
	}
	final, err := CanonicalizeForHash(result.SignedXML)
	if err != nil {
		return nil, err
	}
	if final.HashBase64 != first.HashBase64 {
		result, err = build(final.HashBase64)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// buildSignedXMLWithSignature is the TS buildSignedXmlWithSignature twin.
func buildSignedXMLWithSignature(ctx signingContext, invoiceHash string, signatureValue string, signingTime string) (*SignResult, error) {
	signedPropertiesDigest := DigestSdkSignedProperties(ctx.certificateInfo, signingTime)
	signedInfoXML := BuildSignedInfo(invoiceHash, signedPropertiesDigest)
	signatureXML := BuildSignatureXML(signedInfoXML, signatureValue, ctx.certificateB64, ctx.certificateInfo, signingTime)

	var qrBase64 *string
	if ctx.qrData != nil {
		tlv, err := zatca.GeneratePhase2TLV(zatca.QRData{
			SellerName:           ctx.qrData.SellerName,
			VATNumber:            ctx.qrData.VATNumber,
			Timestamp:            ctx.qrData.Timestamp,
			TotalWithVAT:         ctx.qrData.TotalWithVAT,
			VATTotal:             ctx.qrData.VATTotal,
			InvoiceHash:          invoiceHash,
			Signature:            signatureValue,
			PublicKey:            decodeMustBase64("publicKey", ctx.publicKeyB64),
			CertificateSignature: decodeMustBase64("certificateSignature", ctx.qrData.CertificateSignatureBase64),
		})
		if err != nil {
			return nil, err
		}
		encoded := base64.StdEncoding.EncodeToString(tlv)
		qrBase64 = &encoded
	}
	signedXML, err := AssembleSignedXML(ctx.xml, ctx.ublRoot.Name, signatureXML, qrBase64)
	if err != nil {
		return nil, err
	}
	return &SignResult{SignedXML: signedXML, InvoiceHash: invoiceHash, SignatureValue: signatureValue}, nil
}

func decodeMustBase64(field string, value string) []byte {
	raw, err := lenientBase64Decode(strings.TrimSpace(value))
	if err != nil {
		panic(fmt.Sprintf("signing: %s must be valid base64: %v", field, err))
	}
	return raw
}

// signCanonicalSignedInfo produces the DER base64 ECDSA-SHA256 signature —
// the TS signSignedInfo twin (node crypto createSign('SHA256')).
func signCanonicalSignedInfo(key *ecdsa.PrivateKey, canonicalSignedInfo string) (string, error) {
	digest := sha256.Sum256([]byte(canonicalSignedInfo))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing: ECDSA sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// extractQrPublicKey derives the QR tag-8 public key (base64 SPKI DER) from
// the certificate and verifies the private key matches — the TS
// extractQrPublicKey twin (mismatch throws).
func extractQrPublicKey(cert *x509.Certificate, privateKey *ecdsa.PrivateKey) (string, error) {
	certPublicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("signing: certificate key is %T, want ECDSA", cert.PublicKey)
	}
	certSPKI, err := x509MarshalPKIX(certPublicKey)
	if err != nil {
		return "", err
	}
	keySPKI, err := x509MarshalPKIX(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}
	if string(certSPKI) != string(keySPKI) {
		return "", fmt.Errorf("signing: private key does not match the supplied CSID certificate")
	}
	return base64.StdEncoding.EncodeToString(certSPKI), nil
}

// VerifySignature verifies the embedded signature of a signed invoice (for
// testing / debugging) — the TS verifySignature twin: it extracts
// ds:SignedInfo + ds:SignatureValue, canonicalizes the fragment and verifies
// the DER ECDSA-SHA256 signature with the certificate/public-key PEM.
func VerifySignature(signedXML string, publicKeyPEM string) bool {
	sigMatch := signatureValuePattern.FindStringSubmatch(signedXML)
	signedInfoMatch := signedInfoPattern.FindString(signedXML)
	if sigMatch == nil || signedInfoMatch == "" {
		return false
	}
	canonical, err := CanonicalizeXML(signedInfoMatch)
	if err != nil {
		return false
	}
	key, err := parsePublicKeyPEM(publicKeyPEM)
	if err != nil {
		return false
	}
	der, err := base64.StdEncoding.DecodeString(sigMatch[1])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(canonical))
	return ecdsa.VerifyASN1(key, digest[:], der)
}

var (
	signatureValuePattern = regexp.MustCompile(`<ds:SignatureValue[^>]*>([^<]+)</ds:SignatureValue>`)
	signedInfoPattern     = regexp.MustCompile(`<ds:SignedInfo[\s\S]*?</ds:SignedInfo>`)
)
