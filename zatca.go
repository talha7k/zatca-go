// Package zatca is a dependency-free Go implementation of the ZATCA
// (Saudi Arabia, Zakat, Tax and Customs Authority) phase-2 e-invoicing
// compliance crypto core.
//
// It is a byte-exact port of the production-proven TypeScript stack
// (@talha7k/zatca-qr TLV + @esellar/contracts + WebCrypto ECDSA) used by
// the esellar platform; parity is pinned by golden vectors generated from
// the TS implementation (testdata/golden-vectors.json). The package covers:
//
//   - QR TLV encoding (tags 1..9, BER short/long lengths) — GeneratePhase2TLV
//   - QR TLV decoding and the exact-tags-1..9 shape check — ParseTLV
//   - the QR base64 composite embedded in invoice XML — GenerateQRBase64
//   - invoice hashing (SHA-256 over canonical XML) — HashCanonical, HashChainNext
//   - ECDSA P-256 sign/verify in IEEE-P1363 raw r||s form — SignP1363ECDSASHA256,
//     VerifyP1363ECDSASHA256, with ASN.1 DER conversion — P1363ToDER, DERToP1363
//   - X.509 certificate parsing (PEM) — ParseCertificatePEM, PublicKeyFromPEM
//
// Out of scope by design (owned by the application layer / TS pipeline):
// UBL XML generation, XMLDSig/XAdES assembly, and ZATCA API transport.
//
// All types and functions are safe for concurrent use unless documented
// otherwise; none mutate shared state.
package zatca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
)

// ---------------------------------------------------------------------------
// QR TLV — encode
// ---------------------------------------------------------------------------

// QRData carries the nine ZATCA phase-2 QR fields, in tag order.
//
// Tags 1..7 are encoded as UTF-8 text (the values are trimmed, matching the
// TypeScript reference); tags 8 and 9 are binary DER values. InvoiceHash
// accepts either the 44-character base64 form (as stored on invoices) or a
// 64-character SHA-256 hex digest — hex is normalized to base64 before
// encoding, mirroring the TS normalizeInvoiceHash behavior.
type QRData struct {
	// SellerName is tag 1 — the seller (registration) name.
	SellerName string
	// VATNumber is tag 2 — the seller 15-digit VAT registration number.
	VATNumber string
	// Timestamp is tag 3 — ISO 8601 "YYYY-MM-DDThh:mm:ss" (optional "Z").
	Timestamp string
	// TotalWithVAT is tag 4 — the tax-inclusive total (e.g. "115.00").
	TotalWithVAT string
	// VATTotal is tag 5 — the document VAT total (e.g. "15.00").
	VATTotal string
	// InvoiceHash is tag 6 — base64 (or hex) of the invoice hash.
	InvoiceHash string
	// Signature is tag 7 — base64 of the ECDSA signature (text in TLV).
	Signature string
	// PublicKey is tag 8 — raw SPKI DER bytes of the signing public key.
	PublicKey []byte
	// CertificateSignature is tag 9 — raw signatureValue bytes of the
	// signing certificate (extractCertificateSignature semantics).
	CertificateSignature []byte
}

// EncodeTLVBytes encodes one TLV element from raw bytes: a one-byte tag, a
// BER length (short form below 128, long form 0x81 for <256 and 0x82 for
// <65536 — the exact forms the TypeScript reference emits), then the value.
// Values of 65536 bytes or more are rejected, mirroring the TS encoder.
func EncodeTLVBytes(tag byte, value []byte) ([]byte, error) {
	if len(value) >= 1<<16 {
		return nil, fmt.Errorf("zatca: TLV value for tag %d exceeds 65535 bytes (got %d)", tag, len(value))
	}
	out := make([]byte, 0, len(value)+4)
	out = append(out, tag)
	switch {
	case len(value) < 0x80:
		out = append(out, byte(len(value)))
	case len(value) < 0x100:
		out = append(out, 0x81, byte(len(value)))
	default:
		out = append(out, 0x82, byte(len(value)>>8), byte(len(value)))
	}
	return append(out, value...), nil
}

// EncodeTLV encodes one TLV element whose value is the UTF-8 encoding of
// text (tags 1..7 in the ZATCA phase-2 QR).
func EncodeTLV(tag byte, value string) ([]byte, error) {
	return EncodeTLVBytes(tag, []byte(value))
}

// normalizeInvoiceHash mirrors the TS reference: a 64-character hex digest
// is converted to its base64 form (the format ZATCA consumers store);
// anything else must already be valid base64 and is kept verbatim.
func normalizeInvoiceHash(value string) (string, error) {
	if len(value) == 64 && isHex(value) {
		raw, err := hex.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("zatca: invoice hash hex decode: %w", err)
		}
		return base64.StdEncoding.EncodeToString(raw), nil
	}
	if _, err := decodeBase64(value); err != nil {
		return "", fmt.Errorf("zatca: invoice hash must be base64 or 64-char hex: %w", err)
	}
	return value, nil
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// decodeBase64 decodes standard base64, tolerating missing padding the way
// the runtime atob of the TS reference does. It rejects non-alphabet input.
func decodeBase64(value string) ([]byte, error) {
	if value == "" {
		return []byte{}, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

// GeneratePhase2TLV encodes the nine QR fields into the TLV payload, in tag
// order 1..9. All text fields are required and trimmed before encoding; the
// result is byte-identical to the TypeScript generatePhase2TLV for the same
// input (pinned by golden vectors).
func GeneratePhase2TLV(data QRData) ([]byte, error) {
	fields := []struct {
		tag   byte
		value string
		name  string
	}{
		{1, data.SellerName, "seller name"},
		{2, data.VATNumber, "VAT number"},
		{3, data.Timestamp, "timestamp"},
		{4, data.TotalWithVAT, "total with VAT"},
		{5, data.VATTotal, "VAT total"},
	}
	var out []byte
	for _, f := range fields {
		if f.value == "" {
			return nil, fmt.Errorf("zatca: %s is required for the phase-2 QR", f.name)
		}
		encoded, err := EncodeTLV(f.tag, f.value)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	if data.InvoiceHash == "" {
		return nil, fmt.Errorf("zatca: invoice hash is required for the phase-2 QR")
	}
	invoiceHash, err := normalizeInvoiceHash(data.InvoiceHash)
	if err != nil {
		return nil, err
	}
	if encoded, err := EncodeTLV(6, invoiceHash); err != nil {
		return nil, err
	} else {
		out = append(out, encoded...)
	}
	if data.Signature == "" {
		return nil, fmt.Errorf("zatca: signature is required for the phase-2 QR")
	}
	if _, err := decodeBase64(data.Signature); err != nil {
		return nil, fmt.Errorf("zatca: QR signature must be valid base64: %w", err)
	}
	if encoded, err := EncodeTLV(7, data.Signature); err != nil {
		return nil, err
	} else {
		out = append(out, encoded...)
	}
	for _, b := range []struct {
		tag   byte
		value []byte
		name  string
	}{
		{8, data.PublicKey, "public key"},
		{9, data.CertificateSignature, "certificate signature"},
	} {
		if len(b.value) == 0 {
			return nil, fmt.Errorf("zatca: %s is required for the phase-2 QR", b.name)
		}
		encoded, err := EncodeTLVBytes(b.tag, b.value)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	return out, nil
}

// GenerateQRBase64 composes GeneratePhase2TLV with standard base64 — the
// exact string embedded into the invoice XML as the QR payload.
func GenerateQRBase64(data QRData) (string, error) {
	tlv, err := GeneratePhase2TLV(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(tlv), nil
}

// ---------------------------------------------------------------------------
// QR TLV — decode
// ---------------------------------------------------------------------------

// Tag is one decoded TLV element: the one-byte identifier and its value.
type Tag struct {
	ID    byte
	Value []byte
}

// ParseTLV walks a ZATCA QR payload (tag byte, BER short/long length, value)
// and returns the elements in encounter order. It rejects indefinite lengths
// and truncated payloads, mirroring the TS parseZatcaQrTlv error surface.
func ParseTLV(payload []byte) ([]Tag, error) {
	var tags []Tag
	off := 0
	for off < len(payload) {
		tag := payload[off]
		off++
		if off >= len(payload) {
			return nil, fmt.Errorf("zatca: QR TLV truncated length (tag %d)", tag)
		}
		length := int(payload[off])
		off++
		if length&0x80 != 0 {
			count := length & 0x7f
			if count == 0 {
				return nil, fmt.Errorf("zatca: QR TLV indefinite length is unsupported (tag %d)", tag)
			}
			if off+count > len(payload) {
				return nil, fmt.Errorf("zatca: QR TLV truncated long-form length (tag %d)", tag)
			}
			length = 0
			for i := 0; i < count; i++ {
				length = length<<8 | int(payload[off+i])
			}
			off += count
		}
		if off+length > len(payload) {
			return nil, fmt.Errorf("zatca: QR TLV value overruns the QR payload (tag %d)", tag)
		}
		value := make([]byte, length)
		copy(value, payload[off:off+length])
		tags = append(tags, Tag{ID: tag, Value: value})
		off += length
	}
	return tags, nil
}

// AssertTags1To9 requires the decoded tag set to be exactly 1..9 — the
// ZATCA phase-2 QR shape check.
func AssertTags1To9(tags []Tag) error {
	if len(tags) != 9 {
		return fmt.Errorf("zatca: QR must contain exactly TLV tags 1..9 (found %d tags)", len(tags))
	}
	for i, tag := range tags {
		if tag.ID != byte(i+1) {
			return fmt.Errorf("zatca: QR must contain exactly TLV tags 1..9 (found tag %d at position %d)", tag.ID, i)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Invoice hash — SHA-256 over the canonical XML
// ---------------------------------------------------------------------------

// InvoiceHash is the SHA-256 digest of the canonical invoice XML in both
// digest encodings: Hex for auditing and Base64 for the QR tag 6 / PIH.
type InvoiceHash struct {
	Hex    string
	Base64 string
}

// HashCanonical computes the ZATCA invoice hash: SHA-256 over the canonical
// XML string (UTF-8 bytes). The canonicalization itself (removal of
// UBLExtensions / cac:Signature / the QR reference, XML C14N) is owned by
// the TS pipeline — callers pass its `canonical` output here.
func HashCanonical(canonical string) InvoiceHash {
	sum := sha256.Sum256([]byte(canonical))
	return InvoiceHash{
		Hex:    hex.EncodeToString(sum[:]),
		Base64: base64.StdEncoding.EncodeToString(sum[:]),
	}
}

// HashChainNext computes the next invoice hash in the chain. The preimage is
// the canonical XML ALONE — the previous invoice hash (PIH) is carried
// INSIDE the document and never enters the digest (BR-KSA-26 chain rule).
// The first link uses the genesis PIH constant; this function is the Go twin
// of the TS computeNextHash.
func HashChainNext(canonicalXML string) string {
	return HashCanonical(canonicalXML).Base64
}

// ---------------------------------------------------------------------------
// ECDSA — IEEE-P1363 raw r||s (WebCrypto's native form)
// ---------------------------------------------------------------------------

// SignP1363ECDSASHA256 signs the UTF-8 message with the PEM-encoded ECDSA
// P-256 private key (PKCS#8) and returns the IEEE-P1363 raw signature:
// exactly 64 bytes of big-endian r followed by s — the form WebCrypto's
// ECDSA sign produces. The underlying ECDSA signature is randomized per
// call, like every ECDSA implementation.
func SignP1363ECDSASHA256(privateKeyPEM string, message string) ([]byte, error) {
	key, err := PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(message))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("zatca: ECDSA sign: %w", err)
	}
	return derSignatureToP1363(der, key.Curve.Params().BitSize/8)
}

// VerifyP1363ECDSASHA256 verifies an IEEE-P1363 raw signature (r||s, 32
// bytes each for P-256) over the UTF-8 message with the PEM-encoded ECDSA
// public key (SPKI). It is the Go twin of the WebCrypto verify path.
func VerifyP1363ECDSASHA256(publicKeyPEM string, message string, signature []byte) (bool, error) {
	key, err := PublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return false, err
	}
	der, err := p1363SignatureToDER(signature, key.Curve.Params().BitSize/8)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256([]byte(message))
	return ecdsa.VerifyASN1(key, digest[:], der), nil
}

// P1363ToDER converts an IEEE-P1363 raw signature (fixed-width r||s) into
// the ASN.1 DER SEQUENCE { INTEGER r, INTEGER s } form. The half width is
// inferred from the input length — 64 bytes for P-256 or 96 for P-384,
// exactly the widths the TypeScript converter accepts.
func P1363ToDER(signature []byte) ([]byte, error) {
	switch len(signature) {
	case 64:
		return p1363SignatureToDER(signature, 32)
	case 96:
		return p1363SignatureToDER(signature, 48)
	default:
		return nil, fmt.Errorf("zatca: unsupported P1363 length %d (expected 64 for P-256 or 96 for P-384)", len(signature))
	}
}

// DERToP1363 converts an ASN.1 DER ECDSA signature into the IEEE-P1363 raw
// form: each integer left-padded with zeros to halfWidth bytes (32 for
// P-256). It is the inverse of P1363ToDER.
func DERToP1363(derSignature []byte, halfWidth int) ([]byte, error) {
	return derSignatureToP1363(derSignature, halfWidth)
}

type derSignature struct {
	R, S *big.Int
}

// p1363SignatureToDER: fixed-width r||s → minimal-length DER INTEGERs.
// Mirrors the TS convertP1363SignatureToDER byte-for-byte, including the
// 0x00 sign-byte insertion when the high bit is set and the rejection of
// empty/odd-length or wrong-width input.
func p1363SignatureToDER(signature []byte, halfWidth int) ([]byte, error) {
	if halfWidth <= 0 {
		return nil, fmt.Errorf("zatca: unsupported half width %d", halfWidth)
	}
	if len(signature) == 0 || len(signature)%2 != 0 {
		return nil, fmt.Errorf("zatca: P1363 signature must be r||s with equal halves (got %d bytes)", len(signature))
	}
	if len(signature) != halfWidth*2 {
		return nil, fmt.Errorf("zatca: unsupported P1363 length %d (expected %d for this curve)", len(signature), halfWidth*2)
	}
	encoded, err := asn1.Marshal(derSignature{
		R: new(big.Int).SetBytes(signature[:halfWidth]),
		S: new(big.Int).SetBytes(signature[halfWidth:]),
	})
	if err != nil {
		return nil, fmt.Errorf("zatca: DER encode signature: %w", err)
	}
	return encoded, nil
}

// derSignatureToP1363: DER SEQUENCE { INTEGER r, INTEGER s } → fixed-width
// r||s. Rejects non-SEQUENCE input, mirroring the TS convertDerSignatureToP1363.
func derSignatureToP1363(derSignatureBytes []byte, halfWidth int) ([]byte, error) {
	if halfWidth <= 0 {
		return nil, fmt.Errorf("zatca: unsupported half width %d", halfWidth)
	}
	var parsed derSignature
	if rest, err := asn1.Unmarshal(derSignatureBytes, &parsed); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("zatca: invalid DER signature (expected SEQUENCE of two INTEGERs)")
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, fmt.Errorf("zatca: invalid DER signature (nil integer)")
	}
	rBytes := fixedWidthBytes(parsed.R, halfWidth)
	sBytes := fixedWidthBytes(parsed.S, halfWidth)
	return append(rBytes, sBytes...), nil
}

func fixedWidthBytes(value *big.Int, width int) []byte {
	out := make([]byte, width)
	value.FillBytes(out)
	return out
}

// ---------------------------------------------------------------------------
// Keys and certificates
// ---------------------------------------------------------------------------

// PrivateKeyFromPEM parses a PEM-encoded PKCS#8 ECDSA private key.
func PrivateKeyFromPEM(privateKeyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("zatca: no PEM block in private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("zatca: parse PKCS#8 private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("zatca: private key is %T, want ECDSA", parsed)
	}
	return key, nil
}

// PublicKeyFromPEM parses a PEM-encoded SPKI ECDSA public key.
func PublicKeyFromPEM(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("zatca: no PEM block in public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("zatca: parse SPKI public key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("zatca: public key is %T, want ECDSA", parsed)
	}
	return key, nil
}

// ParseCertificatePEM parses a PEM-encoded X.509 certificate (the ZATCA
// device/CSID certificate form: EC P-256). The returned certificate exposes
// Signature — the raw signatureValue bytes that feed QR tag 9 — and
// supports CheckSignatureFrom for self/chain verification.
func ParseCertificatePEM(certificatePEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		return nil, fmt.Errorf("zatca: no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("zatca: parse X.509 certificate: %w", err)
	}
	return cert, nil
}

// CertificateSignatureBase64 returns the certificate's raw signatureValue
// bytes (QR tag 9 source) in base64 — the twin of the TS
// extractZatcaCertificateSignaturePem DER walk.
func CertificateSignatureBase64(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Signature)
}

// SupportedCurves documents the curves covered by the P-1363 helpers today.
// ZATCA device certificates are EC P-256; P-384/P-521 are accepted by the
// generic width-parameterized conversions.
func SupportedCurves() []elliptic.Curve {
	return []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
}
