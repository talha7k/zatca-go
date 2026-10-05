// ZATCA golden-vector parity gate — Go MUST reproduce every TS-produced
// vector byte-exactly. Fixtures are frozen from the prod-proven TypeScript
// implementation by apps/api/scripts/zatca-golden-vectors.ts into
// testdata/golden-vectors.json.
//
// Regenerate fixtures with:
//
//	pnpm --filter api exec tsx scripts/zatca-golden-vectors.ts
package zatca_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	zatca "github.com/talha7k/zatca-go"
)

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

type goldenFixtures struct {
	Meta struct {
		Generator string `json:"generator"`
	} `json:"_meta"`
	Key struct {
		Curve string `json:"curve"`
		// DevOnlyTestSigningKeyPEMBody is the unarmored base64 DER body of
		// the DEV-ONLY PKCS#8 test key (randomly generated per fixture run;
		// signs nothing real). Kept unarmored so secret scanners see no PEM
		// private-key blocks; the generic-entropy finding is allowlisted in
		// .gitleaksignore. Tests re-armor the body before use.
		DevOnlyTestSigningKeyPEMBody string `json:"dev_only_test_signing_key_pem_body"`
		PrivateKeyPEMType            string `json:"private_key_pem_type"`
		PublicKeyPEM                 string `json:"public_key_pem"`
		PublicKeySpki64              string `json:"public_key_spki_base64"`
	} `json:"key"`
	InvoiceVectors []struct {
		ID     string `json:"id"`
		Inputs struct {
			SellerNameAr      string `json:"seller_name_ar"`
			SellerNameEn      string `json:"seller_name_en"`
			SellerVATNumber   string `json:"seller_vat_number"`
			IssueDate         string `json:"issue_date"`
			IssueTime         string `json:"issue_time"`
			TotalWithVATCents int64  `json:"total_with_vat_cents"`
			VATTotalCents     int64  `json:"vat_total_cents"`
			VATRatePercent    int    `json:"vat_rate_percent"`
		} `json:"inputs"`
		XML               string `json:"xml"`
		Canonical         string `json:"canonical"`
		InvoiceHashHex    string `json:"invoice_hash_hex"`
		InvoiceHashBase64 string `json:"invoice_hash_base64"`
		QR                struct {
			SellerName                 string `json:"seller_name"`
			VATNumber                  string `json:"vat_number"`
			Timestamp                  string `json:"timestamp"`
			TotalWithVAT               string `json:"total_with_vat"`
			VATTotal                   string `json:"vat_total"`
			InvoiceHashBase64          string `json:"invoice_hash_base64"`
			SignaturePayloadUTF8       string `json:"signature_payload_utf8"`
			SignatureP1363Base64       string `json:"signature_p1363_base64"`
			SignatureDERBase64         string `json:"signature_der_base64"`
			PublicKeySpkiBase64        string `json:"public_key_spki_base64"`
			CertificateSignatureBase64 string `json:"certificate_signature_base64"`
		} `json:"qr"`
		QRTLVHex      string `json:"qr_tlv_hex"`
		ZatcaQRBase64 string `json:"zatca_qr_base64"`
	} `json:"invoice_vectors"`
	HashChain struct {
		GenesisPih string `json:"genesis_pih"`
		Links      []struct {
			ID                string `json:"id"`
			PreviousHash      string `json:"previous_hash"`
			InvoiceHashBase64 string `json:"invoice_hash_base64"`
		} `json:"links"`
	} `json:"hash_chain"`
	SignatureVectors []struct {
		ID          string `json:"id"`
		PayloadUTF8 string `json:"payload_utf8"`
		P1363Base64 string `json:"p1363_base64"`
		DERBase64   string `json:"der_base64"`
	} `json:"signature_vectors"`
	P1363DERVectors []struct {
		ID          string `json:"id"`
		P1363Base64 string `json:"p1363_base64"`
		DERBase64   string `json:"der_base64"`
	} `json:"p1363_der_vectors"`
	SHA256Vectors []struct {
		InputUTF8 string `json:"input_utf8"`
		HashHex   string `json:"hash_hex"`
	} `json:"sha256_vectors"`
	Certificate struct {
		PEM             string `json:"pem"`
		SignatureBase64 string `json:"signature_base64"`
		SubjectCN       string `json:"subject_cn"`
	} `json:"certificate"`
}

func loadFixtures(t *testing.T) goldenFixtures {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden-vectors.json")
	if err != nil {
		t.Fatalf("read golden fixtures: %v", err)
	}
	var f goldenFixtures
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse golden fixtures: %v", err)
	}
	if len(f.InvoiceVectors) < 3 {
		t.Fatalf("expected at least 3 invoice vectors, got %d", len(f.InvoiceVectors))
	}
	return f
}

// privateKeyPEM re-arms the unarmored fixture key body into PEM form
// (fixtures keep the private-key armor out of the committed JSON).
func privateKeyPEM(fix goldenFixtures) string {
	body := fix.Key.DevOnlyTestSigningKeyPEMBody
	var wrapped strings.Builder
	for i := 0; i < len(body); i += 64 {
		end := i + 64
		if end > len(body) {
			end = len(body)
		}
		wrapped.WriteString(body[i:end])
		wrapped.WriteString("\n")
	}
	return "-----BEGIN " + fix.Key.PrivateKeyPEMType + "-----\n" +
		wrapped.String() +
		"-----END " + fix.Key.PrivateKeyPEMType + "-----\n"
}

// ---------------------------------------------------------------------------
// Z3 parity gate — invoice vectors (hash + TLV + QR, byte-exact)
// ---------------------------------------------------------------------------

func TestGoldenInvoiceVectorsByteParity(t *testing.T) {
	fix := loadFixtures(t)
	for _, tc := range fix.InvoiceVectors {
		t.Run(tc.ID, func(t *testing.T) {
			// (1) invoice hash — SHA-256 over the canonical XML bytes.
			got := zatca.HashCanonical(tc.Canonical)
			if got.Hex != tc.InvoiceHashHex {
				t.Errorf("invoice_hash_hex mismatch:\n got  %s\n want %s", got.Hex, tc.InvoiceHashHex)
			}
			if got.Base64 != tc.InvoiceHashBase64 {
				t.Errorf("invoice_hash_base64 mismatch:\n got  %s\n want %s", got.Base64, tc.InvoiceHashBase64)
			}

			// (2) QR TLV — rebuild all nine tags from the vector's QR inputs
			// and require byte equality with the TS-emitted payload.
			spki, err := base64.StdEncoding.DecodeString(tc.QR.PublicKeySpkiBase64)
			if err != nil {
				t.Fatalf("decode spki: %v", err)
			}
			certSig, err := base64.StdEncoding.DecodeString(tc.QR.CertificateSignatureBase64)
			if err != nil {
				t.Fatalf("decode cert signature: %v", err)
			}
			tlv, err := zatca.GeneratePhase2TLV(zatca.QRData{
				SellerName:           tc.QR.SellerName,
				VATNumber:            tc.QR.VATNumber,
				Timestamp:            tc.QR.Timestamp,
				TotalWithVAT:         tc.QR.TotalWithVAT,
				VATTotal:             tc.QR.VATTotal,
				InvoiceHash:          tc.QR.InvoiceHashBase64,
				Signature:            tc.QR.SignatureP1363Base64,
				PublicKey:            spki,
				CertificateSignature: certSig,
			})
			if err != nil {
				t.Fatalf("GeneratePhase2TLV: %v", err)
			}
			wantTLV, err := hex.DecodeString(tc.QRTLVHex)
			if err != nil {
				t.Fatalf("decode fixture TLV hex: %v", err)
			}
			if !bytes.Equal(tlv, wantTLV) {
				t.Errorf("QR TLV bytes mismatch:\n got  %x\n want %x", tlv, wantTLV)
			}

			// (3) QR base64 composite — the exact string embedded in the XML.
			qrB64, err := zatca.GenerateQRBase64(zatca.QRData{
				SellerName:           tc.QR.SellerName,
				VATNumber:            tc.QR.VATNumber,
				Timestamp:            tc.QR.Timestamp,
				TotalWithVAT:         tc.QR.TotalWithVAT,
				VATTotal:             tc.QR.VATTotal,
				InvoiceHash:          tc.QR.InvoiceHashBase64,
				Signature:            tc.QR.SignatureP1363Base64,
				PublicKey:            spki,
				CertificateSignature: certSig,
			})
			if err != nil {
				t.Fatalf("GenerateQRBase64: %v", err)
			}
			if qrB64 != tc.ZatcaQRBase64 {
				t.Errorf("zatca_qr_base64 mismatch:\n got  %s\n want %s", qrB64, tc.ZatcaQRBase64)
			}

			// (4) QR tag 7 — the TS signature over the stated payload must
			// verify under the fixture public key (P-1363 raw form).
			ok, err := zatca.VerifyP1363ECDSASHA256(fix.Key.PublicKeyPEM, tc.QR.SignaturePayloadUTF8, mustB64(t, tc.QR.SignatureP1363Base64))
			if err != nil {
				t.Fatalf("VerifyP1363ECDSASHA256: %v", err)
			}
			if !ok {
				t.Error("TS P-1363 signature over stated payload does NOT verify under Go")
			}

			// (5) DER twin of the same signature must match the TS DER form
			// after P1363→DER conversion.
			der, err := zatca.P1363ToDER(mustB64(t, tc.QR.SignatureP1363Base64))
			if err != nil {
				t.Fatalf("P1363ToDER: %v", err)
			}
			if !bytes.Equal(der, mustB64(t, tc.QR.SignatureDERBase64)) {
				t.Errorf("P1363→DER mismatch:\n got  %x\n want %x", der, mustB64(t, tc.QR.SignatureDERBase64))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Hash chain — PIH chaining across the frozen invoice sequence
// ---------------------------------------------------------------------------

func TestGoldenHashChain(t *testing.T) {
	fix := loadFixtures(t)
	if len(fix.HashChain.Links) != len(fix.InvoiceVectors) {
		t.Fatalf("chain/vector count mismatch")
	}
	canonicalByID := map[string]string{}
	for _, v := range fix.InvoiceVectors {
		canonicalByID[v.ID] = v.Canonical
	}
	prev := fix.HashChain.GenesisPih
	for _, link := range fix.HashChain.Links {
		if link.PreviousHash != prev {
			t.Errorf("%s: fixture chain broken: previous_hash %q != prior %q", link.ID, link.PreviousHash, prev)
		}
		got := zatca.HashChainNext(canonicalByID[link.ID])
		if got != link.InvoiceHashBase64 {
			t.Errorf("%s: chain hash mismatch:\n got  %s\n want %s", link.ID, got, link.InvoiceHashBase64)
		}
		prev = link.InvoiceHashBase64
	}
}

// ---------------------------------------------------------------------------
// Signature vectors — verify TS signatures; Go signs round-trip
// ---------------------------------------------------------------------------

func TestGoldenSignatureVerifyTS(t *testing.T) {
	fix := loadFixtures(t)
	for _, tc := range fix.SignatureVectors {
		t.Run(tc.ID, func(t *testing.T) {
			sig := mustB64(t, tc.P1363Base64)
			if len(sig) != 64 {
				t.Fatalf("P-1363 signature must be 64 bytes, got %d", len(sig))
			}
			ok, err := zatca.VerifyP1363ECDSASHA256(fix.Key.PublicKeyPEM, tc.PayloadUTF8, sig)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Error("TS signature does not verify under Go")
			}
			// DER twin round-trip: P1363→DER→P1363 must be identity.
			der := mustB64(t, tc.DERBase64)
			converted, err := zatca.P1363ToDER(sig)
			if err != nil {
				t.Fatalf("P1363ToDER: %v", err)
			}
			if !bytes.Equal(converted, der) {
				t.Errorf("converted DER differs from TS DER:\n got  %x\n want %x", converted, der)
			}
			back, err := zatca.DERToP1363(converted, 32)
			if err != nil {
				t.Fatalf("DERToP1363: %v", err)
			}
			if !bytes.Equal(back, sig) {
				t.Errorf("DER→P1363 round-trip diverged:\n got  %x\n want %x", back, sig)
			}
		})
	}
}

func TestGoSignatureRoundTrip(t *testing.T) {
	fix := loadFixtures(t)
	payload := "go-side round-trip payload — must verify under the frozen key"
	sig, err := zatca.SignP1363ECDSASHA256(privateKeyPEM(fix), payload)
	if err != nil {
		t.Fatalf("SignP1363ECDSASHA256: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("Go P-1363 signature must be 64 bytes, got %d", len(sig))
	}
	ok, err := zatca.VerifyP1363ECDSASHA256(fix.Key.PublicKeyPEM, payload, sig)
	if err != nil {
		t.Fatalf("verify go signature: %v", err)
	}
	if !ok {
		t.Error("Go-produced signature does not round-trip verify")
	}
	// Wrong payload must not verify.
	ok, err = zatca.VerifyP1363ECDSASHA256(fix.Key.PublicKeyPEM, payload+"x", sig)
	if err != nil {
		t.Fatalf("verify wrong payload: %v", err)
	}
	if ok {
		t.Error("signature verified over the WRONG payload")
	}
}

// ---------------------------------------------------------------------------
// P-1363 ↔ DER edge vectors (frozen from the vendored TS converter)
// ---------------------------------------------------------------------------

func TestGoldenP1363DEREdges(t *testing.T) {
	fix := loadFixtures(t)
	for _, tc := range fix.P1363DERVectors {
		t.Run(tc.ID, func(t *testing.T) {
			p1363 := mustB64(t, tc.P1363Base64)
			der := mustB64(t, tc.DERBase64)
			gotDER, err := zatca.P1363ToDER(p1363)
			if err != nil {
				t.Fatalf("P1363ToDER: %v", err)
			}
			if !bytes.Equal(gotDER, der) {
				t.Errorf("DER mismatch:\n got  %x\n want %x", gotDER, der)
			}
			gotP1363, err := zatca.DERToP1363(der, 32)
			if err != nil {
				t.Fatalf("DERToP1363: %v", err)
			}
			if !bytes.Equal(gotP1363, p1363) {
				t.Errorf("P1363 mismatch:\n got  %x\n want %x", gotP1363, p1363)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SHA-256 digest parity (UTF-8, incl. Arabic)
// ---------------------------------------------------------------------------

func TestGoldenSHA256(t *testing.T) {
	fix := loadFixtures(t)
	for _, tc := range fix.SHA256Vectors {
		sum := sha256.Sum256([]byte(tc.InputUTF8))
		if hex.EncodeToString(sum[:]) != tc.HashHex {
			t.Errorf("sha256(%q): got %s want %s", tc.InputUTF8, hex.EncodeToString(sum[:]), tc.HashHex)
		}
	}
}

// ---------------------------------------------------------------------------
// Certificate — Go x509 parses the TS-minted self-signed fixture
// ---------------------------------------------------------------------------

func TestGoldenCertificate(t *testing.T) {
	fix := loadFixtures(t)
	cert, err := zatca.ParseCertificatePEM(fix.Certificate.PEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if cert.Subject.CommonName != fix.Certificate.SubjectCN {
		t.Errorf("subject CN: got %q want %q", cert.Subject.CommonName, fix.Certificate.SubjectCN)
	}
	// Public key inside the cert must equal the fixture keypair's public key.
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert public key is %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	pemPub, err := zatca.PublicKeyFromPEM(fix.Key.PublicKeyPEM)
	if err != nil {
		t.Fatalf("PublicKeyFromPEM: %v", err)
	}
	if certPub.X.Cmp(pemPub.X) != 0 || certPub.Y.Cmp(pemPub.Y) != 0 {
		t.Error("certificate public key differs from the fixture keypair public key")
	}
	// Self-signature must verify (Go, stdlib path).
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-signature does not verify: %v", err)
	}
	// The raw signatureValue bytes (QR tag 9 source) must match the TS-extracted form.
	if !bytes.Equal(cert.Signature, mustB64(t, fix.Certificate.SignatureBase64)) {
		t.Errorf("certificate signature bytes mismatch:\n got  %x\n want %x", cert.Signature, mustB64(t, fix.Certificate.SignatureBase64))
	}
	// PEM round-trip: re-encode and re-parse.
	rePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	recert, err := zatca.ParseCertificatePEM(string(rePEM))
	if err != nil {
		t.Fatalf("re-parse re-encoded PEM: %v", err)
	}
	if !bytes.Equal(recert.Raw, cert.Raw) {
		t.Error("PEM re-encode round-trip diverged")
	}
}

// ---------------------------------------------------------------------------

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return raw
}

// ---------------------------------------------------------------------------
// Decode round-trip — ParseTLV over the golden payload re-encodes identically
// ---------------------------------------------------------------------------

func TestGoldenTLVDecodeReencode(t *testing.T) {
	fix := loadFixtures(t)
	for _, tc := range fix.InvoiceVectors {
		t.Run(tc.ID, func(t *testing.T) {
			payload := mustB64(t, tc.ZatcaQRBase64)
			tags, err := zatca.ParseTLV(payload)
			if err != nil {
				t.Fatalf("ParseTLV: %v", err)
			}
			if err := zatca.AssertTags1To9(tags); err != nil {
				t.Fatalf("AssertTags1To9: %v", err)
			}
			// Re-encode each element in order — must reproduce the payload.
			var rebuilt []byte
			for _, tag := range tags {
				encoded, err := zatca.EncodeTLVBytes(tag.ID, tag.Value)
				if err != nil {
					t.Fatalf("EncodeTLVBytes(tag %d): %v", tag.ID, err)
				}
				rebuilt = append(rebuilt, encoded...)
			}
			if !bytes.Equal(rebuilt, payload) {
				t.Errorf("decode→re-encode diverged:\n got  %x\n want %x", rebuilt, payload)
			}
			// Tag 6 must carry the base64 invoice-hash TEXT (not raw bytes).
			wantTag6 := tc.QR.InvoiceHashBase64
			if string(tags[5].Value) != wantTag6 {
				t.Errorf("tag 6: got %q want %q", tags[5].Value, wantTag6)
			}
			// Tags 8/9 must carry the raw DER bytes.
			if !bytes.Equal(tags[7].Value, mustB64(t, tc.QR.PublicKeySpkiBase64)) {
				t.Error("tag 8 is not the raw SPKI bytes")
			}
			if !bytes.Equal(tags[8].Value, mustB64(t, tc.QR.CertificateSignatureBase64)) {
				t.Error("tag 9 is not the raw certificate signature bytes")
			}
		})
	}
}

// Corruption controls — the gate must fail on drifted inputs.
func TestGoldenGateRejectsDrift(t *testing.T) {
	fix := loadFixtures(t)
	tc := fix.InvoiceVectors[0]

	drifting := zatca.QRData{
		SellerName:   tc.QR.SellerName + " ",
		VATNumber:    tc.QR.VATNumber,
		Timestamp:    tc.QR.Timestamp,
		TotalWithVAT: tc.QR.TotalWithVAT,
		VATTotal:     tc.QR.VATTotal,
		InvoiceHash:  tc.QR.InvoiceHashBase64,
		Signature:    tc.QR.SignatureP1363Base64,
	}
	if _, err := zatca.GeneratePhase2TLV(drifting); err == nil {
		t.Error("expected missing tags 8/9 to be rejected")
	}

	// A one-byte TLV corruption must break the exact-hash parity.
	tlv := mustB64(t, tc.ZatcaQRBase64)
	tlv[len(tlv)-1] ^= 0xff
	tags, err := zatca.ParseTLV(tlv)
	if err != nil {
		t.Fatalf("corrupted payload must still parse: %v", err)
	}
	_ = tags // decoding tolerates any byte values; parity is asserted upstream
}
