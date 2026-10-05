// The SDK conformance gate — runs the FULL pipeline when the official ZATCA
// SDK and Java are present; otherwise skips LOUD with install instructions.
//
// Two pipelines are validated:
//   - UNSIGNED (XML-only fixtures): the Z6 document with a clearly-marked
//     placeholder child in ext:ExtensionContent (the UBL 2.1 XSD forbids
//     the empty ExtensionContent the builder emits; canonicalization strips
//     UBLExtensions wholesale so hashes are unaffected). Gate: XSD-clean +
//     schematron findings confined to the documented unsigned-payload
//     classes (QR / cryptographic stamp family).
//   - GO-SIGNED (Z9): the real XAdES/XMLDSig signed payload assembled by
//     packages/zatca-go/signing with the deterministic test key/cert and
//     the Phase-2 QR embedded. Gate: XSD/EN/KSA PASSED with ZERO
//     schematron errors (the executable spec: the TS conformance suite's
//     signed-invoice gates), the QR stage reached, and the SDK's
//     -generateHash equal to the Go canonicalizer's hash of the signed
//     document.
package conformance

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	zatca "github.com/talha7k/zatca-go"
	signing "github.com/talha7k/zatca-go/signing"
	xml "github.com/talha7k/zatca-go/xml"
)

// unsignedPayloadAllowedSchematronCodes — violations EXPECTED on an unsigned
// document (the QR/cryptographic-stamp family; all stamp-related asserts
// inspect ext:UBLExtensions content this library does not assemble yet).
var unsignedPayloadAllowedSchematronCodes = map[string]bool{
	"BR-KSA-27": true, // QR code must exist
	"BR-KSA-28": true, // cryptographic stamp signature-info ID
	"BR-KSA-29": true, // cryptographic stamp referenced signature ID
	"BR-KSA-30": true, // cryptographic stamp signature method
	"BR-KSA-31": true, // cryptographic stamp must exist (simplified)
}

// harness is the shared, discovered environment for the SDK tests.
type harness struct {
	inst     *SdkInstallation
	config   string
	tmpDir   string
	skipNote string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	inst, reason := DiscoverSDK(repoRoot)
	if inst == nil {
		skipLoud(t, "SDK unavailable", reason+
			"\n  Setup: download the Compliance Enablement Toolbox from https://zatca.gov.sa"+
			"\n  (Systems Developers → Compliance Enablement Toolbox), unzip it into the repo root"+
			"\n  (zatca-envoice-sdk-203/ style) or export ZATCA_SDK_HOME=<dir containing Apps/>.")
	}
	if !JavaAvailable() {
		skipLoud(t, "Java unavailable", "java not on PATH — install a JDK (verified on Java 21) to run the SDK conformance harness.")
	}
	tmpDir := t.TempDir()
	config, err := WriteSDKConfig(inst.Home, tmpDir)
	if err != nil {
		t.Fatalf("write SDK_CONFIG: %v", err)
	}
	return &harness{inst: inst, config: config, tmpDir: tmpDir}
}

// skipLoud prints the reason to the test log AND stdout, then skips — the
// skip must be impossible to miss in CI logs.
func skipLoud(t *testing.T, title, reason string) {
	message := "[zatca-sdk-conformance] SKIPPED: " + title + "\n  " + reason
	t.Log(message)
	println(message)
	t.Skipf("%s: %s", title, reason)
}

// extensionPlaceholderPattern — the UNSIGNED builder emits an empty
// <ext:ExtensionContent/>, which the UBL 2.1 XSD rejects (ExtensionContent
// requires one child from a non-UBL-extension namespace). The TS pipeline
// never validates this intermediate: its signing step fills the extension
// with the XMLDSig/XAdES structure (Z9-future here). The harness therefore
// injects a clearly-marked placeholder child — a lax-processed element from
// an unregistered namespace — so the UNSIGNED document is XSD-clean without
// pretending to be signed. Canonicalization strips UBLExtensions wholesale,
// so invoice hashes are unaffected.
var extensionPlaceholderPattern = strings.NewReplacer(
	"<ext:ExtensionContent/>",
	`<ext:ExtensionContent><zgc:UnsignedExtensionContent xmlns:zgc="urn:esellar:zatca-go:unsigned-extension"/></ext:ExtensionContent>`,
)

// withExtensionPlaceholder stamps the unsigned-extension stand-in into the
// document (idempotent: documents without the empty form pass through).
func withExtensionPlaceholder(document string) string {
	return extensionPlaceholderPattern.Replace(document)
}

// writeInvoiceFixture builds the Z6 XML for a standard invoice (mirroring the
// TS conformance fixture shape: KSA-23 additional number, B2B buyer,
// supply date, payment means) into the harness tmp dir. UNSIGNED path: the
// document carries the placeholder extension (see extensionPlaceholderPattern).
func (h *harness) writeInvoiceFixture(t *testing.T, name string, mutate func(*xml.InvoiceData)) string {
	t.Helper()
	document := h.buildConformanceDocument(t, mutate)
	// Z2 signing artifacts: the hash + P-1363 signature over the canonical
	// bytes with the deterministic test key (the QR tag-6/tag-7 pipeline —
	// embedding happens in the Z9 signed pipeline below).
	canonical := stripForHashNote(document)
	hash := xml.HashCanonical(canonical)
	key, err := TestPrivateKeyPKCS8PEM()
	if err != nil {
		t.Fatalf("convert test key: %v", err)
	}
	if _, err := zatca.SignP1363ECDSASHA256(key, hash.Base64); err != nil {
		t.Fatalf("Z2 sign: %v", err)
	}
	path := filepath.Join(h.tmpDir, name)
	if err := os.WriteFile(path, []byte(withExtensionPlaceholder(document)), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// buildConformanceDocument generates the clean Z6 document (no placeholder).
func (h *harness) buildConformanceDocument(t *testing.T, mutate func(*xml.InvoiceData)) string {
	t.Helper()
	counter := 1
	supplyDate := "2026-10-06"
	paymentMeans := 10
	fifteen := 15.0
	inv := &xml.InvoiceData{
		InvoiceNumber:       "CONFORM-0001",
		UUID:                "b16f9d2e-7a34-4c5b-8d6e-9f0a1b2c3d4e",
		IssueDate:           "2026-10-06",
		IssueTime:           "14:30:00",
		InvoiceTypeCode:     "388",
		InvoiceTypeCodeName: "0100000",
		ProfileID:           xml.ProfileIDReporting,
		CurrencyCode:        "SAR",
		InvoiceCounter:      &counter,
		SupplyDate:          &supplyDate,
		PaymentMeansCode:    &paymentMeans,
		PreviousInvoiceHash: xml.GenesisPIH,
		Supplier: xml.SupplierInfo{
			NameAr:    "شركة الاختبار",
			NameEn:    "Test Company",
			VATNumber: "300000000000003",
			CRNumber:  "1010101010",
			Address: xml.PostalAddress{
				Street: "King Fahd Road", Building: "1234", AdditionalNumber: "8008",
				District: "Al Olaya", City: "Riyadh", PostalCode: "12211", CountryCode: "SA",
			},
		},
		Customer: &xml.CustomerInfo{
			Name:      "Test Buyer LLC",
			VATNumber: "310000000000003",
			Address: &xml.PostalAddress{
				Street: "Prince Turki Road", Building: "1111", AdditionalNumber: "2222",
				District:         "Al Malqa",
				CountrySubentity: "Riyadh Region",
				City:             "Riyadh", PostalCode: "13521", CountryCode: "SA",
			},
		},
		LineExtensionAmount: "500.00",
		TaxExclusiveAmount:  "500.00",
		TaxInclusiveAmount:  "575.00",
		PayableAmount:       "575.00",
		TaxAmount:           "75.00",
		TaxSubtotals: []xml.TaxSubtotal{
			{TaxableAmount: "500.00", TaxAmount: "75.00", Percent: fifteen, TaxCategoryID: "S"},
		},
		InvoiceLines: []xml.InvoiceLineItem{
			{ID: 1, Quantity: "2", UnitCode: "PCE", LineExtensionAmount: "500.00", TaxAmount: "75.00",
				ItemName: "Chicken Biryani Family Pack", TaxCategoryID: "S", TaxPercent: fifteen, PriceAmount: "250.00"},
		},
	}
	if mutate != nil {
		mutate(inv)
	}
	document, err := xml.GenerateInvoiceXml(inv)
	if err != nil {
		t.Fatalf("generate invoice XML: %v", err)
	}
	return document
}

// stripForHashNote documents (in code) that canonicalization stays TS-owned:
// the Z2 artifact here is computed over the raw document for pipeline wiring
// only — the BYTE-exact hash parity oracle is the golden fixtures
// (TestGoldenXMLByteParity + the SDK -generateHash check below).
func stripForHashNote(document string) string { return document }

// writeSignedInvoiceFixture builds the SAME conformance invoice and signs it
// through the Z9 signing package (XAdES XMLDSig + embedded Phase-2 QR) with
// the deterministic test key/cert — the GO-SIGNED pipeline the SDK
// validates in TestSDKValidateGoSignedInvoice. The placeholder is NOT
// injected here: signing replaces the whole ext:UBLExtensions block.
func (h *harness) writeSignedInvoiceFixture(t *testing.T, name string) string {
	t.Helper()
	document := h.buildConformanceDocument(t, nil)

	keyPEM, err := TestPrivateKeyPEM()
	if err != nil {
		t.Fatalf("test key PEM: %v", err)
	}
	firstMatch := func(tag string) string {
		re := regexp.MustCompile(`<` + tag + `[^>]*>([^<]+)</` + tag + `>`)
		m := re.FindStringSubmatch(document)
		if m == nil {
			t.Fatalf("document missing <%s>", tag)
		}
		return strings.TrimSpace(m[1])
	}
	signed, err := signing.SignInvoice(signing.SignParams{
		XML:            document,
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: TestCertPEM,
		QRData: &signing.QRSignData{
			// Tag 1 must equal the XML cbc:RegistrationName; tag 3 must equal
			// cbc:IssueDate + 'T' + cbc:IssueTime (the TS conformance QR rules).
			SellerName:   firstMatch("cbc:RegistrationName"),
			VATNumber:    firstMatch("cbc:CompanyID"),
			Timestamp:    firstMatch("cbc:IssueDate") + "T" + strings.TrimSuffix(firstMatch("cbc:IssueTime"), "Z"),
			TotalWithVAT: firstMatch("cbc:TaxInclusiveAmount"),
			VATTotal:     firstMatch("cbc:TaxAmount"),
			// Tag 9 — mirror of the TS conformance fixture: the ZATCA CA's DER
			// ECDSA signature over a REAL CSID cert is unavailable offline
			// (the self-signed test cert's own signature is ~97 TLV bytes and
			// trips BR-CL-KSA-14's 500-char QR limit; the TS conformance
			// substituted this short DER-shaped placeholder for the same
			// reason). A syntactically valid placeholder keeps the TLV shape
			// realistic without pretending to be CA-signed.
			CertificateSignatureBase64: "MAYCASoCASs=",
		},
	})
	if err != nil {
		t.Fatalf("Z9 sign: %v", err)
	}
	path := filepath.Join(h.tmpDir, name)
	if err := os.WriteFile(path, []byte(signed.SignedXML), 0o600); err != nil {
		t.Fatalf("write signed fixture: %v", err)
	}
	return path
}

func TestSDKValidateUnsignedInvoice(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	t.Logf("[zatca-sdk-conformance] SDK %s at %s", h.inst.Version, h.inst.Home)

	invoicePath := h.writeInvoiceFixture(t, "validate-unsigned.xml", nil)
	run, report, err := h.inst.RunValidate(ctx, h.config, invoicePath)
	if err != nil {
		t.Fatalf("SDK -validate failed: %v\nstdout tail: %s", err, tail(run.Stdout, 800))
	}
	logFindings(t, "unsigned-invoice", run, report)

	// The exit-0 trap, pinned: the CLI exits 0 regardless of the verdict.
	if run.Status != 0 {
		t.Fatalf("SDK -validate exited %d — the documented contract is exit 0; the CLI behavior changed", run.Status)
	}
	// Hard gate: XSD must pass with zero structural errors even unsigned.
	if report.StageResults["XSD"] != "PASSED" || len(report.XSDErrors) != 0 {
		t.Fatalf("unsigned invoice must be XSD-clean: %s\nxsd errors: %v", report.Describe(), report.XSDErrors)
	}
	// No FATAL rule violations: schematron findings must be confined to the
	// documented unsigned-payload classes (QR/stamp family).
	var fatal []string
	for _, entry := range report.SchematronErrors {
		code := schematronCode(entry)
		if !unsignedPayloadAllowedSchematronCodes[code] {
			fatal = append(fatal, entry)
		}
	}
	if len(fatal) != 0 {
		t.Errorf("fatal schematron violations on the unsigned document: %v", fatal)
	}
}

// TestSDKValidateGoSignedInvoice — THE Z9 gate: the GO-SIGNED XAdES/XMLDSig
// payload reaches the same validation verdicts the TS-signed documents get
// (the executable spec: tests/conformance/zatca-sdk.test.ts signed gates —
// XSD/EN/KSA PASSED with zero schematron errors; the QR cryptographic stage
// must RUN; SDK 3.0.8's QR layout deviation is documented there and not
// gated). The SDK's -generateHash over the signed output must equal the Go
// canonicalizer's hash — the authority agrees with our C14N on a document
// carrying the full signature structure.
func TestSDKValidateGoSignedInvoice(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	t.Logf("[zatca-sdk-conformance] SDK %s at %s", h.inst.Version, h.inst.Home)

	signedPath := h.writeSignedInvoiceFixture(t, "validate-go-signed.xml")
	signedXML, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatalf("read signed fixture: %v", err)
	}
	run, report, err := h.inst.RunValidate(ctx, h.config, signedPath)
	if err != nil {
		t.Fatalf("SDK -validate failed: %v\nstdout tail: %s", err, tail(run.Stdout, 800))
	}
	logFindings(t, "go-signed-invoice", run, report)

	if run.Status != 0 {
		t.Fatalf("SDK -validate exited %d — the documented contract is exit 0; the CLI behavior changed", run.Status)
	}
	if report.Crashed {
		t.Fatalf("SDK report crashed before validating: %s", report.Describe())
	}
	// Hard gates — identical to the TS-signed verdicts.
	if report.StageResults["XSD"] != "PASSED" || len(report.XSDErrors) != 0 {
		t.Errorf("go-signed invoice XSD: %s\nxsd errors: %v", report.Describe(), report.XSDErrors)
	}
	if report.StageResults["EN"] != "PASSED" {
		t.Errorf("go-signed invoice EN stage: %s", report.Describe())
	}
	if report.StageResults["KSA"] != "PASSED" {
		t.Errorf("go-signed invoice KSA stage: %s", report.Describe())
	}
	// PIH stage (observed on this SDK configuration in place of the TS run's
	// QR stage) — the previous-invoice-hash chain check must pass too.
	if report.StageResults["PIH"] != "PASSED" {
		t.Errorf("go-signed invoice PIH stage: %s", report.Describe())
	}
	if report.Summary != "PASSED" {
		t.Errorf("go-signed invoice GLOBAL result: %s", report.Describe())
	}
	if len(report.SchematronErrors) != 0 {
		t.Errorf("go-signed invoice must carry ZERO schematron errors: %v", report.SchematronErrors)
	}
	// Note (deviation from the TS conformance observation): SDK 3.0.8 in
	// this harness reports stages XSD/EN/KSA/PIH — the separate QR
	// cryptographic stage the TS run observed does not appear here. It is
	// not gated: the decompiled-jar analysis in the TS suite proves that
	// stage contradicts the published QR layout and cannot pass, while the
	// schematron QR/stamp family (BR-KSA-27..31) is covered by KSA=PASSED.

	// The authority's own hash of the signed document must equal the Go
	// canonicalizer's — the strongest C14N parity check (the signed doc
	// carries the signature structure that the SDK's canonicalization must
	// strip identically).
	sdkHash, err := h.inst.ExtractHash(ctx, h.config, signedPath)
	if err != nil {
		t.Fatalf("SDK -generateHash on the signed document: %v", err)
	}
	canonical, err := signing.CanonicalizeForHash(string(signedXML))
	if err != nil {
		t.Fatalf("Go canonicalize signed document: %v", err)
	}
	if sdkHash != canonical.HashBase64 {
		t.Errorf("SDK -generateHash %q != Go canonical hash %q on the signed document", sdkHash, canonical.HashBase64)
	}
}

func TestSDKValidateNegativeControlXSD(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	brokenPath := h.writeInvoiceFixture(t, "negative-xsd.xml", nil)
	raw, err := os.ReadFile(brokenPath)
	if err != nil {
		t.Fatal(err)
	}
	broken := regexp.MustCompile(`<cbc:IssueDate>[^<]*</cbc:IssueDate>`).
		ReplaceAllString(string(raw), "<cbc:IssueDate>NOT-A-DATE</cbc:IssueDate>")
	if err := os.WriteFile(brokenPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	run, report, err := h.inst.RunValidate(ctx, h.config, brokenPath)
	if err != nil {
		t.Fatalf("SDK -validate failed: %v", err)
	}
	logFindings(t, "negative-control/xsd", run, report)

	// The trap, demonstrated: XSD FAILED yet exit status 0.
	if report.StageResults["XSD"] != "FAILED" {
		t.Fatalf("negative control must FAIL XSD, got %s", report.Describe())
	}
	if len(report.XSDErrors) == 0 {
		t.Fatal("negative control must carry parsed XSD errors")
	}
	if !strings.Contains(report.XSDErrors[0], "UBL 2.1") {
		t.Errorf("first XSD error must mention UBL 2.1 standards, got %q", report.XSDErrors[0])
	}
	if run.Status != 0 {
		t.Errorf("negative control exit = %d; the -validate-always-exits-0 trap contract broke", run.Status)
	}
}

func TestSDKGenerateHashParity(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// The TS-frozen golden canonical + hash (standard fixture) — the SDK's
	// -generateHash over the SAME bytes must reproduce the frozen digest.
	canonicalPath := filepath.Join("..", "testdata", "xml", "standard-b2b-vat15.canonical.xml")
	manifestPath := filepath.Join("..", "testdata", "xml", "manifest.json")
	if _, err := os.Stat(canonicalPath); err != nil {
		t.Skipf("golden xml fixtures not present: %v", err)
	}
	frozenHash := frozenManifestHash(t, manifestPath, "standard-b2b-vat15")

	sdkHash, err := h.inst.ExtractHash(ctx, h.config, canonicalPath)
	if err != nil {
		t.Fatalf("SDK -generateHash: %v", err)
	}
	if sdkHash != frozenHash {
		t.Errorf("SDK -generateHash %q != frozen golden hash %q", sdkHash, frozenHash)
	}
}

// frozenManifestHash extracts the frozen invoice_hash_base64 for id from the
// golden xml manifest.
func frozenManifestHash(t *testing.T, manifestPath, id string) string {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	needle := `"id": "` + id + `"`
	text := string(raw)
	idx := strings.Index(text, needle)
	if idx < 0 {
		t.Fatalf("manifest has no fixture %q", id)
	}
	const hashKey = `"invoice_hash_base64": "`
	hashIdx := strings.Index(text[idx:], hashKey)
	if hashIdx < 0 {
		t.Fatalf("fixture %q has no invoice_hash_base64", id)
	}
	rest := text[idx+hashIdx+len(hashKey):]
	end := strings.Index(rest, `"`)
	return rest[:end]
}

func schematronCode(entry string) string {
	if idx := strings.Index(entry, " : "); idx > 0 {
		return entry[:idx]
	}
	return entry
}

func logFindings(t *testing.T, label string, run CLIRun, report ParsedValidationReport) {
	t.Logf("[zatca-sdk-conformance] %s (exit=%d): %s", label, run.Status, report.Describe())
	for _, e := range report.XSDErrors {
		t.Logf("[zatca-sdk-conformance]   xsd  %s", truncate(e, 240))
	}
	for _, e := range report.SchematronErrors {
		t.Logf("[zatca-sdk-conformance]   sch  %s", truncate(e, 240))
	}
	for _, e := range report.OtherErrors {
		t.Logf("[zatca-sdk-conformance]   oth  %s", truncate(e, 240))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
