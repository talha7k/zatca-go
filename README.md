# zatca-go

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](./LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/talha7k/zatca-go.svg)](https://pkg.go.dev/github.com/talha7k/zatca-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/talha7k/zatca-go)](https://goreportcard.com/report/github.com/talha7k/zatca-go)

**ZATCA phase-2 (Fatoora, Saudi e-invoicing) SDK for Go** — QR TLV, invoice
hashing, XAdES-signed UBL XML, the Fatoora gateway client and BR-KSA
validation, in one dependency-free (stdlib-only) module. A byte-exact port of
a production-proven TypeScript stack (`@talha7k/zatca-qr` TLV + WebCrypto
ECDSA) extracted from a live e-invoicing platform: every exported value is
pinned against golden vectors generated from that implementation, and the
generated invoices are validated by the official ZATCA E-Invoicing SDK.

## Quick start — Phase-1 QR in 10 lines

```sh
go get github.com/talha7k/zatca-go
```

```go
package main

import (
	"fmt"

	zatca "github.com/talha7k/zatca-go"
)

func main() {
	qr, err := zatca.GenerateQRBase64(zatca.QRData{ // tags 1..5 (phase 1)
		SellerName:   "My Company LLC",
		VATNumber:    "310122393500003",
		Timestamp:    "2026-10-01T14:30:00",
		TotalWithVAT: "115.00",
		VATTotal:     "15.00",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(qr) // base64 TLV — embed in the invoice's QR element
}
```

Phase-2 adds tags 6..9 (`InvoiceHash`, `Signature`, `PublicKey`,
`CertificateSignature`) plus UBL XML generation (`xml`), XAdES signing
(`signing`) and clearance/reporting submission (`authority`) — see the
capability table and the subpackage sections below.

## What it covers

| Capability | API |
|---|---|
| QR TLV encode (tags 1..9, BER short/long lengths) | `GeneratePhase2TLV`, `GenerateQRBase64`, `EncodeTLV`, `EncodeTLVBytes` |
| QR TLV decode + exact-tags-1..9 shape check | `ParseTLV`, `AssertTags1To9` |
| Invoice hash (SHA-256 over canonical XML) | `HashCanonical`, `HashChainNext` |
| ECDSA P-256 sign/verify, IEEE-P1363 raw r‖s form | `SignP1363ECDSASHA256`, `VerifyP1363ECDSASHA256` |
| P-1363 ↔ ASN.1 DER signature conversion | `P1363ToDER`, `DERToP1363` |
| X.509 certificate parse (PEM), tag-9 bytes | `ParseCertificatePEM`, `CertificateSignatureBase64`, `PublicKeyFromPEM`, `PrivateKeyFromPEM` |
| UBL 2.1 XML generation (`xml`) — standard/simplified invoices, credit & debit notes | `xml.GenerateInvoiceXml`, `xml.GenerateCreditNoteXml`, `xml.GenerateDebitNoteXml` |
| Order→invoice mapping discipline (`xml`) — inclusive-VAT integer cents, address normalization, issue-date clamp | `xml.VATFromInclusiveCents`, `xml.TaxFromTaxableCents`, `xml.NormalizeBuildingNumber`, `xml.NormalizePostalCode`, `xml.IssueDateNotAfterToday` |
| ICV/PIH hash-chain + production patches (`xml`) | `xml.PatchInvoiceChainReferences`, `xml.PatchProductionXML`, `xml.PatchStandardInvoiceSupplyDate`, `xml.PatchBusinessProcessProfile` |
| BR-KSA validation suite (`validate`) — structured faults: rule id, severity, message, path | `validate.Invoice`, `validate.CreditNote`, `validate.RuleIDs` |
| XAdES/XMLDSig signed payload (`signing`) — canonicalization, digest, ECDSA-SHA256 (DER) signature, envelope assembly, QR embedding | `signing.SignInvoice`, `signing.CanonicalizeForHash`, `signing.VerifySignature`, `signing.AssembleSignedXML` |
| Official-SDK conformance harness (`conformance`, test-only) | SDK discovery, `SDK_CONFIG` bootstrap, report parser, skip-loud gates |
| Fatoora gateway client (authority) | `authority.Client` — see below |

## Signed payload (`signing` subpackage)

The `zatca_cleared_xml_payload` path — an enveloped XAdES/XMLDSig signature
spliced into the invoice's `ext:UBLExtensions` block plus the embedded
Phase-2 QR. A byte-exact port of `@talha7k/zatca/dist/signing` (sign.js +
shared.js) including its canonicalization engine:

```go
result, err := signing.SignInvoice(signing.SignParams{
	XML:            unsignedInvoiceXML, // with ext:UBLExtensions placeholder
	PrivateKeyPEM:  csidPrivateKeyPEM,
	CertificatePEM: csidCertificatePEM,
	QRData: &signing.QRSignData{ // tags 1..5 + 9 from document context
		SellerName: registrationName, VATNumber: vatNumber,
		Timestamp: issueDate + "T" + issueTime,
		TotalWithVAT: payableAmount, VATTotal: vatAmount,
		CertificateSignatureBase64: certSignatureB64,
	},
})
// result.SignedXML — the signed payload; result.InvoiceHash — QR tag 6 / PIH;
// result.SignatureValue — the DER ECDSA signature (base64).
```

### Canonicalization scope

Go has no C14N in stdlib, so `signing` carries a focused **inclusive-C14N
port of the exact engine the TS pipeline drives**
(xmldsigjs `XmlCanonicalizer(withComments=false, excC14N=false)` — the
quirks included: prefixed attributes auto-render their namespace,
`xmlns=""` always renders, namespace/attribute sort orders, the attribute
escaping table where `>` is escaped in text but NOT in attribute values).
Deliberately out of scope (unreachable from this pipeline, documented in
`signing/canonicalize.go`): exclusive C14N / InclusiveNamespaces PrefixList,
comment preservation, DOCTYPE subsets, Unicode NFC re-normalization.

`signing.CanonicalizeForHash` additionally applies the ZATCA exclusion
transforms (strip `ext:UBLExtensions`, `cac:Signature`, and the
`cbc:ID='QR'` AdditionalDocumentReference) before canonicalizing — the
invoice-hash preimage. Byte parity is pinned two ways: every Z6 golden
fixture's TS-frozen `.canonical.xml` is reproduced byte-exactly, and the
official SDK's `-generateHash` over a GO-SIGNED document equals the Go
canonical hash (see below).

### TS quirks mirrored (quirks-for-quirks — the validator hashes these bytes)

- **DigestValues are double-encoded**: `base64(hex(sha256(...)))` — base64
  OF the hex digest TEXT, for both the XAdES CertDigest and the
  SignedProperties reference. (The invoice reference DigestValue is normal
  base64 of raw digest bytes.)
- **Signing time has no milliseconds and no `Z`** —
  `formatSigningTime` → `"2026-10-06T14:30:00"`; each stabilization pass
  re-stamps the time (mirrored: `SignParams.SigningTime` pins it).
- **SignatureValue is ASN.1 DER** ECDSA-SHA256 (not the raw P-1363 form the
  QR tag-7/TLV layer uses elsewhere in this library).
- **The certificate info issuer string** reproduces Node's
  `X509Certificate.issuer` (OpenSSL short names, one RDN per line in cert
  order) transformed by the TS pipeline's
  `split('\n').reverse().join(', ')`.
- **The stabilization second pass**: the signed document is re-hashed and
  rebuilt once when the hash moved (it normally does not — the signature
  blocks are all stripped before hashing).
- **XAdES element order/attributes are exact**: SignedInfo (exclusion
  transforms, two references), KeyInfo with the DER cert, `ds:Object` →
  `QualifyingProperties` → `SignedProperties` (with the namespace-stripped
  open tag) — ZATCA's validator is strict.

### Parity & authority conformance

`testdata/signing/` freezes, for all 5 invoice types: the TS-SIGNED XML
(deterministic static test key/cert, pinned signing time) plus the parsed
structure (canonical SignedInfo, both digest values, DER signature, QR
inputs). The Go suite requires: canonical SignedInfo bytes equal,
SignedProperties digest equal, certificate info equal, the frozen TS
signature verifying over the frozen canonical SignedInfo, the **full signed
XML reproduced byte-exactly** when Go rebuilds with the frozen signature,
and a fresh randomized Go signature round-trip verifies with a well-formed
document and stable canonical hash. The fixtures are generated by the
TypeScript reference implementation's golden-vector generator and frozen
in-tree (see [Parity vs TypeScript](#parity-vs-typescript)).

Ultimate gate — the official SDK validates the GO-SIGNED document:

```
[zatca-sdk-conformance] go-signed-invoice (exit=0):
  stages=[XSD=PASSED EN=PASSED KSA=PASSED PIH=PASSED]
  xsd=0 schematron=0 warnings=0 global=PASSED crashed=false
```

zero schematron errors (the TS conformance suite's signed gates, mirrored in
`conformance`), plus `-generateHash` cross-check on the signed output.

## XML generation (`xml` subpackage)

A byte-exact Go port of `@talha7k/zatca`'s template-literal UBL 2.1 builders
(`dist/xml/{invoice,fragments,credit-note}.js`) plus the pure order→invoice
mapping discipline of the production TypeScript pipeline:

- **Decimal money is lexical, never float** — amounts (BT-131/106/109/116…)
  format to exactly 2 fraction digits with exact scaled-integer arithmetic
  (HALF-UP away from zero: `"2.675"` → `"2.68"`); unit prices/quantities
  (BT-146/129) carry up to 10 digits per BR-KSA-EN16931-11. `Decimal` is a
  canonical xs:decimal string type.
- **Inclusive-VAT integer cents** — `VATFromInclusiveCents` derives
  `taxableCents = round(grossCents × 100/(100+rate))` then
  `taxCents = round(taxableCents × rate/100)`: the TAXABLE base is the
  anchor (BR-CO-17), never the charged gross.
- **Chain patching** — `PatchInvoiceChainReferences` rewrites ICV (KSA-16)
  and PIH (KSA-13) references into a minted document (genesis PIH fallback);
  `PatchProductionXML` applies the reporting:1.0 profile + KSA-5 supply-date
  patches.
- **Parity** — `testdata/xml/` freezes UNSIGNED fixtures (standard B2B,
  simplified, zero-rated, Arabic lines, simplified credit note) built by the
  TS generators; `xml/xml_test.go` requires byte-identical XML from the Go
  builders for every fixture, plus canonical-hash parity. Fixtures are frozen
  in-tree; see [Parity vs TypeScript](#parity-vs-typescript) for their
  provenance.

## BR-KSA validation (`validate` subpackage)

33 rules over the `xml.InvoiceData` model — the supported document types
(standard 0100000, simplified 0200000, credit/debit notes). Rules are
translated from the authoritative schematron shipped in the ZATCA SDK
(`20210819_ZATCA_E-invoice_Validation_Rules.xsl`: rule ids, assert text and
flag→severity extracted verbatim — BR-KSA-09 is the one warning), with
`github.com/invopop/gobl.sa.zatca` used as a structure reference only (never
imported). The EN 16931 core-consistency block (BR-CO-10/13/15/17/18,
BR-S-08) mirrors the TS production-readiness gate, including the BT-117
1-minor-unit tolerance. Faults are structured:

```go
faults := validate.Invoice(inv, validate.WithNow(nowFn))
// []validate.Fault{{RuleID: "BR-KSA-15", Severity: "error",
//   Path: "supplyDate", Message: "…"}, …}
```

## Official-SDK conformance (`conformance` subpackage — TEST-ONLY)

Validates this library's invoice XML against the OFFICIAL ZATCA E-Invoicing
Java SDK. The mechanics are ported from the TS harness (talha7k/zatca
tests/conformance) — never its test code:

- **Discovery** — `ZATCA_SDK_HOME` (must contain `Apps/`), then
  `zatca-*sdk*` directories in the repo root. Java 21 checked on PATH.
- **SDK_CONFIG bootstrap** — the SDK reads `SDK_CONFIG` env with NO
  fallback; the shipped config uses Windows paths, so the harness writes a
  config with absolute paths into a temp dir per run (never committed).
- **The exit-0 trap** — `-validate` ALWAYS exits 0, even on global FAILED
  (pinned by a live negative control). Gates parse the report
  (`ParseValidationReport`, the reverse-engineered SDK 3.0.8 format), never
  the exit code.
- **Deterministic fixtures** — the static TEST_CERT/TEST_PRIVATE_KEY pair,
  the key stored unarmored (gitleaks discipline) and re-armed at runtime.
- **Unsigned path (XML-only fixtures, flag retained)** — the UBL 2.1 XSD
  forbids the empty `ext:ExtensionContent` the builder emits (the TS
  pipeline never validates this intermediate — its signing step fills the
  extension), so unsigned documents carry a clearly-marked placeholder
  child. Gate: XSD PASSED + schematron findings confined to the documented
  QR/cryptographic-stamp family, `-generateHash` parity against the frozen
  golden hash, and the exit-0-trap negative control.
- **GO-SIGNED path (Z9)** — the real XAdES/XMLDSig payload from the
  `signing` package. Gate: XSD/EN/KSA/PIH PASSED with ZERO schematron
  errors and GLOBAL PASSED, plus SDK `-generateHash` == Go canonical hash
  on the signed document. (Observed stages on SDK 3.0.8 in this harness:
  XSD/EN/KSA/PIH; the separate QR cryptographic stage the TS run observed
  does not appear — it is not gated, see the decompiled-jar deviation note
  in the TS suite; the schematron QR/stamp family BR-KSA-27..31 is covered
  by KSA=PASSED.)

**The 160MB SDK jar is NEVER committed.** Download the Compliance &
Enablement Toolbox from <https://zatca.gov.sa> (Systems Developers →
Compliance Enablement Toolbox) after accepting the terms, unzip it into the
repo root (`zatca-envoice-sdk-203/` style) or point `ZATCA_SDK_HOME` at it,
then:

```sh
ZATCA_SDK_HOME=/path/to/zatca-envoice-sdk-203 go test ./conformance/
```

Without the SDK (or Java) the conformance tests SKIP LOUDLY with install
instructions; everything else stays green.

## Authority client (`authority` subpackage)

The Fatoora (ZATCA portal) HTTP client — the half of the ecosystem the
existing Go libraries lack — ported from the production-proven TypeScript
stack (its authority client, driving `@talha7k/zatca`'s api classes).
Still stdlib-only (`net/http`).

Flows, and the gateway endpoints they hit:

| Flow | Endpoint | Auth |
|---|---|---|
| Compliance CSID (onboarding, OTP + CSR) | `POST /compliance` | `OTP` header |
| Compliance invoice verification (sample set) | `POST /compliance/invoices` | Basic |
| Production CSID (after compliance passes) | `POST /production/csids` | Basic (compliance credentials) |
| Clearance — standard B2B invoices | `POST /invoices/clearance/single` | Basic + `Clearance-Status` |
| Reporting — simplified B2C invoices | `POST /invoices/reporting/single` | Basic + `Clearance-Status` |
| Status polling | `GET /invoices/status/{uuid}` | Basic |

Every request carries `Content-Type: application/json`, `Accept:
application/json`, `Accept-Language: en`, `Accept-Version: V2`.

```go
client := authority.New(authority.Config{
	Environment: authority.EnvironmentSandbox,
	BaseURL:     authority.SimulationBaseURL, // presets: SandboxConfig() etc.
	Timeout:     authority.DefaultTimeout,   // 25s transport budget
})

// Onboarding — NEVER fails on transport errors: a hung gateway returns a
// REJECTED response with REQUEST_FAILED diagnostics carrying the timeout
// sentinel, so callers classify retryable FAILED vs terminal REJECTED.
csid := client.ComplianceCSID(ctx, csrPEM, otp)
if csid.Status != authority.StatusAccepted { ... }
prod := client.ProductionCSID(ctx, authority.Credentials{
	BinarySecurityToken: csid.BinarySecurityToken, Secret: csid.Secret,
}, csid.RequestID)

// Submission — transport failures surface as *TransportError (timeout vs
// connection); gateway rejections and parse failures are results.
result, err := client.SubmitForClearance(ctx, credentials, authority.SubmitInvoiceRequest{
	InvoiceHash: invoiceHash, UUID: invoiceUUID, Invoice: invoiceB64,
})
status, err := client.CheckInvoiceStatus(ctx, credentials, invoiceUUID)
```

Configuration:

- **Base URL presets** — `SandboxConfig()` (simulation — the smoke-test
  default; the developer-portal sandbox's PCSID path is unreliable for
  final simplified reporting), `DeveloperPortalConfig()`,
  `ProductionConfig()` (`/e-invoicing/core`). `ConfigFromEnv(env)` resolves
  the `ZATCA_SANDBOX_URL` / `ZATCA_SANDBOX_MODE` /
  `ZATCA_SANDBOX_INVOICE_URL` / `ZATCA_PRODUCTION_URL` /
  `ZATCA_PRODUCTION_INVOICE_URL` split exactly like the TS plugin, with
  `NormalizeProductionInvoiceBaseURL` rewriting an upstream-style
  `/core-portal` suffix to `/core`.
- **Timeout** — `DefaultTimeout` (25s) aborts every call (the production TS
  queue consumer ran under a 60s platform cap; a hung ZATCA call must never
  eat it and leave an ambiguous "did ZATCA receive it?" state).
- **Retry (reporting only)** — transport failures and non-terminal 5xx
  retry per `RetryConfig` (default 3 retries over `[5s, 30s, 300s]`,
  clamped to the last delay; delays are deterministic — the Effect
  jitter is intentionally dropped). 4xx (incl. 429) and explicit ZATCA
  rejections are terminal.
- **Clearance-Status** — `"1"` default, overridable per config.

Error taxonomy:

- `*authority.TransportError` — connection failure
  (`CodeAPIConnectionError`, original network error wrapped in `Err`) or
  timeout (`CodeAPITimeout`, `Timeout: true`).
- `*authority.APIError` — status endpoint's 404 ("Invoice not found") and
  unparseable status bodies.
- Values, not errors — gateway rejections (`Status REJECTED`), parse
  failures (`PARSE_ERROR`/`CLIENT` alerts), and onboarding transport
  failures (`REQUEST_FAILED` diagnostics) travel inside results, mirroring
  the TS observable behavior. `AssertNoZatcaAlerts` is the strict-success
  wrapper.

Edge-case semantics preserved from the TS plugin (the timeout-sentinel
family): the `TimeoutSentinelMessage` string surfaced on every timed-out
onboarding call (the production retry classifier matches it — "aborted" /
"timed out" / "timeout"), object-only gateway JSON parsing (the portal
answers with HTML error pages under load), request-id extraction from body
`requestID` / `requestId` / response headers, recursive `[redacted]` preview
sanitation (token/secret/certificate/private/csr keys, 2000-char cap),
string-item → diagnostic-message coercion, and `CertificatePEMToBase64Token`
(the Basic-auth username is the base64(DER) body of the stored compliance
certificate). Each is cited to its TypeScript source file and line in
`authority/sentinel.go` and `authority/onboarding.go`.

The DB-state onboarding policy layer (production-CSID request plans,
config secret redaction) is application-layer and stays with the app
port — only the gateway client lives here.

## Usage

```go
package main

import (
	"fmt"

	zatca "github.com/talha7k/zatca-go"
)

func main() {
	// QR: nine fields → TLV → the base64 string embedded in the invoice XML.
	qr, err := zatca.GenerateQRBase64(zatca.QRData{
		SellerName:           "مطعم الوادي الهندي",
		VATNumber:            "310122393500003",
		Timestamp:            "2026-10-01T14:30:00",
		TotalWithVAT:         "115.00",
		VATTotal:             "15.00",
		InvoiceHash:          invoiceHashBase64, // base64 or 64-char hex
		Signature:            sigP1363Base64,    // tag 7 (base64 text)
		PublicKey:            spkiDER,           // tag 8 (raw SPKI bytes)
		CertificateSignature: certSigBytes,      // tag 9 (raw signatureValue)
	})

	// Invoice hash: SHA-256 over the canonical XML the TS pipeline emits.
	hash := zatca.HashCanonical(canonicalXML) // .Base64 / .Hex

	// Signatures: WebCrypto-compatible IEEE-P1363 (64-byte r||s).
	sig, err := zatca.SignP1363ECDSASHA256(privatePEM, message)
	ok, err := zatca.VerifyP1363ECDSASHA256(publicPEM, message, sig)
	_ = qr
	_ = ok
	_ = err
}
```

## Parity vs TypeScript

`testdata/golden-vectors.json` is the oracle — generated by the TS
implementation (see `_meta.generator` inside the file). The test suite in
`golden_parity_test.go` requires, for every vector:

- invoice hash hex/base64 equal,
- QR TLV bytes equal and the QR base64 string equal,
- the TS ECDSA signature verifies under Go, and the Go-produced signature
  round-trip verifies under the same key,
- P-1363 ↔ DER edge cases round-trip byte-exactly,
- the fixture certificate parses (Go `crypto/x509`), self-verifies, and its
  raw signature bytes equal the TS-extracted QR tag-9 form.

`testdata/golden-vectors.json` is frozen in-tree — the committed oracle. It
was generated by the TypeScript reference implementation (see `_meta.generator`
inside the file); the generator itself ships with that implementation's
private production checkout, not here. To regenerate you would run it from
that checkout, then re-run this suite:

```sh
# from the TypeScript reference implementation's checkout:
<generator> emit-golden-vectors   # writes testdata/golden-vectors.json, testdata/xml/, testdata/signing/

# then, in this module:
go test -count=1 ./...
```

All fixture keys/signatures/certificates are dev-only material — never used
against ZATCA.

### TS quirks preserved intentionally

- **Tag 6 carries the base64 TEXT of the invoice hash** (UTF-8 in TLV), not
  raw digest bytes; a 64-char hex input is normalized to base64 first.
- Tags 8/9 carry **raw DER bytes**; tags 1..7 are UTF-8 text, trimmed.
- Encoder length forms: short `<128`, `0x81` `<256`, `0x82` `<65536`;
  larger values are rejected (parity with the TS encoder cap).
- The chain preimage is the canonical XML alone (PIH lives inside the
  document, never in the digest — BR-KSA-26).

## Design note: own UBL generation vs GOBL

Inventory of what the TS reference implementation owns: UBL XML is assembled
by template literals in `@talha7k/zatca` (`dist/xml/invoice.js` +
`fragments.js`) fed by pure app-layer builders (order→InvoiceData mapping,
inclusive-VAT cents math, ICV/PIH chain patching, production readiness
patches); signing/XMLDSig/XAdES assembly (UnderUBLExtensions, SignedInfo
canonicalization, DER signatures) lives in
`@talha7k/zatca/dist/signing/sign.js` with the browser twin using WebCrypto
P-1363 — both halves now have byte-exact Go twins in this library (`xml`,
`signing`). `zatca_cleared_xml_payload` is the signed XML stored after ZATCA
clearance, guarded by the regeneration gate. The canonicalization engine is
now Go-owned too (see § Signed payload) — TS parity pinned by fixtures.

**Why not `github.com/invopop/gobl.sa.zatca`?** Adopting it (Apache-2.0,
actively maintained) would buy the BR-KSA-* validation rule suite, the full
KSA-2 document-variant matrix (nominal/export/self-billed/summary, debit
notes) and the VATEX-SA catalogue — real gaps in selective pre-issuance
gates — at the cost of routing ALL invoice construction through the GOBL
document model and its (partial, in-progress) UBL converters, in Go only.
Browser/offline issuance paths cannot run Go, so a GOBL runtime would create
a two-implementation split (TS for client minting, Go for server) with
double the parity surface. Porting the existing templates to Go, in
contrast, is bounded (~10 deterministic fragments already pinned by
golden-XML tests) and keeps one implementation family. ZATCA scope here is
standard + simplified invoices and credit notes; the variant matrix is the
only argument for GOBL. The working recommendation: keep own UBL generation
+ crypto core (this library), use GOBL as a rules-as-spec reference for the
validation gates, revisit only if exotic invoice variants become a product
requirement.

## License

AGPL-3.0 — see [LICENSE](./LICENSE).
