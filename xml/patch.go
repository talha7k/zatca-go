// Production XML patches — the Go twin of packages/contracts
// zatca-order-xml.ts chain patching (ICV/PIH rewrite into a minted XML) and
// the submission-readiness patches (KSA-5 supply date on standard invoices,
// reporting:1.0 profile).
//
// Go's RE2 has no lookahead: the TS `<cbc:InvoiceTypeCode\b(?=[^>]*\bname=…)…`
// existence checks become a whole-tag match + attribute inspection
// (invoiceTypeCodeMatches).
package xml

import (
	"regexp"
	"strconv"
	"strings"
)

// varBlock pattern: a cac:AdditionalDocumentReference whose first child is
// the given ID (ICV or PIH), non-greedy to the closing tag.
func additionalDocumentReferencePattern(id string) *regexp.Regexp {
	return regexp.MustCompile(`(?s)<cac:AdditionalDocumentReference>\s*<cbc:ID>` + id + `</cbc:ID>.*?</cac:AdditionalDocumentReference>`)
}

var signatureOpenPattern = regexp.MustCompile(`(\s*<cac:Signature\b[^>]*>)`)

func buildICVReference(invoiceCounter int) string {
	return `  <cac:AdditionalDocumentReference>
    <cbc:ID>ICV</cbc:ID>
    <cbc:UUID>` + strconv.Itoa(invoiceCounter) + `</cbc:UUID>
  </cac:AdditionalDocumentReference>`
}

func buildPIHReference(previousInvoiceHash string) string {
	return `  <cac:AdditionalDocumentReference>
    <cbc:ID>PIH</cbc:ID>
    <cac:Attachment>
      <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">` + previousInvoiceHash + `</cbc:EmbeddedDocumentBinaryObject>
    </cac:Attachment>
  </cac:AdditionalDocumentReference>`
}

func patchAdditionalDocumentReference(xmlString, id, replacement string) string {
	pattern := additionalDocumentReferencePattern(id)
	if pattern.MatchString(xmlString) {
		return pattern.ReplaceAllString(xmlString, regexp.QuoteMeta(replacement))
	}
	// No existing reference of this kind — insert before cac:Signature.
	return signatureOpenPattern.ReplaceAllString(xmlString, "\n"+regexp.QuoteMeta(replacement)+"\n$1")
}

// PatchInvoiceChainReferences rewrites the ICV (invoice counter value,
// KSA-16) and PIH (previous invoice hash, KSA-13) references of a minted
// invoice XML — the hash-chain patch discipline. An empty previous hash
// falls back to the genesis PIH (BR-KSA-26 seed).
func PatchInvoiceChainReferences(xmlString string, previousInvoiceHash string, invoiceCounter int) string {
	pih := previousInvoiceHash
	if pih == "" {
		pih = GenesisPIH
	}
	patched := patchAdditionalDocumentReference(xmlString, "ICV", buildICVReference(invoiceCounter))
	return patchAdditionalDocumentReference(patched, "PIH", buildPIHReference(pih))
}

// invoiceTypeCodeMatches reports whether the document carries an
// InvoiceTypeCode element whose name attribute (KSA-2 subtype) starts with
// namePrefix and whose code equals typeCode — the lookahead-free twin of the
// TS regex checks.
func invoiceTypeCodeMatches(xmlString, namePrefix, typeCode string) bool {
	re := regexp.MustCompile(`<cbc:InvoiceTypeCode\b([^>]*)>\s*(\d{3})\s*</cbc:InvoiceTypeCode>`)
	for _, m := range re.FindAllStringSubmatch(xmlString, -1) {
		attrs, code := m[1], m[2]
		if name := extractAttributeName(attrs, "name"); strings.HasPrefix(name, namePrefix) && code == typeCode {
			return true
		}
	}
	return false
}

// extractAttributeName pulls attr="value" / attr='value' from a raw attribute
// string ("" when absent).
func extractAttributeName(attrs, attr string) string {
	for _, quote := range []string{`"`, `'`} {
		re := regexp.MustCompile(`\b` + attr + `=` + regexp.QuoteMeta(quote) + `([^` + regexp.QuoteMeta(quote) + `]*)` + regexp.QuoteMeta(quote))
		if m := re.FindStringSubmatch(attrs); m != nil {
			return m[1]
		}
	}
	return ""
}

var (
	paymentMeansOpenPattern = regexp.MustCompile(`(\s*<cac:PaymentMeans\b[^>]*>)`)
	deliveryOpenPattern     = regexp.MustCompile(`<cac:Delivery\b`)
	taxTotalOpenPattern     = regexp.MustCompile(`(\s*<cac:TaxTotal\b[^>]*>)`)
	clearanceProfilePattern = regexp.MustCompile(`<cbc:ProfileID>clearance:1\.0</cbc:ProfileID>`)
)

// PatchSimplifiedCreditDebitCustomerParty inserts the empty
// AccountingCustomerParty ZATCA requires on simplified credit/debit notes
// (KSA-2 subtype 0200000, type 381/383) when the minted XML carries none.
func PatchSimplifiedCreditDebitCustomerParty(xmlString string) string {
	isSimplifiedCreditOrDebit := invoiceTypeCodeMatches(xmlString, "02", "381") ||
		invoiceTypeCodeMatches(xmlString, "02", "383")
	if !isSimplifiedCreditOrDebit ||
		strings.Contains(xmlString, "<cac:AccountingCustomerParty") {
		return xmlString
	}
	return paymentMeansOpenPattern.ReplaceAllString(xmlString,
		"\n  <cac:AccountingCustomerParty>\n  </cac:AccountingCustomerParty>\n$1")
}

// extractFirstXMLValue returns the trimmed text of the first <cbc:TAG>
// element, or "" — the TS extractXmlValue twin.
func extractFirstXMLValue(xmlString, tagName string) string {
	re := regexp.MustCompile(`<cbc:` + tagName + `[^>]*>([^<]+)</cbc:` + tagName + `>`)
	m := re.FindStringSubmatch(xmlString)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// PatchStandardInvoiceSupplyDate inserts cac:Delivery/cbc:ActualDeliveryDate
// (KSA-5) on standard tax invoices (subtype 01…, type 388) that lack one,
// anchored before PaymentMeans when present, else before the first TaxTotal.
func PatchStandardInvoiceSupplyDate(xmlString string) string {
	if !invoiceTypeCodeMatches(xmlString, "01", "388") ||
		deliveryOpenPattern.MatchString(xmlString) {
		return xmlString
	}
	issueDate := extractFirstXMLValue(xmlString, "IssueDate")
	if issueDate == "" {
		return xmlString
	}
	delivery := `  <cac:Delivery>
    <cbc:ActualDeliveryDate>` + issueDate + `</cbc:ActualDeliveryDate>
  </cac:Delivery>`
	if paymentMeansOpenPattern.MatchString(xmlString) {
		return paymentMeansOpenPattern.ReplaceAllString(xmlString, "\n"+delivery+"\n$1")
	}
	return taxTotalOpenPattern.ReplaceAllString(xmlString, "\n"+delivery+"\n$1")
}

// PatchBusinessProcessProfile rewrites every clearance:1.0 ProfileID (BT-23)
// to reporting:1.0 — the submission pipeline profile.
func PatchBusinessProcessProfile(xmlString string) string {
	return clearanceProfilePattern.ReplaceAllString(xmlString, "<cbc:ProfileID>"+ProfileIDReporting+"</cbc:ProfileID>")
}

// PatchProductionXML composes the submission patches: profile + supply date.
func PatchProductionXML(xmlString string) string {
	return PatchStandardInvoiceSupplyDate(PatchBusinessProcessProfile(xmlString))
}
