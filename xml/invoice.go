// Invoice XML generation — UBL 2.1 for ZATCA phase 2. A byte-exact Go port
// of @talha7k/zatca dist/xml/{invoice,credit-note}.js. The TS doc comments
// are preserved where they explain structure:
//
//   - cbc:UBLVersionID = "2.1" (explicit, required by ZATCA)
//   - cac:AdditionalDocumentReference for ICV (invoice counter) and PIH
//   - cac:Signature element (required by ZATCA)
//   - cbc:RoundingAmount in each invoice line's cac:TaxTotal
//   - cac:PartyIdentification with schemeID="CRN" for supplier
//   - second cac:TaxTotal with tax currency (ZATCA requires both)
package xml

import (
	"fmt"
	"strings"
)

// generateDocumentXML runs fn, converting fragment panics (invalid decimal
// input — the TS builder's throw path) into errors.
func generateDocumentXML(kind string, build func() string) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			var pErr error
			if e, ok := r.(error); ok {
				pErr = e
			} else {
				pErr = fmt.Errorf("%v", r)
			}
			out, err = "", fmt.Errorf("failed to generate %s XML: %w", kind, pErr)
		}
	}()
	return build(), nil
}

// GenerateInvoiceXml generates a complete ZATCA-compliant UBL 2.1 invoice XML
// string — byte-identical to the TS generateInvoiceXml for the same
// InvoiceData (pinned by golden XML fixtures).
func GenerateInvoiceXml(invoice *InvoiceData) (string, error) {
	return generateDocumentXML("invoice", func() string {
		return buildInvoiceXML(invoice)
	})
}

func buildInvoiceXML(invoice *InvoiceData) string {
	refs := chainReferences{invoiceCounter: invoice.InvoiceCounter, previousInvoiceHash: invoice.PreviousInvoiceHash}
	additionalDocs := xmlAdditionalDocumentReferences(refs)
	additionalDocsBlock := "\n"
	if additionalDocs != "" {
		additionalDocsBlock = "\n" + additionalDocs + "\n"
	}
	// Note: Using empty AccountingCustomerParty for simplified (B2C) invoices.
	// ZATCA requires this element even for simplified invoices where no
	// customer details exist.
	customerBlock := "\n  <cac:AccountingCustomerParty>\n  </cac:AccountingCustomerParty>"
	if invoice.Customer != nil {
		customerBlock = "\n" + xmlCustomerParty(*invoice.Customer)
	}
	// KSA-5 supply date — BR-KSA-15 requires cac:Delivery/cbc:ActualDeliveryDate
	// on standard (B2B) tax invoices (KSA-2 first two digits "01").
	deliveryBlock := ""
	if invoice.SupplyDate != nil && *invoice.SupplyDate != "" {
		deliveryBlock = fmt.Sprintf(`
  <cac:Delivery>
    <cbc:ActualDeliveryDate>%s</cbc:ActualDeliveryDate>
  </cac:Delivery>`, escapeXml(*invoice.SupplyDate))
	}
	// BT-81 — BR-KSA-16 requires PaymentMeans on standard (B2B) invoices.
	paymentMeansBlock := ""
	if invoice.PaymentMeansCode != nil && *invoice.PaymentMeansCode != 0 {
		paymentMeansBlock = fmt.Sprintf(`
  <cac:PaymentMeans>
    <cbc:PaymentMeansCode>%d</cbc:PaymentMeansCode>
  </cac:PaymentMeans>`, *invoice.PaymentMeansCode)
	}
	lineBlocks := make([]string, 0, len(invoice.InvoiceLines))
	for _, line := range invoice.InvoiceLines {
		lineBlocks = append(lineBlocks, xmlInvoiceLine(line, invoice.CurrencyCode))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
%s
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:ProfileID>%s</cbc:ProfileID>
  <cbc:ID>%s</cbc:ID>
  <cbc:UUID>%s</cbc:UUID>
  <cbc:IssueDate>%s</cbc:IssueDate>
  <cbc:IssueTime>%s</cbc:IssueTime>
  <cbc:InvoiceTypeCode name="%s">%s</cbc:InvoiceTypeCode>
  <cbc:DocumentCurrencyCode>%s</cbc:DocumentCurrencyCode>
  <cbc:TaxCurrencyCode>%s</cbc:TaxCurrencyCode>
%s%s

%s%s%s%s

%s

%s

%s

%s
</Invoice>`,
		xmlUBLExtensions(),
		escapeXml(invoice.ProfileID),
		escapeXml(invoice.InvoiceNumber),
		escapeXml(invoice.UUID),
		escapeXml(invoice.IssueDate),
		escapeXml(invoice.IssueTime),
		escapeXml(invoice.InvoiceTypeCodeName),
		invoice.InvoiceTypeCode,
		escapeXml(invoice.CurrencyCode),
		escapeXml(invoice.CurrencyCode),
		additionalDocsBlock, xmlSignature(),
		xmlSupplierParty(invoice.Supplier), customerBlock, deliveryBlock, paymentMeansBlock,
		xmlAllowanceCharges(invoice),
		xmlTaxTotalBlocks(invoice.TaxAmount, invoice.CurrencyCode, invoice.TaxSubtotals),
		xmlMonetaryTotal(invoice),
		strings.Join(lineBlocks, "\n"))
}

// GenerateCreditNoteXml generates a complete ZATCA-compliant UBL 2.1 credit
// note XML string (InvoiceTypeCode 381).
func GenerateCreditNoteXml(creditNote *CreditNoteData) (string, error) {
	return generateDocumentXML("credit note", func() string {
		return buildCreditNoteXML(creditNote)
	})
}

// GenerateDebitNoteXml generates a UBL 2.1 debit note (383). Debit notes
// share the credit-note document shape; only the type code differs — the
// code is asserted here so a copy-paste slip cannot emit a mistyped note.
func GenerateDebitNoteXml(debitNote *CreditNoteData) (string, error) {
	if debitNote.InvoiceTypeCode != TypeCodeDebitNote {
		return "", fmt.Errorf("debit notes require InvoiceTypeCode '383', got '%s'", debitNote.InvoiceTypeCode)
	}
	return generateDocumentXML("debit note", func() string {
		return buildCreditNoteXML(debitNote)
	})
}

func xmlBillingReference(cn *CreditNoteData) string {
	return fmt.Sprintf(`  <cac:BillingReference>
    <cac:InvoiceDocumentReference>
      <cbc:ID>%s</cbc:ID>
      <cbc:UUID>%s</cbc:UUID>
      <cbc:IssueDate>%s</cbc:IssueDate>
    </cac:InvoiceDocumentReference>
  </cac:BillingReference>`,
		escapeXml(cn.OriginalInvoiceNumber),
		escapeXml(cn.OriginalInvoiceUUID),
		escapeXml(cn.OriginalInvoiceDate))
}

// xmlPaymentMeans — ZATCA requires the reason for credit/debit notes in
// cbc:InstructionNote, even when the same reason is also exposed as cbc:Note.
func xmlPaymentMeans(cn *CreditNoteData) string {
	return fmt.Sprintf(`  <cac:PaymentMeans>
    <cbc:PaymentMeansCode>10</cbc:PaymentMeansCode>
    <cbc:InstructionNote>%s</cbc:InstructionNote>
  </cac:PaymentMeans>`, escapeXml(cn.Reason))
}

func buildCreditNoteXML(creditNote *CreditNoteData) string {
	refs := chainReferences{invoiceCounter: creditNote.InvoiceCounter, previousInvoiceHash: creditNote.PreviousInvoiceHash}
	additionalDocs := xmlAdditionalDocumentReferences(refs)
	additionalDocsBlock := "\n"
	if additionalDocs != "" {
		additionalDocsBlock = "\n" + additionalDocs + "\n"
	}
	// ZATCA requires cac:AccountingCustomerParty even for simplified (B2C)
	// notes with no buyer details — mirror the invoice builder's empty party.
	customerBlock := "\n  <cac:AccountingCustomerParty>\n  </cac:AccountingCustomerParty>"
	if creditNote.Customer != nil {
		customerBlock = "\n" + xmlCustomerParty(*creditNote.Customer)
	}
	lineBlocks := make([]string, 0, len(creditNote.InvoiceLines))
	for _, line := range creditNote.InvoiceLines {
		lineBlocks = append(lineBlocks, xmlInvoiceLine(line, creditNote.CurrencyCode))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
            xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
            xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
            xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">
%s
  <cbc:UBLVersionID>2.1</cbc:UBLVersionID>
  <cbc:ProfileID>%s</cbc:ProfileID>
  <cbc:ID>%s</cbc:ID>
  <cbc:UUID>%s</cbc:UUID>
  <cbc:IssueDate>%s</cbc:IssueDate>
  <cbc:IssueTime>%s</cbc:IssueTime>
  <cbc:InvoiceTypeCode name="%s">%s</cbc:InvoiceTypeCode>
  <cbc:Note>%s</cbc:Note>
  <cbc:DocumentCurrencyCode>%s</cbc:DocumentCurrencyCode>
  <cbc:TaxCurrencyCode>%s</cbc:TaxCurrencyCode>

%s

%s%s

%s%s

%s

%s

%s

%s

%s
</Invoice>`,
		xmlUBLExtensions(),
		escapeXml(creditNote.ProfileID),
		escapeXml(creditNote.InvoiceNumber),
		escapeXml(creditNote.UUID),
		escapeXml(creditNote.IssueDate),
		escapeXml(creditNote.IssueTime),
		escapeXml(creditNote.InvoiceTypeCodeName),
		creditNote.InvoiceTypeCode,
		escapeXml(creditNote.Reason),
		escapeXml(creditNote.CurrencyCode),
		escapeXml(creditNote.CurrencyCode),
		xmlBillingReference(creditNote),
		additionalDocsBlock, xmlSignature(),
		xmlSupplierParty(creditNote.Supplier), customerBlock,
		xmlPaymentMeans(creditNote),
		xmlAllowanceCharges(&creditNote.InvoiceData),
		xmlTaxTotalBlocks(creditNote.TaxAmount, creditNote.CurrencyCode, creditNote.TaxSubtotals),
		xmlMonetaryTotal(&creditNote.InvoiceData),
		strings.Join(lineBlocks, "\n"))
}
