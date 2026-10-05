// UBL 2.1 XML fragments — a byte-exact Go port of @talha7k/zatca
// dist/xml/fragments.js (template literals). Whitespace is load-bearing: the
// golden XML fixtures pin these bytes.
package xml

import (
	"fmt"
	"strings"
)

// escapeXml escapes the five XML special characters in the same order as the
// TS escapeXml (single pass — no double escaping).
func escapeXml(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

// mustAmount formats a Decimal or panics with the exact upstream context; the
// fragment helpers convert panics to errors at the builder boundary (the TS
// builder throws plain Errors from these code paths).
func mustAmount(d Decimal, fn string) string {
	out, err := FormatAmount(d)
	if err != nil {
		panic(fmt.Errorf("%s: %w", fn, err))
	}
	return out
}

func mustUnitPrice(d Decimal) string {
	out, err := FormatUnitPrice(d)
	if err != nil {
		panic(fmt.Errorf("FormatUnitPrice: %w", err))
	}
	return out
}

func xmlUBLExtensions() string {
	return `  <ext:UBLExtensions>
    <ext:UBLExtension>
      <ext:ExtensionContent/>
    </ext:UBLExtension>
  </ext:UBLExtensions>`
}

// chainReferences carries the ICV/PIH sources (InvoiceData fields).
type chainReferences struct {
	invoiceCounter      *int
	previousInvoiceHash string
}

func xmlAdditionalDocumentReferences(document chainReferences) string {
	var refs []string
	if document.invoiceCounter != nil {
		refs = append(refs, fmt.Sprintf(`  <cac:AdditionalDocumentReference>
    <cbc:ID>ICV</cbc:ID>
    <cbc:UUID>%s</cbc:UUID>
  </cac:AdditionalDocumentReference>`, escapeXml(fmt.Sprintf("%d", *document.invoiceCounter))))
	}
	if document.previousInvoiceHash != "" {
		refs = append(refs, fmt.Sprintf(`  <cac:AdditionalDocumentReference>
    <cbc:ID>PIH</cbc:ID>
    <cac:Attachment>
      <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">%s</cbc:EmbeddedDocumentBinaryObject>
    </cac:Attachment>
  </cac:AdditionalDocumentReference>`, escapeXml(document.previousInvoiceHash)))
	}
	return strings.Join(refs, "\n")
}

func xmlSignature() string {
	return `  <cac:Signature>
    <cbc:ID>urn:oasis:names:specification:ubl:signature:Invoice</cbc:ID>
    <cbc:SignatureMethod>urn:oasis:names:specification:ubl:dsig:enveloped:xades</cbc:SignatureMethod>
  </cac:Signature>`
}

// xmlPostalAddress — KSA-23: PlotIdentification sits between BuildingNumber
// and CitySubdivisionName per the UBL 2.1 element sequence.
func xmlPostalAddress(addr PostalAddress, indent string) string {
	plotIdentification := ""
	if addr.AdditionalNumber != "" {
		plotIdentification = "\n" + indent + "  <cbc:PlotIdentification>" + escapeXml(addr.AdditionalNumber) + "</cbc:PlotIdentification>"
	}
	countrySubentity := ""
	if addr.CountrySubentity != "" {
		countrySubentity = "\n" + indent + "  <cbc:CountrySubentity>" + escapeXml(addr.CountrySubentity) + "</cbc:CountrySubentity>"
	}
	return fmt.Sprintf(`%s<cac:PostalAddress>
%s  <cbc:StreetName>%s</cbc:StreetName>
%s  <cbc:BuildingNumber>%s</cbc:BuildingNumber>%s
%s  <cbc:CitySubdivisionName>%s</cbc:CitySubdivisionName>
%s  <cbc:CityName>%s</cbc:CityName>
%s  <cbc:PostalZone>%s</cbc:PostalZone>%s
%s  <cac:Country>
%s    <cbc:IdentificationCode>%s</cbc:IdentificationCode>
%s  </cac:Country>
%s</cac:PostalAddress>`,
		indent,
		indent, escapeXml(addr.Street),
		indent, escapeXml(addr.Building), plotIdentification,
		indent, escapeXml(addr.District),
		indent, escapeXml(addr.City),
		indent, escapeXml(addr.PostalCode), countrySubentity,
		indent,
		indent, escapeXml(addr.CountryCode),
		indent,
		indent)
}

func xmlSupplierParty(supplier SupplierInfo) string {
	crBlock := ""
	if supplier.CRNumber != "" {
		crBlock = fmt.Sprintf(`
      <cac:PartyIdentification>
        <cbc:ID schemeID="CRN">%s</cbc:ID>
      </cac:PartyIdentification>`, escapeXml(supplier.CRNumber))
	}
	return fmt.Sprintf(`  <cac:AccountingSupplierParty>
    <cac:Party>
%s
%s
      <cac:PartyTaxScheme>
        <cbc:CompanyID>%s</cbc:CompanyID>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:PartyTaxScheme>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>%s</cbc:RegistrationName>
      </cac:PartyLegalEntity>
    </cac:Party>
  </cac:AccountingSupplierParty>`,
		crBlock,
		xmlPostalAddress(supplier.Address, "      "),
		escapeXml(supplier.VATNumber),
		escapeXml(supplier.NameAr))
}

func xmlCustomerParty(customer CustomerInfo) string {
	addressBlock := ""
	if customer.Address != nil {
		addressBlock = "\n" + xmlPostalAddress(*customer.Address, "      ")
	}
	return fmt.Sprintf(`  <cac:AccountingCustomerParty>
    <cac:Party>
%s
      <cac:PartyTaxScheme>
        <cbc:CompanyID>%s</cbc:CompanyID>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:PartyTaxScheme>
      <cac:PartyLegalEntity>
        <cbc:RegistrationName>%s</cbc:RegistrationName>
      </cac:PartyLegalEntity>
    </cac:Party>
  </cac:AccountingCustomerParty>`,
		addressBlock,
		escapeXml(customer.VATNumber),
		escapeXml(customer.Name))
}

func xmlTaxSubtotal(subtotal TaxSubtotal, currencyCode string) string {
	return fmt.Sprintf(`    <cac:TaxSubtotal>
      <cbc:TaxableAmount currencyID="%s">%s</cbc:TaxableAmount>
      <cbc:TaxAmount currencyID="%s">%s</cbc:TaxAmount>
      <cac:TaxCategory>
        <cbc:ID>%s</cbc:ID>
        <cbc:Percent>%s</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:TaxCategory>
    </cac:TaxSubtotal>`,
		escapeXml(currencyCode), mustAmount(subtotal.TaxableAmount, "FormatAmount"),
		escapeXml(currencyCode), mustAmount(subtotal.TaxAmount, "FormatAmount"),
		subtotal.TaxCategoryID,
		mustPercent(subtotal.Percent))
}

// xmlTaxTotalBlocks emits BOTH TaxTotal blocks (ZATCA requires the second
// one carrying the tax currency).
func xmlTaxTotalBlocks(taxAmount Decimal, currencyCode string, subtotals []TaxSubtotal) string {
	blocks := make([]string, 0, len(subtotals))
	for _, s := range subtotals {
		blocks = append(blocks, xmlTaxSubtotal(s, currencyCode))
	}
	subtotalBlocks := strings.Join(blocks, "\n")
	taxAmountFormatted := mustAmount(taxAmount, "FormatAmount")
	withSubtotals := fmt.Sprintf(`  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="%s">%s</cbc:TaxAmount>
%s
  </cac:TaxTotal>`, escapeXml(currencyCode), taxAmountFormatted, subtotalBlocks)
	withTaxCurrency := fmt.Sprintf(`  <cac:TaxTotal>
    <cbc:TaxAmount currencyID="%s">%s</cbc:TaxAmount>
  </cac:TaxTotal>`, escapeXml(currencyCode), taxAmountFormatted)
	return withSubtotals + "\n" + withTaxCurrency
}

type taxCategoryRef struct {
	id      string
	percent float64
}

func xmlAllowanceCharge(charge AllowanceCharge, currencyCode, indent string, defaultCategory *taxCategoryRef) string {
	var effective *taxCategoryRef
	if charge.TaxCategoryID != "" && charge.TaxPercent != nil {
		effective = &taxCategoryRef{id: charge.TaxCategoryID, percent: *charge.TaxPercent}
	} else {
		effective = defaultCategory
	}
	taxCategoryBlock := ""
	if effective != nil {
		taxCategoryBlock = fmt.Sprintf(`
%s  <cac:TaxCategory>
%s    <cbc:ID>%s</cbc:ID>
%s    <cbc:Percent>%s</cbc:Percent>
%s    <cac:TaxScheme>
%s      <cbc:ID>VAT</cbc:ID>
%s    </cac:TaxScheme>
%s  </cac:TaxCategory>`,
			indent,
			indent, escapeXml(effective.id),
			indent, mustPercent(effective.percent),
			indent,
			indent,
			indent,
			indent)
	}
	chargeIndicator := "false"
	if charge.ChargeIndicator {
		chargeIndicator = "true"
	}
	return fmt.Sprintf(`%s<cac:AllowanceCharge>
%s  <cbc:ChargeIndicator>%s</cbc:ChargeIndicator>
%s  <cbc:AllowanceChargeReason>%s</cbc:AllowanceChargeReason>
%s  <cbc:Amount currencyID="%s">%s</cbc:Amount>
%s
%s</cac:AllowanceCharge>`,
		indent,
		indent, chargeIndicator,
		indent, escapeXml(charge.Reason),
		indent, escapeXml(currencyCode), mustAmount(charge.Amount, "FormatAmount"),
		taxCategoryBlock,
		indent)
}

// xmlAllowanceCharges renders the document-level allowance/charge list (”
// when absent — the caller embeds it into a template line like the TS join).
func xmlAllowanceCharges(doc *InvoiceData) string {
	var defaultCategory *taxCategoryRef
	if len(doc.TaxSubtotals) > 0 {
		defaultCategory = &taxCategoryRef{id: doc.TaxSubtotals[0].TaxCategoryID, percent: doc.TaxSubtotals[0].Percent}
	}
	blocks := make([]string, 0, len(doc.AllowanceCharges))
	for _, charge := range doc.AllowanceCharges {
		blocks = append(blocks, xmlAllowanceCharge(charge, doc.CurrencyCode, "  ", defaultCategory))
	}
	return strings.Join(blocks, "\n")
}

func xmlMonetaryTotal(doc *InvoiceData) string {
	allowanceBlock := ""
	if doc.AllowanceTotalAmount != nil && *doc.AllowanceTotalAmount != "" {
		allowanceBlock = fmt.Sprintf(`
    <cbc:AllowanceTotalAmount currencyID="%s">%s</cbc:AllowanceTotalAmount>`,
			escapeXml(doc.CurrencyCode), mustAmount(*doc.AllowanceTotalAmount, "FormatAmount"))
	}
	// UBL LegalMonetaryTotal sequence: ... AllowanceTotalAmount, ChargeTotalAmount,
	// PrepaidAmount (BT-113), PayableRoundingAmount (BT-114), PayableAmount (BT-115).
	prepaidBlock := ""
	if doc.PrepaidAmount != nil && *doc.PrepaidAmount != "" {
		prepaidBlock = fmt.Sprintf(`
    <cbc:PrepaidAmount currencyID="%s">%s</cbc:PrepaidAmount>`,
			escapeXml(doc.CurrencyCode), mustAmount(*doc.PrepaidAmount, "FormatAmount"))
	}
	roundingBlock := ""
	if doc.RoundingAmount != nil && *doc.RoundingAmount != "" {
		roundingBlock = fmt.Sprintf(`
    <cbc:PayableRoundingAmount currencyID="%s">%s</cbc:PayableRoundingAmount>`,
			escapeXml(doc.CurrencyCode), mustAmount(*doc.RoundingAmount, "FormatAmount"))
	}
	return fmt.Sprintf(`  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="%s">%s</cbc:LineExtensionAmount>
    <cbc:TaxExclusiveAmount currencyID="%s">%s</cbc:TaxExclusiveAmount>
    <cbc:TaxInclusiveAmount currencyID="%s">%s</cbc:TaxInclusiveAmount>%s%s%s
    <cbc:PayableAmount currencyID="%s">%s</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>`,
		escapeXml(doc.CurrencyCode), mustAmount(doc.LineExtensionAmount, "FormatAmount"),
		escapeXml(doc.CurrencyCode), mustAmount(doc.TaxExclusiveAmount, "FormatAmount"),
		escapeXml(doc.CurrencyCode), mustAmount(doc.TaxInclusiveAmount, "FormatAmount"),
		allowanceBlock, prepaidBlock, roundingBlock,
		escapeXml(doc.CurrencyCode), mustAmount(doc.PayableAmount, "FormatAmount"))
}

func xmlInvoiceLine(line InvoiceLineItem, currencyCode string) string {
	defaultCategory := taxCategoryRef{id: line.TaxCategoryID, percent: line.TaxPercent}
	blocks := make([]string, 0, len(line.AllowanceCharges))
	for _, charge := range line.AllowanceCharges {
		blocks = append(blocks, xmlAllowanceCharge(charge, currencyCode, "    ", &defaultCategory))
	}
	allowanceChargeBlock := ""
	if len(blocks) > 0 {
		allowanceChargeBlock = "\n" + strings.Join(blocks, "\n")
	}
	// KSA-12 line amount with VAT = BT-131 + KSA-11 (exact decimal add).
	rounding, err := AddDecimal(line.LineExtensionAmount, line.TaxAmount)
	if err != nil {
		panic(fmt.Errorf("AddDecimal(line %d): %w", line.ID, err))
	}
	return fmt.Sprintf(`  <cac:InvoiceLine>
    <cbc:ID>%d</cbc:ID>
    <cbc:InvoicedQuantity unitCode="%s">%s</cbc:InvoicedQuantity>
    <cbc:LineExtensionAmount currencyID="%s">%s</cbc:LineExtensionAmount>%s
    <cac:TaxTotal>
      <cbc:TaxAmount currencyID="%s">%s</cbc:TaxAmount>
      <cbc:RoundingAmount currencyID="%s">%s</cbc:RoundingAmount>
    </cac:TaxTotal>
    <cac:Item>
      <cbc:Name>%s</cbc:Name>
      <cac:ClassifiedTaxCategory>
        <cbc:ID>%s</cbc:ID>
        <cbc:Percent>%s</cbc:Percent>
        <cac:TaxScheme>
          <cbc:ID>VAT</cbc:ID>
        </cac:TaxScheme>
      </cac:ClassifiedTaxCategory>
    </cac:Item>
    <cac:Price>
      <cbc:PriceAmount currencyID="%s">%s</cbc:PriceAmount>
    </cac:Price>
  </cac:InvoiceLine>`,
		line.ID,
		escapeXml(line.UnitCode), mustUnitPrice(line.Quantity),
		escapeXml(currencyCode), mustAmount(line.LineExtensionAmount, "FormatAmount"), allowanceChargeBlock,
		escapeXml(currencyCode), mustAmount(line.TaxAmount, "FormatAmount"),
		escapeXml(currencyCode), mustAmount(rounding, "FormatAmount"),
		escapeXml(line.ItemName),
		line.TaxCategoryID,
		mustPercent(line.TaxPercent),
		escapeXml(currencyCode), mustUnitPrice(line.PriceAmount))
}
