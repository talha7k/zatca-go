// The BR-KSA rule suite + EN 16931 core consistency checks, expressed as an
// ordered rule table over the xml.InvoiceData model. Each entry returns
// (fault, violated?) — a nil fault with true is impossible by construction.
package validate

import (
	"encoding/base64"
	"fmt"
	"strings"

	xml "github.com/talha7k/zatca-go/xml"
)

var base64Std = base64.StdEncoding

// ruleFunc evaluates one rule against the document.
type ruleFunc func(inv *xml.InvoiceData, o *options) (Fault, bool)

// rule pairs a stable rule identity with its check — identities are explicit
// so RuleIDs() and test pins never depend on which rules happen to fire on a
// probe document.
type rule struct {
	id    string
	check ruleFunc
}

func fault(ruleID string, severity Severity, path, message string) (Fault, bool) {
	return Fault{RuleID: ruleID, Severity: severity, Path: path, Message: message}, true
}

// ksaF builds a BR-KSA fault.
func ksa(ruleID, path, message string) (Fault, bool) {
	// BR-KSA-09 is the only warning-severity rule in our applicable set
	// (schematron flag="warning"); everything else is flag="error".
	severity := SeverityError
	if ruleID == "BR-KSA-09" {
		severity = SeverityWarning
	}
	return fault(ruleID, severity, path, message)
}

// rules is the ordered BR-KSA table (rule order = ascending BR-KSA number,
// then the EN 16931 core-consistency block).
var rules = []rule{
	// BR-KSA-03 — UUID (KSA-1) present, letters/digits/dashes only.
	{id: "BR-KSA-03", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.UUID == "" {
			return ksa("BR-KSA-03", "uuid", "the invoice must contain a unique identifier (UUID, KSA-1)")
		}
		if !uuidPattern.MatchString(inv.UUID) {
			return ksa("BR-KSA-03", "uuid", "the UUID must contain only letters, digits, and dashes")
		}
		return Fault{}, false
	}},

	// BR-KSA-04 — issue date (BT-2) ≤ current date.
	{id: "BR-KSA-04", check: func(inv *xml.InvoiceData, o *options) (Fault, bool) {
		today := o.now().UTC().Format("2006-01-02")
		if inv.IssueDate == "" || inv.IssueDate > today {
			return ksa("BR-KSA-04", "issueDate", "the document issue date (BT-2) must be less or equal to the current date")
		}
		return Fault{}, false
	}},

	// BR-KSA-05 — type code (BT-3) in the KSA subset {388, 383, 381}.
	{id: "BR-KSA-05", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		switch inv.InvoiceTypeCode {
		case xml.TypeCodeInvoice, xml.TypeCodeDebitNote, xml.TypeCodeCreditNote:
			return Fault{}, false
		}
		return ksa("BR-KSA-05", "invoiceTypeCode",
			"the invoice type code (BT-3) must be one of the UN/CEFACT 1001 D.16B subset agreed for KSA electronic invoices (388, 383, 381)")
	}},

	// BR-KSA-06 — KSA-2 subtype name respects the NNPNESB structure.
	{id: "BR-KSA-06", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if validNNPNESB(inv.InvoiceTypeCodeName) {
			return Fault{}, false
		}
		return ksa("BR-KSA-06", "invoiceTypeCodeName",
			"the invoice transaction code (KSA-2) must exist and respect the NNPNESB structure (01/02 subtype + five 0/1 flags)")
	}},

	// BR-KSA-07 — self billing (position 7 = 1) is not allowed on export
	// invoices (position 5 = 1).
	{id: "BR-KSA-07", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		name := inv.InvoiceTypeCodeName
		if len(name) == 7 && name[6] == '1' && name[4] == '1' {
			return ksa("BR-KSA-07", "invoiceTypeCodeName",
				"self billing is not allowed for export invoices (KSA-2 positions 5 and 7)")
		}
		return Fault{}, false
	}},

	// BR-KSA-08 — seller identification scheme: CRN value alphanumeric.
	{id: "BR-KSA-08", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		crn := inv.Supplier.CRNumber
		if crn != "" && !isAlphanumeric(crn) {
			return ksa("BR-KSA-08", "supplier.crNumber",
				"the seller identification (BT-29) must contain only alphanumeric characters")
		}
		return Fault{}, false
	}},

	// BR-KSA-09 (warning) — seller address completeness (KSA-23, BT-35,
	// KSA-17, BT-38, BT-37, KSA-3, BT-40).
	{id: "BR-KSA-09", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		a := inv.Supplier.Address
		missing := []string{}
		for _, m := range []struct {
			field string
			value string
		}{
			{"additionalNumber", a.AdditionalNumber},
			{"street", a.Street},
			{"building", a.Building},
			{"postalCode", a.PostalCode},
			{"city", a.City},
			{"district", a.District},
			{"countryCode", a.CountryCode},
		} {
			if m.value == "" {
				missing = append(missing, m.field)
			}
		}
		if len(missing) > 0 {
			return ksa("BR-KSA-09", "supplier.address",
				"seller address must contain additional number, street name, building number, postal code, city, neighborhood and country code (missing: "+strings.Join(missing, ", ")+")")
		}
		return Fault{}, false
	}},

	// BR-KSA-10 — buyer address street/city/postal/country (standard only;
	// never simplified).
	{id: "BR-KSA-10", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if !IsStandard(inv) || inv.Customer == nil || inv.Customer.Address == nil {
			return Fault{}, false
		}
		a := inv.Customer.Address
		missing := []string{}
		for _, m := range []struct {
			field string
			value string
		}{
			{"street", a.Street},
			{"city", a.City},
			{"postalCode", a.PostalCode},
			{"countryCode", a.CountryCode},
		} {
			if m.value == "" {
				missing = append(missing, m.field)
			}
		}
		if len(missing) > 0 {
			return ksa("BR-KSA-10", "customer.address",
				"buyer address must contain street, city, postal code and country code for standard tax invoices (missing: "+strings.Join(missing, ", ")+")")
		}
		return Fault{}, false
	}},

	// BR-KSA-14 — buyer identification must be alphanumeric when present
	// (scheme validity in our model: the B2B VAT/TIN identity).
	{id: "BR-KSA-14", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.Customer != nil && inv.Customer.VATNumber != "" && !isAlphanumeric(inv.Customer.VATNumber) {
			return ksa("BR-KSA-14", "customer.vatNumber",
				"the buyer identification (BT-46) must contain only alphanumeric characters")
		}
		return Fault{}, false
	}},

	// BR-KSA-15 — standard tax invoices must carry the supply date (KSA-5).
	{id: "BR-KSA-15", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if IsStandard(inv) && (inv.SupplyDate == nil || *inv.SupplyDate == "") {
			return ksa("BR-KSA-15", "supplyDate",
				"the tax invoice (subtype 01, type 388) must contain the supply date (KSA-5)")
		}
		return Fault{}, false
	}},

	// BR-KSA-16 — payment means code present on standard invoices and, when
	// present anywhere, one of 10/30/42/48/1 (optional on simplified).
	{id: "BR-KSA-16", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.PaymentMeansCode == nil {
			if IsStandard(inv) {
				return ksa("BR-KSA-16", "paymentMeansCode",
					"payment means code (BT-81) is required on standard tax invoices (one of 10, 30, 42, 48, 1)")
			}
			return Fault{}, false
		}
		if !paymentMeansCodes[*inv.PaymentMeansCode] {
			return ksa("BR-KSA-16", "paymentMeansCode",
				"payment means code (BT-81) must contain one of the values 10, 30, 42, 48, 1")
		}
		return Fault{}, false
	}},

	// BR-KSA-26 — the previous invoice hash (KSA-13), when present, must be
	// base64 (decodable; the schematron assert also demands non-empty text).
	{id: "BR-KSA-26", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.PreviousInvoiceHash != "" && !isBase64(inv.PreviousInvoiceHash) {
			return ksa("BR-KSA-26", "previousInvoiceHash",
				"the previous invoice hash (KSA-13) must be a base64 encoded SHA-256 digest")
		}
		return Fault{}, false
	}},

	// BR-KSA-33 — every invoice must have the invoice counter value (KSA-16).
	{id: "BR-KSA-33", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.InvoiceCounter == nil {
			return ksa("BR-KSA-33", "invoiceCounter", "each invoice must have an invoice counter value (KSA-16)")
		}
		return Fault{}, false
	}},

	// BR-KSA-34 — the counter contains only digits.
	{id: "BR-KSA-34", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.InvoiceCounter != nil && *inv.InvoiceCounter < 0 {
			return ksa("BR-KSA-34", "invoiceCounter", "the invoice counter value (KSA-16) contains only digits")
		}
		return Fault{}, false
	}},

	// BR-KSA-37 — seller building number must be 4 digits.
	{id: "BR-KSA-37", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		b := inv.Supplier.Address.Building
		if b == "" || len(b) != 4 || !isDigits(b) {
			return ksa("BR-KSA-37", "supplier.address.building",
				"the seller address building number must contain 4 digits")
		}
		return Fault{}, false
	}},

	// BR-KSA-38 — seller country code must be "SA".
	{id: "BR-KSA-38", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.Supplier.Address.CountryCode != "SA" {
			return ksa("BR-KSA-38", "supplier.address.countryCode",
				`the seller address country code (BT-40) must be "SA"`)
		}
		return Fault{}, false
	}},

	// BR-KSA-39 — seller VAT registration number (BT-31) must exist.
	{id: "BR-KSA-39", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.Supplier.VATNumber == "" {
			return ksa("BR-KSA-39", "supplier.vatNumber",
				"the invoice must contain the seller VAT registration number (BT-31) and/or seller group VAT registration number (KSA-18)")
		}
		return Fault{}, false
	}},

	// BR-KSA-40 — seller VAT registration number: 15 digits, first and last
	// are "3".
	{id: "BR-KSA-40", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if !validSellerVATNumber(inv.Supplier.VATNumber) {
			return ksa("BR-KSA-40", "supplier.vatNumber",
				"the seller VAT registration number (BT-31) must contain 15 digits and the first and the last digits must be \"3\"")
		}
		return Fault{}, false
	}},

	// BR-KSA-44 — buyer VAT registration number (when present, non-export):
	// 15 digits, first and last are "3".
	{id: "BR-KSA-44", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if !isExport(inv) && inv.Customer != nil && inv.Customer.VATNumber != "" && !validBuyerVATNumber(inv.Customer.VATNumber) {
			return ksa("BR-KSA-44", "customer.vatNumber",
				"the buyer VAT registration number (BT-48) must contain 15 digits and the first and the last digits must be \"3\"")
		}
		return Fault{}, false
	}},

	// BR-KSA-51 — line amount with VAT (KSA-12) = line net (BT-131) +
	// line VAT (KSA-11). Our builder derives the RoundingAmount; validation
	// re-derives and compares so drifted inputs cannot reach the XML.
	{id: "BR-KSA-51", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		for i, line := range inv.InvoiceLines {
			if _, err := xml.AddDecimal(line.LineExtensionAmount, line.TaxAmount); err != nil {
				return ksa("BR-KSA-51", linePath(i), "line amounts must be valid decimals to derive the line amount with VAT (KSA-12 = BT-131 + KSA-11)")
			}
		}
		return Fault{}, false
	}},

	// BR-KSA-52 — line VAT amount (KSA-11) mandatory on standard documents
	// (subtype 01, including their notes).
	{id: "BR-KSA-52", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if strings.HasPrefix(inv.InvoiceTypeCodeName, "01") {
			for i, line := range inv.InvoiceLines {
				if line.TaxAmount == "" {
					return ksa("BR-KSA-52", linePath(i), "the line VAT amount (KSA-11) is mandatory for tax invoice lines")
				}
			}
		}
		return Fault{}, false
	}},

	// BR-KSA-61 — previous invoice hash (KSA-13) must exist.
	{id: "BR-KSA-61", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.PreviousInvoiceHash == "" {
			return ksa("BR-KSA-61", "previousInvoiceHash",
				"the previous invoice hash (KSA-13) must exist in an invoice")
		}
		return Fault{}, false
	}},

	// BR-KSA-64 — seller additional number (KSA-23) must be 4 digits.
	{id: "BR-KSA-64", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		a := inv.Supplier.Address.AdditionalNumber
		if len(a) != 4 || !isDigits(a) {
			return ksa("BR-KSA-64", "supplier.address.additionalNumber",
				"the seller address additional number (KSA-23) must be 4 digits")
		}
		return Fault{}, false
	}},

	// BR-KSA-66 — seller postal code must be 5 digits.
	{id: "BR-KSA-66", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		p := inv.Supplier.Address.PostalCode
		if len(p) != 5 || !isDigits(p) {
			return ksa("BR-KSA-66", "supplier.address.postalCode",
				"the seller postal code (BT-38) must be 5 digits")
		}
		return Fault{}, false
	}},

	// BR-KSA-68 — tax currency code (BT-6) must exist. Our model emits it
	// from CurrencyCode; an empty currency breaks both currency codes.
	{id: "BR-KSA-68", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		if inv.CurrencyCode == "" {
			return ksa("BR-KSA-68", "currencyCode", "the tax currency code (BT-6) must exist in an invoice")
		}
		return Fault{}, false
	}},

	// --- EN 16931 core consistency (the TS production-readiness gate) ---

	// BR-CO-10 — BT-106 = Σ BT-131 (line nets).
	{id: "BR-CO-10", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		sum := xml.Decimal("0")
		for _, line := range inv.InvoiceLines {
			s, err := xml.AddDecimal(sum, line.LineExtensionAmount)
			if err != nil {
				return fault("BR-CO-10", SeverityError, "lines", "invoice line net amounts must be valid decimals")
			}
			sum = s
		}
		if amountDiffer(inv.LineExtensionAmount, sum) {
			return fault("BR-CO-10", SeverityError, "lineExtensionAmount",
				fmt.Sprintf("invoice line net amount total (BT-106) must equal Σ line net amounts (got %s, want %s)", inv.LineExtensionAmount, sum))
		}
		return Fault{}, false
	}},

	// BR-CO-13 — BT-109 = Σ BT-131 − document allowances + document charges.
	{id: "BR-CO-13", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		sum := xml.Decimal("0")
		for _, line := range inv.InvoiceLines {
			s, err := xml.AddDecimal(sum, line.LineExtensionAmount)
			if err != nil {
				return fault("BR-CO-13", SeverityError, "lines", "invoice line net amounts must be valid decimals")
			}
			sum = s
		}
		for _, charge := range inv.AllowanceCharges {
			value := charge.Amount
			var err error
			if charge.ChargeIndicator {
				sum, err = xml.AddDecimal(sum, value)
			} else {
				sum, err = subDecimal(sum, value)
			}
			if err != nil {
				return fault("BR-CO-13", SeverityError, "allowanceCharges", "allowance/charge amounts must be valid decimals")
			}
		}
		if amountDiffer(inv.TaxExclusiveAmount, sum) {
			return fault("BR-CO-13", SeverityError, "taxExclusiveAmount",
				fmt.Sprintf("tax exclusive amount (BT-109) must equal line nets minus allowances plus charges (got %s, want %s)", inv.TaxExclusiveAmount, sum))
		}
		return Fault{}, false
	}},

	// BR-CO-18 — BT-112 = BT-109 + BT-117.
	{id: "BR-CO-18", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		sum, err := xml.AddDecimal(inv.TaxExclusiveAmount, inv.TaxAmount)
		if err == nil && amountDiffer(inv.TaxInclusiveAmount, sum) {
			return fault("BR-CO-18", SeverityError, "taxInclusiveAmount",
				fmt.Sprintf("tax inclusive amount (BT-112) must equal tax exclusive + VAT (got %s, want %s)", inv.TaxInclusiveAmount, sum))
		}
		return Fault{}, false
	}},

	// BR-CO-15 — BT-115 = BT-112 − BT-113 (prepaid) + BT-114 (rounding).
	{id: "BR-CO-15", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		expected, err := xml.AddDecimal(inv.TaxInclusiveAmount, "0.00")
		if err != nil {
			return fault("BR-CO-15", SeverityError, "payableAmount", "amounts must be valid decimals")
		}
		if inv.PrepaidAmount != nil && *inv.PrepaidAmount != "" {
			if expected, err = subDecimal(expected, *inv.PrepaidAmount); err != nil {
				return fault("BR-CO-15", SeverityError, "prepaidAmount", "prepaid amount must be a valid decimal")
			}
		}
		if inv.RoundingAmount != nil && *inv.RoundingAmount != "" {
			if expected, err = xml.AddDecimal(expected, *inv.RoundingAmount); err != nil {
				return fault("BR-CO-15", SeverityError, "roundingAmount", "rounding amount must be a valid decimal")
			}
		}
		if amountDiffer(inv.PayableAmount, expected) {
			return fault("BR-CO-15", SeverityError, "payableAmount",
				fmt.Sprintf("payable amount (BT-115) must equal tax inclusive − prepaid + rounding (got %s, want %s)", inv.PayableAmount, expected))
		}
		return Fault{}, false
	}},

	// BR-S-08 — each standard-category VAT subtotal's taxable amount (BT-116)
	// equals Σ line nets minus allowances plus charges for that category.
	// Single-category documents (all of esellar's) compare globally.
	{id: "BR-S-08", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		for i, subtotal := range inv.TaxSubtotals {
			sum := xml.Decimal("0")
			for _, line := range inv.InvoiceLines {
				if line.TaxCategoryID != subtotal.TaxCategoryID {
					continue
				}
				s, err := xml.AddDecimal(sum, line.LineExtensionAmount)
				if err != nil {
					return fault("BR-S-08", SeverityError, taxSubtotalPath(i), "line net amounts must be valid decimals")
				}
				sum = s
			}
			for _, charge := range inv.AllowanceCharges {
				if charge.TaxCategoryID != "" && charge.TaxCategoryID != subtotal.TaxCategoryID {
					continue
				}
				var err error
				if charge.ChargeIndicator {
					sum, err = xml.AddDecimal(sum, charge.Amount)
				} else {
					sum, err = subDecimal(sum, charge.Amount)
				}
				if err != nil {
					return fault("BR-S-08", SeverityError, taxSubtotalPath(i), "allowance amounts must be valid decimals")
				}
			}
			if amountDiffer(subtotal.TaxableAmount, sum) {
				return fault("BR-S-08", SeverityError, taxSubtotalPath(i),
					fmt.Sprintf("VAT category taxable amount (BT-116) must equal the category line nets minus allowances plus charges (got %s, want %s)", subtotal.TaxableAmount, sum))
			}
		}
		return Fault{}, false
	}},

	// BR-CO-17 / BT-117 — category VAT within 1 minor unit of the exact
	// product taxable × percent (integer-cents comparison).
	{id: "BR-CO-17", check: func(inv *xml.InvoiceData, _ *options) (Fault, bool) {
		for i, subtotal := range inv.TaxSubtotals {
			taxableCents, err := decimalToCents(subtotal.TaxableAmount)
			if err != nil {
				return fault("BR-CO-17", SeverityError, taxSubtotalPath(i), "taxable amount must be a valid decimal")
			}
			taxCents, err := decimalToCents(subtotal.TaxAmount)
			if err != nil {
				return fault("BR-CO-17", SeverityError, taxSubtotalPath(i), "tax amount must be a valid decimal")
			}
			exact := xml.TaxFromTaxableCents(taxableCents, subtotal.Percent)
			diff := exact - taxCents
			if diff < 0 {
				diff = -diff
			}
			if diff >= 1 {
				percent, perr := xml.FormatPercentFixed2(subtotal.Percent)
				if perr != nil {
					percent = fmt.Sprintf("%v", subtotal.Percent)
				}
				return fault("BR-CO-17", SeverityError, taxSubtotalPath(i),
					fmt.Sprintf("category VAT (BT-117) must be within 1 minor unit of %s × %s%% (want %d cents, got %d cents)",
						subtotal.TaxableAmount, percent, exact, taxCents))
			}
		}
		return Fault{}, false
	}},
}

// noteRules validates the credit/debit-note-only fields.
func noteRules(note *xml.CreditNoteData) []Fault {
	var faults []Fault
	// BR-KSA-56 — billing reference ID (BT-25) mandatory for 381/383.
	if note.OriginalInvoiceNumber == "" {
		faults = append(faults, Fault{RuleID: "BR-KSA-56", Severity: SeverityError, Path: "originalInvoiceNumber",
			Message: "credit and debit notes must contain the billing reference ID (BT-25) of the original invoice"})
	}
	// BR-KSA-17 — the reason (KSA-10) for issuing is mandatory.
	if note.Reason == "" {
		faults = append(faults, Fault{RuleID: "BR-KSA-17", Severity: SeverityError, Path: "reason",
			Message: "debit and credit notes must contain the reason (KSA-10) for issuing"})
	}
	return faults
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func validNNPNESB(name string) bool {
	if len(name) != 7 {
		return false
	}
	// NN: the two-digit subtype "01" (standard/tax invoice) or "02"
	// (simplified) — the TS check is substring(@name,1,2) IN ('01','02').
	subtype := name[0:2]
	if subtype != "01" && subtype != "02" {
		return false
	}
	// PNESB: five 0/1 flags.
	for i := 2; i < 7; i++ {
		if name[i] != '0' && name[i] != '1' {
			return false
		}
	}
	return true
}

func isAlphanumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func isExport(inv *xml.InvoiceData) bool {
	return len(inv.InvoiceTypeCodeName) == 7 && inv.InvoiceTypeCodeName[4] == '1'
}

func linePath(i int) string        { return fmt.Sprintf("lines[%d].taxAmount", i) }
func taxSubtotalPath(i int) string { return fmt.Sprintf("taxSubtotals[%d]", i) }

// amountDiffer — the TS xmlAmountsDiffer gate: 2dp amounts differ when the
// cent distance exceeds 1 minor unit.
func amountDiffer(a, b xml.Decimal) bool {
	ac, aerr := decimalToCents(a)
	bc, berr := decimalToCents(b)
	if aerr != nil || berr != nil {
		return true
	}
	d := ac - bc
	if d < 0 {
		d = -d
	}
	return d > 1
}

// decimalToCents converts a 2dp decimal to integer cents (errors when the
// value carries more precision).
func decimalToCents(d xml.Decimal) (int64, error) {
	s := string(d)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var intPart, fracPart string
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		intPart, fracPart = s[:dot], s[dot+1:]
	} else {
		intPart = s
	}
	if len(fracPart) > 2 {
		return 0, fmt.Errorf("more than 2 fraction digits: %q", string(d))
	}
	for len(fracPart) < 2 {
		fracPart += "0"
	}
	if intPart == "" {
		intPart = "0"
	}
	var n int64
	for _, r := range intPart + fracPart {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid decimal %q", string(d))
		}
		n = n*10 + int64(r-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

// subDecimal subtracts b from a exactly (a + (−b)).
func subDecimal(a, b xml.Decimal) (xml.Decimal, error) {
	negated, err := negateDecimal(b)
	if err != nil {
		return "", err
	}
	return xml.AddDecimal(a, negated)
}

func negateDecimal(d xml.Decimal) (xml.Decimal, error) {
	s := strings.TrimSpace(string(d))
	if s == "" {
		return "", fmt.Errorf("empty decimal")
	}
	if strings.HasPrefix(s, "-") {
		return xml.Decimal(s[1:]), nil
	}
	return xml.Decimal("-" + s), nil
}
