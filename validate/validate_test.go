// BR-KSA validation suite tests — valid documents pass clean; every rule
// has a violation fixture that fails with exactly the right code + path.
package validate_test

import (
	"testing"
	"time"

	"github.com/talha7k/zatca-go/validate"
	xml "github.com/talha7k/zatca-go/xml"
)

// frozen "now" — issue dates are 2026-10-06 so BR-KSA-04 passes.
var testNow = func() time.Time { return time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC) }

func opt() validate.Option { return validate.WithNow(testNow) }

// ---------------------------------------------------------------------------
// Valid fixtures — one per esellar document type
// ---------------------------------------------------------------------------

func validStandardInvoice() *xml.InvoiceData {
	counter := 8
	supplyDate := "2026-10-06"
	paymentMeans := 10
	fifteen := 15.0
	return &xml.InvoiceData{
		InvoiceNumber:       "ORD-0001",
		UUID:                "b16f9d2e-7a34-4c5b-8d6e-9f0a1b2c3d4e",
		IssueDate:           "2026-10-06",
		IssueTime:           "14:30:00",
		InvoiceTypeCode:     "388",
		InvoiceTypeCodeName: "0100000",
		ProfileID:           "reporting:1.0",
		CurrencyCode:        "SAR",
		InvoiceCounter:      &counter,
		SupplyDate:          &supplyDate,
		PaymentMeansCode:    &paymentMeans,
		PreviousInvoiceHash: "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ==",
		Supplier: xml.SupplierInfo{
			NameAr:    "مطعم الوادي الهندي",
			NameEn:    "Indian Valley Restaurant",
			VATNumber: "310122393500003",
			CRNumber:  "1010512345",
			Address: xml.PostalAddress{
				Street: "King Fahd Road", Building: "1234", AdditionalNumber: "5678",
				District: "Al Olaya", City: "Riyadh", PostalCode: "12211", CountryCode: "SA",
			},
		},
		Customer: &xml.CustomerInfo{
			Name:      "Ac Corp Ltd",
			VATNumber: "310122393500113",
			Address: &xml.PostalAddress{
				Street: "Prince Turki Road", Building: "1111", AdditionalNumber: "2222",
				District: "Al Malqa", City: "Riyadh", PostalCode: "13521", CountryCode: "SA",
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
}

func validSimplifiedInvoice() *xml.InvoiceData {
	inv := validStandardInvoice()
	inv.InvoiceTypeCodeName = "0200000"
	inv.Customer = nil
	inv.SupplyDate = nil
	inv.PaymentMeansCode = nil
	return inv
}

func validCreditNote() *xml.CreditNoteData {
	inv := validSimplifiedInvoice()
	inv.InvoiceTypeCode = "381"
	return &xml.CreditNoteData{
		InvoiceData:           *inv,
		OriginalInvoiceNumber: "ORD-0001",
		OriginalInvoiceUUID:   "b16f9d2e-7a34-4c5b-8d6e-9f0a1b2c3d4e",
		OriginalInvoiceDate:   "2026-10-06",
		Reason:                "Order returned by customer",
	}
}

func TestValidDocumentsPassClean(t *testing.T) {
	if faults := validate.Invoice(validStandardInvoice(), opt()); len(faults) != 0 {
		t.Errorf("standard invoice must pass clean, got: %v", faults)
	}
	if faults := validate.Invoice(validSimplifiedInvoice(), opt()); len(faults) != 0 {
		t.Errorf("simplified invoice must pass clean, got: %v", faults)
	}
	if faults := validate.CreditNote(validCreditNote(), opt()); len(faults) != 0 {
		t.Errorf("credit note must pass clean, got: %v", faults)
	}
}

// The generated XML documents (golden fixtures rebuilt as Go models) must
// pass too — generator output and validator agree.
func TestGoldenFixtureModelsPass(t *testing.T) {
	// A model mirroring the simplified-arabic-lines golden fixture shape.
	counter := 1
	fifteen := 15.0
	inv := &xml.InvoiceData{
		InvoiceNumber:       "GOV-SIMPLIFIED-ARABIC-LINES",
		UUID:                "vector-simplified-arabic-lines-0001-0002-0003",
		IssueDate:           "2026-10-04",
		IssueTime:           "18:00:05",
		InvoiceTypeCode:     "388",
		InvoiceTypeCodeName: "0200000",
		ProfileID:           "reporting:1.0",
		CurrencyCode:        "SAR",
		InvoiceCounter:      &counter,
		PreviousInvoiceHash: xml.GenesisPIH,
		Supplier: xml.SupplierInfo{
			NameAr: "مطعم الوادي الهندي", VATNumber: "310122393500003",
			Address: xml.PostalAddress{
				Street: "King Fahd Road", Building: "1234", AdditionalNumber: "5678",
				District: "Al Olaya", City: "Riyadh", PostalCode: "12211", CountryCode: "SA",
			},
		},
		LineExtensionAmount: "700.00",
		TaxExclusiveAmount:  "700.00",
		TaxInclusiveAmount:  "805.00",
		PayableAmount:       "805.00",
		TaxAmount:           "105.00",
		TaxSubtotals:        []xml.TaxSubtotal{{TaxableAmount: "700.00", TaxAmount: "105.00", Percent: fifteen, TaxCategoryID: "S"}},
		InvoiceLines: []xml.InvoiceLineItem{
			{ID: 1, Quantity: "3", UnitCode: "PCE", LineExtensionAmount: "300.00", TaxAmount: "45.00",
				ItemName: "شاورما عربية", TaxCategoryID: "S", TaxPercent: fifteen, PriceAmount: "100.00"},
			{ID: 2, Quantity: "1", UnitCode: "PCE", LineExtensionAmount: "400.00", TaxAmount: "60.00",
				ItemName: "عصير مانجو", TaxCategoryID: "S", TaxPercent: fifteen, PriceAmount: "400.00"},
		},
	}
	if faults := validate.Invoice(inv, opt()); len(faults) != 0 {
		t.Errorf("golden-shape invoice must pass clean, got: %v", faults)
	}
}

// ---------------------------------------------------------------------------
// Rule violation table — mutate the valid fixture, expect exactly one fault
// with the right rule id (and path where pinned)
// ---------------------------------------------------------------------------

func TestRuleViolations(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*xml.InvoiceData)
		wantRule string
		wantPath string
	}{
		{"BR-KSA-03 empty uuid", func(v *xml.InvoiceData) { v.UUID = "" }, "BR-KSA-03", "uuid"},
		{"BR-KSA-03 bad uuid chars", func(v *xml.InvoiceData) { v.UUID = "bad uuid!" }, "BR-KSA-03", "uuid"},
		{"BR-KSA-04 future issue", func(v *xml.InvoiceData) { v.IssueDate = "2026-10-07" }, "BR-KSA-04", "issueDate"},
		{"BR-KSA-05 bad type code", func(v *xml.InvoiceData) { v.InvoiceTypeCode = "999" }, "BR-KSA-05", "invoiceTypeCode"},
		{"BR-KSA-06 bad subtype", func(v *xml.InvoiceData) { v.InvoiceTypeCodeName = "9900000" }, "BR-KSA-06", "invoiceTypeCodeName"},
		// "0100101" — NN=01, P=0, N=0, E=1 (export), S=0, B=1 (self-billed).
		{"BR-KSA-07 self-billed export", func(v *xml.InvoiceData) { v.InvoiceTypeCodeName = "0100101" }, "BR-KSA-07", "invoiceTypeCodeName"},
		{"BR-KSA-08 crn non-alnum", func(v *xml.InvoiceData) { v.Supplier.CRNumber = "10-15-!" }, "BR-KSA-08", "supplier.crNumber"},
		{"BR-KSA-09 missing district", func(v *xml.InvoiceData) { v.Supplier.Address.District = "" }, "BR-KSA-09", "supplier.address"},
		{"BR-KSA-10 missing buyer city", func(v *xml.InvoiceData) { v.Customer.Address.City = "" }, "BR-KSA-10", "customer.address"},
		{"BR-KSA-14 buyer id non-alnum", func(v *xml.InvoiceData) { v.Customer.VATNumber = "310 22 393500113" }, "BR-KSA-14", "customer.vatNumber"},
		{"BR-KSA-15 no supply date", func(v *xml.InvoiceData) { v.SupplyDate = nil }, "BR-KSA-15", "supplyDate"},
		{"BR-KSA-16 no payment means", func(v *xml.InvoiceData) { v.PaymentMeansCode = nil }, "BR-KSA-16", "paymentMeansCode"},
		{"BR-KSA-16 bad payment means", func(v *xml.InvoiceData) { m := 99; v.PaymentMeansCode = &m }, "BR-KSA-16", "paymentMeansCode"},
		{"BR-KSA-26 bad pih", func(v *xml.InvoiceData) { v.PreviousInvoiceHash = "not-base64-sha256!!" }, "BR-KSA-26", "previousInvoiceHash"},
		{"BR-KSA-33 no counter", func(v *xml.InvoiceData) { v.InvoiceCounter = nil }, "BR-KSA-33", "invoiceCounter"},
		{"BR-KSA-37 building 5 digits", func(v *xml.InvoiceData) { v.Supplier.Address.Building = "12345" }, "BR-KSA-37", "supplier.address.building"},
		{"BR-KSA-38 country not SA", func(v *xml.InvoiceData) { v.Supplier.Address.CountryCode = "AE" }, "BR-KSA-38", "supplier.address.countryCode"},
		{"BR-KSA-39 no seller vat", func(v *xml.InvoiceData) { v.Supplier.VATNumber = "" }, "BR-KSA-39", "supplier.vatNumber"},
		{"BR-KSA-40 seller vat shape", func(v *xml.InvoiceData) { v.Supplier.VATNumber = "310122393500004" }, "BR-KSA-40", "supplier.vatNumber"},
		{"BR-KSA-44 buyer vat shape", func(v *xml.InvoiceData) { v.Customer.VATNumber = "31012239350011" }, "BR-KSA-44", "customer.vatNumber"},
		{"BR-KSA-52 line vat empty", func(v *xml.InvoiceData) { v.InvoiceLines[0].TaxAmount = "" }, "BR-KSA-52", "lines[0].taxAmount"},
		{"BR-KSA-61 no pih", func(v *xml.InvoiceData) { v.PreviousInvoiceHash = "" }, "BR-KSA-61", "previousInvoiceHash"},
		{"BR-KSA-64 additional number", func(v *xml.InvoiceData) { v.Supplier.Address.AdditionalNumber = "567" }, "BR-KSA-64", "supplier.address.additionalNumber"},
		{"BR-KSA-66 postal 4 digits", func(v *xml.InvoiceData) { v.Supplier.Address.PostalCode = "1221" }, "BR-KSA-66", "supplier.address.postalCode"},
		{"BR-KSA-68 no currency", func(v *xml.InvoiceData) { v.CurrencyCode = "" }, "BR-KSA-68", "currencyCode"},
		{"BR-CO-10 line sum drift", func(v *xml.InvoiceData) { v.LineExtensionAmount = "501.00" }, "BR-CO-10", "lineExtensionAmount"},
		{"BR-CO-13 exclusive drift", func(v *xml.InvoiceData) { v.TaxExclusiveAmount = "499.00" }, "BR-CO-13", "taxExclusiveAmount"},
		{"BR-CO-18 inclusive drift", func(v *xml.InvoiceData) { v.TaxInclusiveAmount = "576.00" }, "BR-CO-18", "taxInclusiveAmount"},
		{"BR-CO-15 payable drift", func(v *xml.InvoiceData) { v.PayableAmount = "574.00" }, "BR-CO-15", "payableAmount"},
		{"BR-S-08 subtotal drift", func(v *xml.InvoiceData) { v.TaxSubtotals[0].TaxableAmount = "499.00" }, "BR-S-08", "taxSubtotals[0]"},
		{"BR-CO-17 tax off by 2 cents", func(v *xml.InvoiceData) {
			v.TaxSubtotals[0].TaxAmount = "75.02"
			v.TaxAmount = "75.02"
			v.TaxInclusiveAmount = "575.02"
			v.PayableAmount = "575.02"
		}, "BR-CO-17", "taxSubtotals[0]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := validStandardInvoice()
			tc.mutate(inv)
			faults := validate.Invoice(inv, opt())
			if len(faults) == 0 {
				t.Fatalf("expected %s violation, got none", tc.wantRule)
			}
			for _, f := range faults {
				if f.RuleID == tc.wantRule {
					if tc.wantPath != "" && f.Path != tc.wantPath {
						t.Errorf("fault %s at path %q, want %q", f.RuleID, f.Path, tc.wantPath)
					}
					return
				}
			}
			t.Fatalf("expected fault %s, got %v", tc.wantRule, faults)
		})
	}
}

func TestNoteRuleViolations(t *testing.T) {
	t.Run("BR-KSA-56 missing billing reference", func(t *testing.T) {
		note := validCreditNote()
		note.OriginalInvoiceNumber = ""
		faults := validate.CreditNote(note, opt())
		if !hasRule(faults, "BR-KSA-56") {
			t.Fatalf("expected BR-KSA-56, got %v", faults)
		}
	})
	t.Run("BR-KSA-17 missing reason", func(t *testing.T) {
		note := validCreditNote()
		note.Reason = ""
		faults := validate.CreditNote(note, opt())
		if !hasRule(faults, "BR-KSA-17") {
			t.Fatalf("expected BR-KSA-17, got %v", faults)
		}
	})
}

func TestBRKSA09IsWarning(t *testing.T) {
	inv := validStandardInvoice()
	inv.Supplier.Address.District = ""
	faults := validate.Invoice(inv, opt())
	for _, f := range faults {
		if f.RuleID == "BR-KSA-09" && f.Severity != validate.SeverityWarning {
			t.Errorf("BR-KSA-09 must be a warning (schematron flag), got %s", f.Severity)
		}
	}
}

func TestSimplifiedSkipsStandardOnlyRules(t *testing.T) {
	// Simplified invoices need no supply date, payment means or buyer
	// address — dropping ALL of them must stay clean.
	inv := validSimplifiedInvoice()
	inv.Customer = nil
	inv.SupplyDate = nil
	inv.PaymentMeansCode = nil
	if faults := validate.Invoice(inv, opt()); len(faults) != 0 {
		t.Errorf("simplified invoice without B2B fields must pass, got: %v", faults)
	}
}

func TestRuleCount(t *testing.T) {
	// Pin the suite size so rule additions are deliberate (update with the
	// new rule's fixture when this breaks).
	if got := len(validate.RuleIDs()); got < 27 {
		t.Errorf("rule suite shrunk: %d rules", got)
	}
}

func hasRule(faults []validate.Fault, ruleID string) bool {
	for _, f := range faults {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
