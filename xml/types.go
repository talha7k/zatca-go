// ZATCA phase-2 UBL 2.1 document types — the Go twin of @talha7k/zatca
// dist/types.d.ts (InvoiceData / CreditNoteData and friends). Amounts are
// canonical xs:decimal lexical strings (Decimal), never floats.
package xml

// Document type codes (UN/CEFACT 1001 subset agreed for KSA).
const (
	TypeCodeInvoice    = "388" // tax invoice
	TypeCodeCreditNote = "381"
	TypeCodeDebitNote  = "383"
)

// KSA-2 invoice transaction (subtype) name prefixes.
const (
	SubtypeStandardTaxInvoice   = "0100000"
	SubtypeSimplifiedTaxInvoice = "0200000"
)

// ProfileIDReporting is BT-23 for the reporting (simplified) pipeline —
// packages/contracts ZATCA_PROFILE_ID.
const ProfileIDReporting = "reporting:1.0"

// ProfileIDClearance is BT-23 for the clearance pipeline.
const ProfileIDClearance = "clearance:1.0"

// GenesisPIH is the BR-KSA-26 chain seed: base64 of the UTF-8 hex text of
// sha256("0") — packages/contracts ZATCA_INITIAL_PREVIOUS_INVOICE_HASH.
const GenesisPIH = "NWZlY2ViNjZmZmM4NmYzOGQ5NTI3ODZjNmQ2OTZjNzljMmRiYzIzOWRkNGU5MWI0NjcyOWQ3M2EyN2ZiNTdlOQ=="

// PostalAddress mirrors the UBL address block. AdditionalNumber is KSA-23
// (cbc:PlotIdentification — BR-KSA-09/64 seller requirement); CountrySubentity
// is BT-80 (BR-KSA-10 buyer assert).
type PostalAddress struct {
	Street           string
	Building         string
	AdditionalNumber string
	District         string
	CountrySubentity string
	City             string
	PostalCode       string
	CountryCode      string
}

// SupplierInfo is the AccountingSupplierParty payload.
type SupplierInfo struct {
	NameAr    string
	NameEn    string
	VATNumber string
	CRNumber  string // optional — emitted as PartyIdentification schemeID="CRN"
	Address   PostalAddress
}

// CustomerInfo is the AccountingCustomerParty payload (nil customer on the
// document ⇒ the empty party element ZATCA requires for simplified B2C).
type CustomerInfo struct {
	Name      string
	VATNumber string
	Address   *PostalAddress
}

// TaxSubtotal is one VAT breakdown block (BG-23).
type TaxSubtotal struct {
	TaxableAmount Decimal
	TaxAmount     Decimal
	Percent       float64
	TaxCategoryID string // S | Z | E | O | AE
}

// AllowanceCharge is a document- or line-level allowance/charge block.
type AllowanceCharge struct {
	ChargeIndicator bool
	Reason          string
	Amount          Decimal
	TaxCategoryID   string   // optional — falls back to the enclosing category
	TaxPercent      *float64 // optional
}

// InvoiceLineItem is one cac:InvoiceLine.
type InvoiceLineItem struct {
	ID                  int
	Quantity            Decimal // BT-129 — unrestricted decimals
	UnitCode            string
	LineExtensionAmount Decimal // BT-131 — net
	TaxAmount           Decimal // KSA-11 — line VAT
	ItemName            string
	TaxCategoryID       string
	TaxPercent          float64 // BT-152
	PriceAmount         Decimal // BT-146 — full precision (≤10dp in XML)
	AllowanceCharges    []AllowanceCharge
}

// InvoiceData carries everything the UBL 2.1 invoice builder needs — the
// InvoiceData of @talha7k/zatca. Credit/debit notes extend it with the
// billing reference + reason (CreditNoteData).
type InvoiceData struct {
	InvoiceNumber       string
	UUID                string
	IssueDate           string  // BT-2, YYYY-MM-DD
	IssueTime           string  // BT-5, hh:mm:ss
	InvoiceTypeCode     string  // 388 | 381 | 383
	InvoiceTypeCodeName string  // KSA-2 NNPNESB: 0100000 | 0200000 | …
	ProfileID           string  // reporting:1.0 | clearance:1.0
	CurrencyCode        string  // SAR
	InvoiceCounter      *int    // KSA-16 (ICV) — nil = absent
	SupplyDate          *string // KSA-5 (cac:Delivery) — standard invoices
	PaymentMeansCode    *int    // BT-81 — standard invoices
	PreviousInvoiceHash string  // KSA-13 (PIH) — empty = absent

	Supplier SupplierInfo
	Customer *CustomerInfo

	LineExtensionAmount  Decimal  // BT-106 — Σ line nets (incl. allowances)
	TaxExclusiveAmount   Decimal  // BT-109
	TaxInclusiveAmount   Decimal  // BT-112
	AllowanceTotalAmount *Decimal // BT-107
	AllowanceCharges     []AllowanceCharge
	PrepaidAmount        *Decimal // BT-113
	RoundingAmount       *Decimal // BT-114
	PayableAmount        Decimal  // BT-115
	TaxAmount            Decimal  // BT-117
	TaxSubtotals         []TaxSubtotal
	InvoiceLines         []InvoiceLineItem
}

// CreditNoteData is a credit (381) or debit (383) note: the invoice shape
// plus the billing reference to the original invoice and the KSA-10 reason.
type CreditNoteData struct {
	InvoiceData
	OriginalInvoiceNumber string // BT-25 — mandatory for 381/383 (BR-KSA-56)
	OriginalInvoiceUUID   string
	OriginalInvoiceDate   string
	Reason                string // KSA-10 (BR-KSA-17)
}
