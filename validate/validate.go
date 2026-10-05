// Package validate implements the ZATCA BR-KSA business-rule suite for the
// invoice types esellar issues: standard tax invoices (KSA-2 subtype
// 0100000), simplified tax invoices (0200000) and their credit/debit notes.
//
// Rules are translated from the authoritative ZATCA schematron shipped in
// the Compliance & Enablement Toolbox
// (20210819_ZATCA_E-invoice_Validation_Rules.xsl — rule ids, assert text and
// flag/severity extracted verbatim), with github.com/invopop/gobl.sa.zatca
// used as a STRUCTURE reference only (never imported): their addon proves
// which rules are enforceable without a full UBL DOM and how fault
// identities are shaped.
//
// Faults are structured: rule id, severity (the schematron flag), a message
// close to the upstream assert text, and a dotted path into the document
// model. Validation is semantic — it runs on the xml.InvoiceData model
// BEFORE generation (pre-issuance gates), complementing the SDK's own XSD +
// schematron pass on the signed XML (conformance harness).
package validate

import (
	"regexp"
	"strings"
	"time"

	xml "github.com/talha7k/zatca-go/xml"
)

// Severity mirrors the schematron failed-assert flag.
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Fault is one rule violation.
type Fault struct {
	// RuleID is the ZATCA rule identity, e.g. "BR-KSA-15".
	RuleID string `json:"rule_id"`
	// Severity is "error" or "warning" (the schematron flag).
	Severity Severity `json:"severity"`
	// Message paraphrases the upstream assert text.
	Message string `json:"message"`
	// Path is a dotted path into the document model,
	// e.g. "supplier.address.building" or "lines[0].taxAmount".
	Path string `json:"path"`
}

func (f Fault) Error() string {
	return f.RuleID + " (" + string(f.Severity) + ") at " + f.Path + ": " + f.Message
}

// options carries the injectable environment.
type options struct {
	now func() time.Time
}

// Option configures Validate.
type Option func(*options)

// WithNow overrides the clock (BR-KSA-04 compares the issue date against
// today). Defaults to time.Now.
func WithNow(now func() time.Time) Option {
	return func(o *options) { o.now = now }
}

// IsStandard reports whether the document is a standard tax invoice:
// type 388 with KSA-2 subtype prefix 01 (tax invoice + associated notes).
func IsStandard(inv *xml.InvoiceData) bool {
	return inv.InvoiceTypeCode == xml.TypeCodeInvoice && strings.HasPrefix(inv.InvoiceTypeCodeName, "01")
}

// IsSimplified reports whether the document is simplified (subtype 02).
func IsSimplified(inv *xml.InvoiceData) bool {
	return strings.HasPrefix(inv.InvoiceTypeCodeName, "02")
}

// IsNote reports whether the document is a credit (381) or debit (383) note.
func IsNote(inv *xml.InvoiceData) bool {
	return inv.InvoiceTypeCode == xml.TypeCodeCreditNote || inv.InvoiceTypeCode == xml.TypeCodeDebitNote
}

// Invoice validates any esellar document (invoice or credit/debit note —
// pass a *CreditNoteData's embedded InvoiceData plus the note fields via
// CreditNote for note-specific rules). It returns every violation, in rule
// order; an empty slice means the document satisfies the suite.
func Invoice(inv *xml.InvoiceData, opts ...Option) []Fault {
	var o options
	o.now = time.Now
	for _, opt := range opts {
		opt(&o)
	}
	var faults []Fault
	for _, r := range rules {
		if f, violated := r.check(inv, &o); violated {
			faults = append(faults, f)
		}
	}
	return faults
}

// RuleIDs lists every rule identity in the suite, in evaluation order —
// documentation and the suite-size pin for tests.
func RuleIDs() []string {
	ids := make([]string, 0, len(rules)+2)
	for _, r := range rules {
		ids = append(ids, r.id)
	}
	return append(ids, "BR-KSA-17", "BR-KSA-56") // note-only rules
}

// CreditNote validates a credit (381) or debit (383) note: the common
// invoice suite plus the note-specific rules (BR-KSA-17 reason,
// BR-KSA-56 billing reference).
func CreditNote(note *xml.CreditNoteData, opts ...Option) []Fault {
	faults := Invoice(&note.InvoiceData, opts...)
	faults = append(faults, noteRules(note)...)
	return faults
}

// ---------------------------------------------------------------------------
// Shared predicates
// ---------------------------------------------------------------------------

var uuidPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isBase64 checks base64 decodability — the schematron BR-KSA-26 assert is
// presence + non-empty + mimeCode text/plain; the base64-SHA-256 shape is
// the descriptive contract (the genesis PIH sentinel is base64 of the
// 64-byte hex TEXT of sha256("0"), so PIH values legitimately decode to
// 32- or 64-byte forms — decodability is the enforceable invariant).
func isBase64(s string) bool {
	_, err := base64Std.DecodeString(s)
	return err == nil && s != ""
}

// validSellerVATNumber: 15 digits, first and last are "3" (BR-KSA-40).
func validSellerVATNumber(v string) bool {
	return len(v) == 15 && isDigits(v) && v[0] == '3' && v[14] == '3'
}

// validBuyerVATNumber: same shape (BR-KSA-44).
func validBuyerVATNumber(v string) bool { return validSellerVATNumber(v) }

// paymentMeansCodes lists BT-81 values ZATCA accepts (BR-KSA-16).
var paymentMeansCodes = map[int]bool{10: true, 30: true, 42: true, 48: true, 1: true}
