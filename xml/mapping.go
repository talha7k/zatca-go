// Order→invoice mapping discipline — the Go twin of the pure decisions in
// packages/contracts/src/zatca-order-xml.ts. The conventions ported here are
// the load-bearing ones:
//
//   - inclusive-VAT money is derived in INTEGER CENTS ONLY:
//     taxableCents = round(grossCents × 100/(100+rate)),
//     taxCents     = round(taxableCents × rate/100) — tax is derived from the
//     TAXABLE base (BR-CO-17), never from the charged gross;
//   - seller building number is 4 digits (KSA-17/BR-KSA-37), postal code 5
//     digits (BT-38/BR-KSA-66) — Arabic-Indic digits normalized first;
//   - issue dates never run ahead of today (BR-KSA-04).
package xml

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// RoundHalfTowardPositiveInfinityCents mirrors TS Math.round at the cents
// boundary: half rounds toward +∞ (Math.round(-0.5) === 0 — the TS calculators
// only ever feed positive magnitudes, but the semantics are pinned anyway).
func RoundHalfTowardPositiveInfinityCents(value float64) int64 {
	return int64(math.Floor(value + 0.5))
}

// TaxFromTaxableCents derives VAT cents from the taxable base:
// taxableCents × rate/100 rounded half-up at the cents boundary — the exact
// integer form of the TS calculateTaxFromTaxableAmount (bp = round(rate×100)).
func TaxFromTaxableCents(taxableCents int64, ratePercent float64) int64 {
	bp := RoundHalfTowardPositiveInfinityCents(ratePercent * 100)
	return RoundHalfTowardPositiveInfinityCents(float64(taxableCents) * float64(bp) / 10_000)
}

// VATFromInclusiveCents splits a VAT-inclusive gross (cents) into
// taxable + tax per the inclusive-VAT cents convention: the TAXABLE base is
// the anchor (rounded half-up), tax derives from it, and the filed inclusive
// total is taxable + tax — never the raw gross anchor (BR-CO-17: a drifted
// pair like 8.70/1.30 is rejected downstream by the BT-117 gate).
// grossCents 1000 @ 15% → 870 / 131 / 1001 (the TS doc's 10.00 → 8.70/1.31/10.01).
func VATFromInclusiveCents(grossCents int64, ratePercent float64) (taxableCents, taxCents, inclusiveCents int64) {
	if !(ratePercent > 0) {
		return grossCents, 0, grossCents
	}
	taxableCents = RoundHalfTowardPositiveInfinityCents(float64(grossCents) * 100 / (100 + ratePercent))
	taxCents = TaxFromTaxableCents(taxableCents, ratePercent)
	return taxableCents, taxCents, taxableCents + taxCents
}

// FormatCents renders integer cents as "DDD.DD" (integer math only — the
// golden-generator centsToDecimal twin for building Decimal inputs).
func FormatCents(cents int64) Decimal {
	sign := ""
	if cents < 0 {
		sign = "-"
		cents = -cents
	}
	return Decimal(fmt.Sprintf("%s%d.%02d", sign, cents/100, cents%100))
}

// normalizeArabicDigits maps Arabic-Indic (٠-٩) and Extended Arabic-Indic
// (۰-۹) digits to ASCII digits — the TS normalizeArabicDigits twin.
func normalizeArabicDigits(value string) string {
	var sb strings.Builder
	for _, r := range value {
		switch {
		case r >= '٠' && r <= '٩': // U+0660..U+0669
			sb.WriteRune(rune('0' + r - '٠'))
		case r >= '۰' && r <= '۹': // U+06F0..U+06F9
			sb.WriteRune(rune('0' + r - '۰'))
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func digitsOnly(value string) string {
	var sb strings.Builder
	for _, r := range normalizeArabicDigits(value) {
		if r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// NormalizeBuildingNumber enforces the 4-digit KSA-17 seller building number:
// digits extracted (Arabic digits normalized), zero-padded/sliced to 4; values
// with no digits pass through untouched (the TS normalizeZatcaBuildingNumber
// contract — callers decide fallbacks like "1234").
func NormalizeBuildingNumber(value string) string {
	digits := digitsOnly(value)
	if digits == "" {
		return value
	}
	return padLeftSlice(digits, 4)
}

// NormalizePostalCode enforces the 5-digit BT-38 seller postal code
// (TS normalizeZatcaPostalCode twin).
func NormalizePostalCode(value string) string {
	digits := digitsOnly(value)
	if digits == "" {
		return value
	}
	return padLeftSlice(digits, 5)
}

func padLeftSlice(digits string, width int) string {
	for len(digits) < width {
		digits = "0" + digits
	}
	if len(digits) > width {
		digits = digits[len(digits)-width:]
	}
	return digits
}

// IssueDateNotAfterToday clamps a business date to today (UTC) — the TS
// getZatcaIssueDateNotAfterToday twin (BR-KSA-04: issue date ≤ current date).
// An invalid candidate falls back to now.
func IssueDateNotAfterToday(candidate time.Time, now time.Time) string {
	if candidate.IsZero() {
		candidate = now
	}
	candidateISO := candidate.UTC().Format("2006-01-02")
	todayISO := now.UTC().Format("2006-01-02")
	if candidateISO > todayISO {
		return todayISO
	}
	return candidateISO
}
