// Exact decimal formatting for xs:decimal lexical strings — the Go twin of
// @talha7k/zatca dist/utils/xml.js (BigInt scaled-integer arithmetic; never
// floats). ZATCA amounts (BT-131/106/109/116…) carry max 2 fraction digits;
// unit price (BT-146) and quantity (BT-129) are unrestricted decimals. All
// arithmetic here operates on canonical decimal STRINGS with big.Int scaled
// magnitudes, rounding HALF-UP (away from zero) like the TS reference.
package xml

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strings"
)

// Decimal is a canonical xs:decimal lexical string (optional sign, digits,
// optional fraction) — never a float. Empty means "absent" for optional
// fields. The XML builder validates and formats every Decimal through
// FormatAmount / FormatUnitPrice before emission, so a malformed lexical form
// surfaces as a generation error exactly where the TS builder would throw.
type Decimal string

var decimalLexical = regexp.MustCompile(`^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$`)

type parsedDecimal struct {
	negative bool
	digits   *big.Int // magnitude as a scaled integer
	scale    int      // fraction digits
}

func parseDecimal(s Decimal, fn string) (parsedDecimal, error) {
	str := string(s)
	if !decimalLexical.MatchString(str) {
		return parsedDecimal{}, fmt.Errorf(
			"invalid decimal string passed to %s: %q — expected the canonical xs:decimal lexical form (optional sign, digits, optional . fraction)", fn, str)
	}
	negative := str[0] == '-'
	unsigned := str
	if negative || str[0] == '+' {
		unsigned = str[1:]
	}
	intPart, fracPart := unsigned, ""
	if dot := strings.IndexByte(unsigned, '.'); dot >= 0 {
		intPart, fracPart = unsigned[:dot], unsigned[dot+1:]
	}
	if intPart == "" {
		intPart = "0"
	}
	digits, ok := new(big.Int).SetString(intPart+fracPart, 10)
	if !ok {
		return parsedDecimal{}, fmt.Errorf("invalid decimal string passed to %s: %q", fn, str)
	}
	return parsedDecimal{negative: negative, digits: digits, scale: len(fracPart)}, nil
}

// rescaleHalfUp rescales a magnitude to target fraction digits, rounding
// HALF_UP (away from zero) — the TS rescaleHalfUp twin.
func rescaleHalfUp(digits *big.Int, scale, target int) *big.Int {
	if scale <= target {
		return new(big.Int).Mul(digits, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(target-scale)), nil))
	}
	div := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale-target)), nil)
	q, r := new(big.Int).QuoRem(digits, div, new(big.Int))
	r2 := new(big.Int).Mul(r, big.NewInt(2))
	if r2.Cmp(div) >= 0 {
		return q.Add(q, big.NewInt(1))
	}
	return q
}

// renderScaled renders a signed scaled magnitude as a decimal string with
// exactly scale fraction digits (no "-0") — the TS renderScaled twin.
func renderScaled(negative bool, magnitude *big.Int, scale int) string {
	s := magnitude.String()
	if len(s) <= scale {
		s = strings.Repeat("0", scale-len(s)+1) + s
	}
	var sb strings.Builder
	if negative && magnitude.Sign() != 0 {
		sb.WriteByte('-')
	}
	if scale > 0 {
		sb.WriteString(s[:len(s)-scale])
		sb.WriteByte('.')
		sb.WriteString(s[len(s)-scale:])
	} else {
		sb.WriteString(s)
	}
	return sb.String()
}

// NormalizeDecimalString validates a decimal string and returns its minimal
// canonical xs:decimal form: leading zeros stripped, trailing fraction zeros
// stripped, sign preserved, "-0" collapsed to "0" (e.g. "007.5000" → "7.5",
// "-0.00" → "0"). It errors on any input outside the canonical lexical form.
func NormalizeDecimalString(s Decimal) (string, error) {
	d, err := parseDecimal(s, "NormalizeDecimalString")
	if err != nil {
		return "", err
	}
	magnitude, scale := d.digits, d.scale
	ten := big.NewInt(10)
	rem := new(big.Int)
	for scale > 0 {
		q, r := new(big.Int).QuoRem(magnitude, ten, rem)
		if r.Sign() != 0 {
			break
		}
		magnitude, scale = q, scale-1
	}
	return renderScaled(d.negative, magnitude, scale), nil
}

// FormatAmount formats an amount (BT-131/106/109/116…) to exactly 2 decimal
// places with exact scaled-integer arithmetic, rounding HALF-UP — e.g.
// "2.675" → "2.68" — and "-0.00" normalizes to "0.00".
func FormatAmount(n Decimal) (string, error) {
	d, err := parseDecimal(n, "FormatAmount")
	if err != nil {
		return "", err
	}
	return renderScaled(d.negative, rescaleHalfUp(d.digits, d.scale, 2), 2), nil
}

// FormatUnitPrice formats a unit price / quantity (BT-146/BT-129) with up to
// 10 decimals: rounded HALF-UP beyond the 10th fraction digit, trailing zeros
// stripped down to the 2dp minimum, never floated
// (BR-KSA-EN16931-11 / ZATCA XML IG §9.3: the 2-decimal restriction applies
// to AMOUNTS, not the item net price).
func FormatUnitPrice(n Decimal) (string, error) {
	d, err := parseDecimal(n, "FormatUnitPrice")
	if err != nil {
		return "", err
	}
	magnitude := rescaleHalfUp(d.digits, d.scale, 10)
	scale := 10
	ten := big.NewInt(10)
	rem := new(big.Int)
	for scale > 2 {
		q, r := new(big.Int).QuoRem(magnitude, ten, rem)
		if r.Sign() != 0 {
			break
		}
		magnitude, scale = q, scale-1
	}
	return renderScaled(d.negative, magnitude, scale), nil
}

// mustPercent formats a percent (float64 — the TS number path) as
// FormatPercentFixed2 or panics; fragments convert at the builder boundary.
func mustPercent(p float64) string {
	out, err := FormatPercentFixed2(p)
	if err != nil {
		panic(fmt.Errorf("FormatPercentFixed2: %w", err))
	}
	return out
}

// FormatPercentFixed2 renders a percent/quantity float64 exactly the way the
// TS number path does (Number.prototype.toFixed(2)): the float64 is treated
// as its EXACT binary rational value and rounded half-toward-+∞ to 2
// fraction digits (the spec picks the larger n on a tie). big.Rat keeps the
// computation exact — no float re-rounding.
func FormatPercentFixed2(p float64) (string, error) {
	if math.IsNaN(p) || math.IsInf(p, 0) {
		return "", fmt.Errorf("cannot format non-finite percent %v", p)
	}
	rat := new(big.Rat).SetFloat64(p)
	// scaled = p * 100 as an exact rational.
	scaled := rat.Mul(rat, big.NewRat(100, 1))
	num, denom := scaled.Num(), scaled.Denom()
	// n = round-half-up(toward +∞)(p*100) = floor(p*100 + 1/2)
	//     = floor((2·num + denom) / (2·denom)) — exact on the rational.
	n := new(big.Int).Mul(num, big.NewInt(2))
	n.Add(n, denom)
	denom2 := new(big.Int).Lsh(denom, 1)
	n.Div(n, denom2) // big.Int Div floors toward -∞
	neg := n.Sign() < 0
	magnitude := new(big.Int).Abs(n)
	return renderScaled(neg, magnitude, 2), nil
}

// AddDecimal adds two decimals exactly (scaled-integer alignment) — the twin
// of the TS money.add used for line RoundingAmount (KSA-12 = BT-131 + KSA-11).
func AddDecimal(a, b Decimal) (Decimal, error) {
	xa, err := parseDecimal(a, "AddDecimal")
	if err != nil {
		return "", err
	}
	xb, err := parseDecimal(b, "AddDecimal")
	if err != nil {
		return "", err
	}
	scale := xa.scale
	if xb.scale > scale {
		scale = xb.scale
	}
	pow := func(target int) *big.Int {
		return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(target)), nil)
	}
	ad := new(big.Int).Mul(xa.digits, pow(scale-xa.scale))
	bd := new(big.Int).Mul(xb.digits, pow(scale-xb.scale))
	if xa.negative {
		ad.Neg(ad)
	}
	if xb.negative {
		bd.Neg(bd)
	}
	sum := new(big.Int).Add(ad, bd)
	negative := sum.Sign() < 0
	return Decimal(renderScaled(negative, new(big.Int).Abs(sum), scale)), nil
}
