// Invoice hashing + XML escaping re-exports for the xml package: hashing is
// SHA-256 over the canonical XML bytes (canonicalization itself stays
// TS-owned — callers pass its `canonical` output); EscapeXML is exported for
// callers that patch minted documents.
package xml

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// InvoiceHash is the SHA-256 digest of the canonical XML in both encodings.
type InvoiceHash struct {
	Hex    string
	Base64 string
}

// HashCanonical computes the ZATCA invoice hash: SHA-256 over the canonical
// XML string (UTF-8 bytes) — the twin of the root zatca.HashCanonical,
// mirrored here so the xml package stands alone.
func HashCanonical(canonical string) InvoiceHash {
	sum := sha256.Sum256([]byte(canonical))
	return InvoiceHash{
		Hex:    hex.EncodeToString(sum[:]),
		Base64: base64.StdEncoding.EncodeToString(sum[:]),
	}
}

// EscapeXML escapes the five XML special characters (the TS escapeXml twin).
func EscapeXML(s string) string { return escapeXml(s) }
