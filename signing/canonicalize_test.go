// Canonicalization tests — the Go C14N port must reproduce the TS
// (xmldsigjs XmlCanonicalizer, inclusive mode) output byte-exactly.
//
// Primary oracle: the Z6 golden fixtures (testdata/xml/*.canonical.xml) were
// frozen from the prod-proven TS canonicalizeForHash — the Go canonicalizer
// must turn the raw fixtures into those exact bytes.
package signing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join("..", "testdata", filepath.Join(parts...))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// TestCanonicalizeForHashReproducesTSGolden walks every Z6 fixture and
// requires the Go canonicalizer to reproduce the TS-frozen canonical bytes.
func TestCanonicalizeForHashReproducesTSGolden(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "testdata", "xml"))
	if err != nil {
		t.Fatalf("list fixtures: %v", err)
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".canonical.xml") {
			continue
		}
		count++
		t.Run(strings.TrimSuffix(name, ".xml"), func(t *testing.T) {
			id := strings.TrimSuffix(name, ".xml")
			raw := readTestdata(t, "xml", name)
			want := readTestdata(t, "xml", id+".canonical.xml")
			got, err := CanonicalizeForHash(raw)
			if err != nil {
				t.Fatalf("CanonicalizeForHash: %v", err)
			}
			if got.Canonical != want {
				t.Fatalf("canonical mismatch for %s\nwant (%d bytes):\n%q\n\ngot (%d bytes):\n%q",
					id, len(want), want, len(got.Canonical), got.Canonical)
			}
			sum := sha256.Sum256([]byte(got.Canonical))
			if got.HashHex != hex.EncodeToString(sum[:]) || got.HashBase64 != base64.StdEncoding.EncodeToString(sum[:]) {
				t.Fatalf("hash fields inconsistent with canonical bytes for %s", id)
			}
			// The canonical form must not carry the stripped blocks.
			for _, banned := range []string{"<ext:UBLExtensions>", "<cac:Signature>"} {
				if strings.Contains(got.Canonical, banned) {
					t.Fatalf("canonical form still carries %s for %s", banned, id)
				}
			}
		})
	}
	if count == 0 {
		t.Fatal("no Z6 xml fixtures found — the canonicalizer oracle is empty")
	}
}

// TestCanonicalizeXMLFragmentSignedInfo pins the hand-derived canonical form
// of a minimal SignedInfo fragment: namespace declarations sorted by prefix
// (cac, cbc, ds, ext), self-closing elements expanded, attribute untouched.
func TestCanonicalizeXMLFragmentSignedInfo(t *testing.T) {
	input := `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/></ds:SignedInfo>`
	want := `<ds:SignedInfo xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2">` +
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod>` +
		`</ds:SignedInfo>`
	got, err := CanonicalizeXML(input)
	if err != nil {
		t.Fatalf("CanonicalizeXML: %v", err)
	}
	if got != want {
		t.Fatalf("fragment canonical mismatch\nwant: %q\n\ngot:  %q", want, got)
	}
}

// TestCanonicalizeXMLEscaping pins the xmldsigjs NormalizeString behavior:
// text escapes < > & (NOT quotes); attribute values escape < & " plus
// tab/newline character references (NOT >).
func TestCanonicalizeXMLEscaping(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "text gt is escaped",
			input: "<a><t>2 &gt; 1 &amp; x</t></a>",
			want:  "<a><t>2 &gt; 1 &amp; x</t></a>",
		},
		{
			name:  "attr quote escaped, gt kept raw (engine escapes > in text only)",
			input: `<a x="p&quot;q&gt;r"/>`,
			want:  `<a x="p&quot;q>r"></a>`,
		},
		{
			name:  "attr tab newline char refs preserved",
			input: `<a x="p&#x9;q&#xA;r"/>`,
			want:  `<a x="p&#x9;q&#xA;r"></a>`,
		},
		{
			name:  "empty element expanded",
			input: "<a><b/></a>",
			want:  "<a><b></b></a>",
		},
		{
			name:  "xml declaration dropped",
			input: `<?xml version="1.0" encoding="UTF-8"?><a/>`,
			want:  "<a></a>",
		},
		{
			name:  "comments dropped",
			input: "<a><!-- note --><b/></a>",
			want:  "<a><b></b></a>",
		},
		{
			name:  "pre-root whitespace dropped",
			input: "\n  <a>\n  </a>\n",
			want:  "<a>\n  </a>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalizeXML(tc.input)
			if err != nil {
				t.Fatalf("CanonicalizeXML: %v", err)
			}
			if got != tc.want {
				t.Fatalf("want %q got %q", tc.want, got)
			}
		})
	}
}

// TestCanonicalizeXMLNamespaceRedundancy pins inclusive-C14N namespace
// rendering: declared namespaces render at the apex element only; descendants
// inheriting them do not re-render; a re-declaration to a NEW uri renders.
func TestCanonicalizeXMLNamespaceRedundancy(t *testing.T) {
	input := `<a xmlns:p="urn:p" xmlns:q="urn:q"><p:b><c/></p:b><p:b xmlns:p="urn:p2"/></a>`
	want := `<a xmlns:p="urn:p" xmlns:q="urn:q">` +
		`<p:b><c></c></p:b>` +
		`<p:b xmlns:p="urn:p2"></p:b>` +
		`</a>`
	got, err := CanonicalizeXML(input)
	if err != nil {
		t.Fatalf("CanonicalizeXML: %v", err)
	}
	if got != want {
		t.Fatalf("want %q got %q", want, got)
	}
}

// TestCanonicalizeForHashStripsQROnly pins the QR-targeted strip: an
// AdditionalDocumentReference whose cbc:ID is NOT 'QR' must survive.
func TestCanonicalizeForHashStripsQROnly(t *testing.T) {
	input := `<a xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">` +
		`<cac:AdditionalDocumentReference><cbc:ID>QR</cbc:ID><x/></cac:AdditionalDocumentReference>` +
		`<cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID></cac:AdditionalDocumentReference></a>`
	got, err := CanonicalizeForHash(input)
	if err != nil {
		t.Fatalf("CanonicalizeForHash: %v", err)
	}
	want := `<a xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">` +
		`<cac:AdditionalDocumentReference><cbc:ID>ICV</cbc:ID></cac:AdditionalDocumentReference></a>`
	if got.Canonical != want {
		t.Fatalf("want %q got %q", want, got.Canonical)
	}
}
