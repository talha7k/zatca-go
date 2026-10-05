// Canonicalization — the ZATCA signed/invoiced-XML C14N subset, in Go.
//
// This is a byte-exact port of the canonicalizer the TS signing pipeline
// drives (xmldsigjs XmlCanonicalizer(withComments=false, excC14N=false) —
// INCLUSIVE canonicalization, the engine behind both the invoice hash path
// `canonicalizeForHash` and the SignedInfo digest path `canonicalizeXml`).
// The port mirrors the engine's exact semantics, including its quirks
// (namespace-declaration rendering rules, attribute ordering, escaping
// tables) because ZATCA hashes are computed over these bytes.
//
// Scope (deliberate, documented):
//   - Inclusive C14N only (exclusive C14N / InclusiveNamespaces PrefixList
//     is unreachable: the TS pipeline never constructs that mode).
//   - Comments are always dropped (withComments=false).
//   - The DOCTYPE/document-type node is dropped (the TS canonicalizer skips
//     it); DTD internal subsets are not validated.
//   - Unicode NFC normalization is NOT applied (the minted documents are
//     composed-form by construction; the TS engine does not normalize
//     either).
//   - Attribute values containing literal TAB/LF rely on the tokenizer's
//     attribute-value normalization, matching the XML spec behavior of the
//     TS DOMParser for the documents this package mints.
package signing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

// UBL namespace URIs the ZATCA exclusion transforms target.
const (
	nsUBLCommonExtensionComponents = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"
	nsUBLCommonAggregateComponents = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
	nsUBLCommonBasicComponents     = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
	xmlNamespaceURI                = "http://www.w3.org/XML/1998/namespace"
	xmlnsNamespaceURI              = "http://www.w3.org/2000/xmlns/"
)

// CanonicalHash carries the canonical form of a document plus its SHA-256 in
// both encodings — the twin of the TS canonicalizeForHash return shape.
type CanonicalHash struct {
	// Canonical is the canonical XML (UTF-8 text).
	Canonical string
	// HashHex is the lowercase hex SHA-256 of the canonical bytes.
	HashHex string
	// HashBase64 is the standard-base64 SHA-256 of the canonical bytes —
	// the format ZATCA uses (QR tag 6, PIH, API invoiceHash).
	HashBase64 string
}

// hashCanonicalBytes seals the canonical string into a CanonicalHash.
func hashCanonicalBytes(canonical string) CanonicalHash {
	sum := sha256.Sum256([]byte(canonical))
	return CanonicalHash{
		Canonical:  canonical,
		HashHex:    hex.EncodeToString(sum[:]),
		HashBase64: base64.StdEncoding.EncodeToString(sum[:]),
	}
}

// CanonicalizeXML canonicalizes a well-formed XML string (document or
// standalone fragment — the SignedInfo digest path) with the inclusive
// engine. It is the twin of the TS canonicalizeXml helper.
func CanonicalizeXML(xmlString string) (string, error) {
	c := newCanonicalizer()
	if err := c.walkDocument(xmlString, false); err != nil {
		return "", err
	}
	if !c.sawElement {
		return "", fmt.Errorf("signing: XML contains no elements")
	}
	return c.out.String(), nil
}

// CanonicalizeForHash computes the ZATCA invoice-hash canonical form: the
// UBLExtensions elements, cac:Signature elements and the QR
// AdditionalDocumentReference (cbc:ID = 'QR') are removed, then the
// document is canonized. It is the twin of the TS canonicalizeForHash with
// stripQR=true.
func CanonicalizeForHash(xmlString string) (CanonicalHash, error) {
	c := newCanonicalizer()
	if err := c.walkDocument(xmlString, true); err != nil {
		return CanonicalHash{}, err
	}
	if !c.sawElement {
		return CanonicalHash{}, fmt.Errorf("signing: XML contains no elements")
	}
	return hashCanonicalBytes(c.out.String()), nil
}

// ---------------------------------------------------------------------------
// Canonicalizer state
// ---------------------------------------------------------------------------

type c14nState int

const (
	c14nBeforeDocElement c14nState = iota
	c14nInsideDocElement
	c14nAfterDocElement
)

type nsEntry struct {
	prefix string // "" = default namespace (the TS engine normalizes null to "")
	uri    string
}

type canonicalizer struct {
	out        strings.Builder
	state      c14nState
	visible    []nsEntry // rendered-namespace stack; lookup scans top-down
	sawElement bool
}

func newCanonicalizer() *canonicalizer { return &canonicalizer{} }

// pushNS appends a rendered namespace entry (mirrors NamespaceManager.Add
// with its null→"" normalization).
func (c *canonicalizer) pushNS(prefix, uri string) {
	if prefix == "" {
		// keep "" (the normalized default-marker)
	}
	c.visible = append(c.visible, nsEntry{prefix: prefix, uri: uri})
}

func (c *canonicalizer) popNS(count int) {
	c.visible = c.visible[:len(c.visible)-count]
}

// isNamespaceRendered mirrors XmlCanonicalizer.IsNamespaceRendered.
func (c *canonicalizer) isNamespaceRendered(prefix, uri string) bool {
	if prefix == "" && uri == "" {
		return true
	}
	if prefix == "xml" && uri == xmlNamespaceURI {
		return true
	}
	for i := len(c.visible) - 1; i >= 0; i-- {
		if c.visible[i].prefix == prefix {
			return c.visible[i].uri == uri
		}
	}
	return false
}

// normalizeString mirrors XmlCanonicalizer.NormalizeString; asAttr selects
// the attribute-value escaping table.
func normalizeString(input string, asAttr bool) string {
	if input == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(input) + 8)
	for _, ch := range input {
		switch {
		case ch == '<':
			sb.WriteString("&lt;") // attribute OR text
		case ch == '>' && !asAttr:
			sb.WriteString("&gt;") // text only
		case ch == '&':
			sb.WriteString("&amp;")
		case ch == '"' && asAttr:
			sb.WriteString("&quot;")
		case ch == '\t' && asAttr:
			sb.WriteString("&#x9;")
		case ch == '\n' && asAttr:
			sb.WriteString("&#xA;")
		case ch == '\r':
			sb.WriteString("&#xD;")
		default:
			sb.WriteRune(ch)
		}
	}
	return sb.String()
}

// startElement opens an element: '<' qname, rendered namespaces, sorted
// attributes, '>'. It returns the number of namespace entries pushed (the
// caller pops them at the matching end element) and whether this element
// STARTED the document element (the engine's AfterDocElement transition
// fires when that element closes).
func (c *canonicalizer) startElement(qname string, elemPrefix, elemURI string, attrs []c14nAttr) (pushed int, first bool) {
	first = c.state == c14nBeforeDocElement
	if first {
		c.state = c14nInsideDocElement
	}
	c.sawElement = true
	c.out.WriteByte('<')
	c.out.WriteString(qname)
	pushed = c.writeNamespacesAxis(elemPrefix, elemURI, attrs)
	c.writeAttributesAxis(attrs)
	c.out.WriteByte('>')
	return pushed, first
}

func (c *canonicalizer) endElement(qname string, pushed int, first bool) {
	c.out.WriteString("</")
	c.out.WriteString(qname)
	c.out.WriteByte('>')
	if first {
		c.state = c14nAfterDocElement
	}
	if pushed > 0 {
		c.popNS(pushed)
	}
}

func (c *canonicalizer) writeText(data string) {
	if c.state != c14nInsideDocElement {
		// Text nodes whose parent is the document are skipped by the engine.
		return
	}
	c.out.WriteString(normalizeString(data, false))
}

func (c *canonicalizer) writeProcessingInstruction(target, data string) {
	if target == "xml" {
		return
	}
	if c.state == c14nAfterDocElement {
		c.out.WriteString("\n<?")
	} else {
		c.out.WriteString("<?")
	}
	c.out.WriteString(target)
	if data != "" {
		c.out.WriteString(" ")
		// PI nodeValue escaping: only the CR rule applies (not text, not attr).
		c.out.WriteString(strings.ReplaceAll(data, "\r", "&#xD;"))
	}
	if c.state == c14nBeforeDocElement {
		c.out.WriteString("?>\n")
	} else {
		c.out.WriteString("?>")
	}
}

// writeNamespacesAxis mirrors XmlCanonicalizer.WriteNamespacesAxis for the
// inclusive (non-exc) mode: walk attributes in document order, collect the
// namespace entries to render (declared xmlns*, namespace-declaring
// prefixed attributes, undeclared element fallback), sort by prefix with the
// default namespace first, dedup consecutive same-prefix entries and render.
func (c *canonicalizer) writeNamespacesAxis(elemPrefix, elemURI string, attrs []c14nAttr) int {
	list := make([]nsEntry, 0, 4)
	push := func(prefix, uri string) {
		list = append(list, nsEntry{prefix: prefix, uri: uri})
		c.pushNS(prefix, uri)
	}
	for i := range attrs {
		attr := &attrs[i]
		if !attr.isNamespaceDecl {
			// Prefixed attributes carry their namespace in: render it when
			// not already visible (the engine's attribute walk does this).
			if attr.prefix != "" && !c.isNamespaceRendered(attr.prefix, attr.uri) {
				push(attr.prefix, attr.uri)
			}
			continue
		}
		// xmlns="" — the engine renders the default-namespace undeclaration
		// unconditionally (its special case adds the entry before any
		// rendered check).
		if attr.local == "xmlns" && attr.prefix == "" && attr.value == "" {
			push("", "")
			continue
		}
		declared := attr.nsPrefix // "" for the default declaration
		if c.isNamespaceRendered(declared, attr.value) {
			continue
		}
		push(declared, attr.value)
	}
	// Element fallback: the engine re-checks the ELEMENT's own prefix/URI —
	// relevant when canonicalizing fragments whose apex carries declarations.
	if !c.isNamespaceRendered(elemPrefix, elemURI) && elemURI != xmlnsNamespaceURI {
		push(elemPrefix, elemURI)
	}
	sort.SliceStable(list, func(i, j int) bool {
		return namespaceEntryLess(list[i].prefix, list[j].prefix)
	})
	prevPrefix := ""
	first := true
	for _, entry := range list {
		if !first && entry.prefix == prevPrefix {
			continue
		}
		prevPrefix = entry.prefix
		first = false
		c.out.WriteString(" xmlns")
		if entry.prefix != "" {
			c.out.WriteString(":")
			c.out.WriteString(entry.prefix)
		}
		c.out.WriteString(`="`)
		c.out.WriteString(entry.uri)
		c.out.WriteString(`"`)
	}
	return len(list)
}

// namespaceEntryLess mirrors XmlDsigC14NTransformNamespacesComparer: the
// default namespace (empty prefix) sorts first, then lexicographic.
func namespaceEntryLess(a, b string) bool {
	if a == "" {
		return b != "" // "" sorts before any prefixed entry
	}
	if b == "" {
		return false
	}
	return a < b
}

// writeAttributesAxis mirrors XmlDsigC14NTransformAttributesComparer:
// no-namespace attributes first, then by namespace URI + local name.
func (c *canonicalizer) writeAttributesAxis(attrs []c14nAttr) {
	regular := make([]*c14nAttr, 0, len(attrs))
	for i := range attrs {
		if !attrs[i].isNamespaceDecl {
			regular = append(regular, &attrs[i])
		}
	}
	sort.SliceStable(regular, func(i, j int) bool {
		a, b := regular[i], regular[j]
		if a.uri == "" && b.uri != "" {
			return true
		}
		if b.uri == "" && a.uri != "" {
			return false
		}
		return a.uri+a.local < b.uri+b.local
	})
	for _, attr := range regular {
		c.out.WriteString(" ")
		c.out.WriteString(attr.qname)
		c.out.WriteString(`="`)
		c.out.WriteString(normalizeString(attr.value, true))
		c.out.WriteString(`"`)
	}
}

// c14nAttr is one start-element attribute prepared for the canonicalizer.
type c14nAttr struct {
	qname           string // written name (prefix:local or local)
	prefix          string // written prefix ("" = none)
	local           string
	uri             string // resolved namespace URI ("" = none)
	value           string
	isNamespaceDecl bool
	nsPrefix        string // for declarations: the declared prefix ("" = default)
}

// ---------------------------------------------------------------------------
// Document walker — RawToken streaming with subtree-span capture
// ---------------------------------------------------------------------------

// stripRule is one ZATCA exclusion transform (element removed wholesale).
type stripRule struct {
	ns    string
	local string
}

// stripRules mirrors the TS canonicalizeForHash removals: UBLExtensions and
// cac:Signature. The QR AdditionalDocumentReference is value-dependent and
// handled separately.
var stripRules = []stripRule{
	{nsUBLCommonExtensionComponents, "UBLExtensions"},
	{nsUBLCommonAggregateComponents, "Signature"},
}

// scopeFrame holds the xmlns declarations of one open element.
type scopeFrame struct {
	decls map[string]string
}

// walker streams RawTokens through the canonicalizer, applying the ZATCA
// exclusion transforms as subtree-span captures.
type walker struct {
	dec    *xml.Decoder
	c14n   *canonicalizer
	source string
	strip  bool
	// inherited carries the ancestor xmlns declarations for re-parsed
	// subtree spans (the span text itself lacks its ancestors' context).
	inherited map[string]string

	depth  int
	scopes []scopeFrame
	elems  []openElement

	lastSpanEnd int // input offset where the most recently consumed span ended
}

type openElement struct {
	qname  string
	pushed int
	first  bool
}

func (w *walker) resolve(prefix string) (string, bool) {
	for i := len(w.scopes) - 1; i >= 0; i-- {
		if uri, ok := w.scopes[i].decls[prefix]; ok {
			return uri, true
		}
	}
	if uri, ok := w.inherited[prefix]; ok {
		return uri, true
	}
	return "", false
}

// inheritedDecls snapshots the declarations currently in scope (outer to
// inner; later frames shadow earlier ones), including this walker's own
// inherited context so nested span re-parses preserve it.
func (w *walker) inheritedDecls() map[string]string {
	merged := make(map[string]string, 4)
	for prefix, uri := range w.inherited {
		merged[prefix] = uri
	}
	for _, frame := range w.scopes {
		for prefix, uri := range frame.decls {
			merged[prefix] = uri
		}
	}
	return merged
}

// pushScope opens a scope frame for a start element and returns the attrs
// prepared for canonicalization (prefixed attributes resolved).
func (w *walker) pushScope(attrs []xml.Attr, prepare bool) []c14nAttr {
	frame := scopeFrame{decls: map[string]string{}}
	w.scopes = append(w.scopes, frame)
	prepared := make([]c14nAttr, 0, len(attrs))
	for _, attr := range attrs {
		switch {
		case attr.Name.Space == "xmlns": // xmlns:prefix="..."
			frame.decls[attr.Name.Local] = attr.Value
			if prepare {
				prepared = append(prepared, c14nAttr{
					qname: attr.Name.Local, prefix: "xmlns", local: attr.Name.Local,
					value: attr.Value, isNamespaceDecl: true, nsPrefix: attr.Name.Local,
				})
			}
		case attr.Name.Space == "" && attr.Name.Local == "xmlns": // xmlns="..."
			frame.decls[""] = attr.Value
			if prepare {
				prepared = append(prepared, c14nAttr{
					qname: "xmlns", prefix: "", local: "xmlns",
					value: attr.Value, isNamespaceDecl: true, nsPrefix: "",
				})
			}
		default:
			uri := ""
			if attr.Name.Space != "" {
				uri, _ = w.resolve(attr.Name.Space)
			}
			if prepare {
				qname := attr.Name.Local
				if attr.Name.Space != "" {
					qname = attr.Name.Space + ":" + attr.Name.Local
				}
				prepared = append(prepared, c14nAttr{
					qname: qname, prefix: attr.Name.Space, local: attr.Name.Local,
					uri: uri, value: attr.Value,
				})
			}
		}
	}
	return prepared
}

func (w *walker) popScope() {
	w.scopes = w.scopes[:len(w.scopes)-1]
}

// walkDocument parses source and feeds the canonicalizer. With stripActive
// the ZATCA exclusion transforms run.
func (c *canonicalizer) walkDocument(source string, stripActive bool) error {
	w := &walker{
		dec:    xml.NewDecoder(strings.NewReader(source)),
		c14n:   c,
		source: source,
		strip:  stripActive,
	}
	return w.run()
}

// run is the main token loop. Subtree decisions use input-span capture: a
// removed subtree's span is swallowed wholesale; a kept QR-candidate span is
// re-parsed through the render path (fresh scope, shared canonicalizer).
func (w *walker) run() error {
	for {
		tokenStart := w.dec.InputOffset()
		tok, err := w.dec.RawToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("signing: parse XML: %w", err)
		}
		if err := w.walkOne(tok, int(tokenStart)); err != nil {
			return err
		}
	}
	return nil
}

func (w *walker) walkOne(tok xml.Token, tokenStart int) error {
	switch t := tok.(type) {
	case xml.ProcInst:
		w.c14n.writeProcessingInstruction(t.Target, string(t.Inst))
	case xml.Directive:
		// DOCTYPE: the TS engine drops the DocumentType node.
	case xml.Comment:
		// withComments=false: dropped.
	case xml.CharData:
		w.c14n.writeText(string(t))
	case xml.StartElement:
		return w.startElement(t, tokenStart)
	case xml.EndElement:
		return w.endElement(t)
	default:
		return fmt.Errorf("signing: unexpected XML token %T", tok)
	}
	return nil
}

func (w *walker) startElement(t xml.StartElement, tokenStart int) error {
	// Strip checks skip the capture ROOT (depth 0 of a re-parsed span): the
	// span was already decided by the capturing walker. The main walker's
	// depth-0 element is the UBL document root, which never matches a rule.
	if w.strip && w.depth > 0 {
		// Resolve the element namespace against the ENCLOSING scope (the
		// element's own declarations do not affect its own resolution in
		// the engine's model — its prefix/URI come from the parsed node).
		uri, _ := w.resolve(t.Name.Space)
		local := t.Name.Local
		for _, rule := range stripRules {
			if local == rule.local && uri == rule.ns {
				return w.discardSpan(tokenStart)
			}
		}
		if local == "AdditionalDocumentReference" && uri == nsUBLCommonAggregateComponents {
			return w.captureQRSpan(tokenStart)
		}
	}

	w.depth++
	prepared := w.pushScope(t.Attr, true)
	elemURI, _ := w.resolve(t.Name.Space)
	qname := t.Name.Local
	if t.Name.Space != "" {
		qname = t.Name.Space + ":" + t.Name.Local
	}
	pushed, first := w.c14n.startElement(qname, t.Name.Space, elemURI, prepared)
	w.elems = append(w.elems, openElement{qname: qname, pushed: pushed, first: first})
	return nil
}

func (w *walker) endElement(t xml.EndElement) error {
	w.depth--
	if len(w.elems) == 0 {
		return fmt.Errorf("signing: unbalanced XML end element </%s>", t.Name.Local)
	}
	frame := w.elems[len(w.elems)-1]
	w.elems = w.elems[:len(w.elems)-1]
	w.c14n.endElement(frame.qname, frame.pushed, frame.first)
	w.popScope()
	return nil
}

// discardSpan swallows the tokens of a strip-rule subtree: nothing is
// emitted for it. The capture root's own start token was already consumed
// by run(), so its depth is accounted here.
func (w *walker) discardSpan(tokenStart int) error {
	w.depth++
	return w.consumeSpan(w.depth)
}

// captureQRSpan consumes an AdditionalDocumentReference subtree, decides by
// its cbc:ID text whether it is the QR reference, and re-parses kept spans
// through the render path.
func (w *walker) captureQRSpan(tokenStart int) error {
	w.depth++
	if err := w.consumeSpan(w.depth); err != nil {
		return err
	}
	span := w.source[tokenStart:w.lastSpanEnd]
	if !subtreeHasQRID(span, w.inheritedDecls()) {
		// Keep: re-parse the span through the full render path (strip rules
		// stay active inside a kept reference).
		return w.renderSpan(span)
	}
	return nil
}

// consumeSpan // parent sits at parentDepth closes (the root's own start token is consumed
// already), recording the input end offset.
func (w *walker) consumeSpan(parentDepth int) error {
	for {
		tok, err := w.dec.RawToken()
		if err == io.EOF {
			return fmt.Errorf("signing: XML truncated inside removed subtree")
		}
		if err != nil {
			return fmt.Errorf("signing: parse XML: %w", err)
		}
		switch tok.(type) {
		case xml.StartElement:
			w.depth++
		case xml.EndElement:
			w.depth--
			if w.depth < parentDepth {
				w.lastSpanEnd = int(w.dec.InputOffset())
				return nil
			}
		}
	}
}

// renderSpan re-parses a kept span with a fresh walker sharing this
// canonicalizer (fresh scope stack seeded with the inherited declarations,
// strip rules active).
func (w *walker) renderSpan(span string) error {
	sub := &walker{
		dec:       xml.NewDecoder(strings.NewReader(span)),
		c14n:      w.c14n,
		source:    span,
		strip:     w.strip,
		inherited: w.inheritedDecls(),
	}
	return sub.run()
}

// subtreeHasQRID scans a captured AdditionalDocumentReference span for its
// first cbc:ID descendant whose text is exactly "QR" (the TS
// getElementsByTagNameNS('ID')[0].textContent === 'QR' semantics). The
// ancestor declarations seed the scanner's namespace scope.
func subtreeHasQRID(span string, inherited map[string]string) bool {
	dec := xml.NewDecoder(strings.NewReader(span))
	type frame struct {
		isID bool
	}
	var scopes []map[string]string
	if len(inherited) > 0 {
		seed := make(map[string]string, len(inherited))
		for prefix, uri := range inherited {
			seed[prefix] = uri
		}
		scopes = append(scopes, seed)
	}
	var stack []frame
	resolve := func(prefix string) string {
		for i := len(scopes) - 1; i >= 0; i-- {
			if uri, ok := scopes[i][prefix]; ok {
				return uri
			}
		}
		return ""
	}
	idActive := false
	idClosed := false
	var idText strings.Builder
	for {
		tok, err := dec.RawToken()
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			scopes = append(scopes, map[string]string{})
			for _, attr := range t.Attr {
				switch {
				case attr.Name.Space == "xmlns":
					scopes[len(scopes)-1][attr.Name.Local] = attr.Value
				case attr.Name.Space == "" && attr.Name.Local == "xmlns":
					scopes[len(scopes)-1][""] = attr.Value
				}
			}
			stack = append(stack, frame{})
			if !idClosed && t.Name.Local == "ID" && t.Name.Space == "cbc" && resolve("cbc") == nsUBLCommonBasicComponents {
				stack[len(stack)-1].isID = true
				idActive = true
				idText.Reset()
			}
		case xml.CharData:
			if idActive {
				idText.Write(t)
			}
		case xml.EndElement:
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				scopes = scopes[:len(scopes)-1]
				if top.isID {
					idActive = false
					idClosed = true
					if idText.String() == "QR" {
						return true
					}
				}
			}
		}
	}
}
