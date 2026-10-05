// Signature envelope assembly — the ds:Signature / UBL extension block / QR
// embedding builders (the TS shared.js buildSignatureXml,
// buildUBLSignatureBlock, qrElement, insertQr, assembleSignedXml twins).
// Indentation inside the templates is load-bearing: the TS pipeline splices
// these fragments into the minted document verbatim.
package signing

import (
	"fmt"
	"regexp"
	"strings"
)

// BuildSignatureXML wraps SignedInfo, the signature value, the certificate
// and the SignedProperties into the ds:Signature element — the
// buildSignatureXml twin, including the open-tag rewrite that strips the
// SignedProperties namespace declarations (the xades prefix is declared by
// the enclosing QualifyingProperties).
func BuildSignatureXML(signedInfoXML string, signatureValue string, certificateBase64 string, certificate CertificateInfo, signingTime string) string {
	signedPropertiesXML := BuildSignedProperties(certificate, signingTime)
	// The TS: signedPropertiesXml.replace(/^<xades:SignedProperties[^>]*>/,
	// '<xades:SignedProperties Id="xadesSignedProperties">') — the built
	// string always starts with that exact open tag.
	openTagEnd := strings.Index(signedPropertiesXML, ">")
	if !strings.HasPrefix(signedPropertiesXML, "<xades:SignedProperties") || openTagEnd < 0 {
		// Unreachable with the builder above; guard anyway.
		panic("signing: BuildSignedProperties produced an unexpected open tag")
	}
	signedPropertiesBody := `<xades:SignedProperties Id="xadesSignedProperties">` + signedPropertiesXML[openTagEnd+1:]

	return `<ds:Signature xmlns:ds="` + dsNamespace + `" Id="signature">` +
		signedInfoXML +
		`<ds:SignatureValue>` + signatureValue + `</ds:SignatureValue>` +
		`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + certificateBase64 + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
		`<ds:Object><xades:QualifyingProperties xmlns:xades="` + xadesNamespace + `" Target="signature">` +
		signedPropertiesBody +
		`</xades:QualifyingProperties></ds:Object></ds:Signature>`
}

// BuildUBLSignatureBlock builds the UBL DocumentSignatures wrapper —
// ZATCA requires the XML-DSig Signature nested inside
// ext:UBLExtensions > ext:UBLExtension > ext:ExtensionContent
//
//	> sig:UBLDocumentSignatures > sac:SignatureInformation.
func BuildUBLSignatureBlock(signatureXML string, documentName string) string {
	return `    <ext:UBLExtension>
      <ext:ExtensionContent>
        <sig:UBLDocumentSignatures xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2"
                                   xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2"
                                   xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2"
                                   xmlns:ds="` + dsNamespace + `">
          <sac:SignatureInformation>
            <cbc:ID xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">urn:oasis:names:specification:ubl:signature:1</cbc:ID>
            <sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:` + documentName + `</sbc:ReferencedSignatureID>
            ` + signatureXML + `
          </sac:SignatureInformation>
        </sig:UBLDocumentSignatures>
      </ext:ExtensionContent>
    </ext:UBLExtension>`
}

// QRElement builds the cac:AdditionalDocumentReference embedding the QR
// payload.
func QRElement(qrBase64 string) string {
	return `<cac:AdditionalDocumentReference>
    <cbc:ID>QR</cbc:ID>
    <cac:Attachment>
      <cbc:EmbeddedDocumentBinaryObject mimeCode="text/plain">` + qrBase64 + `</cbc:EmbeddedDocumentBinaryObject>
    </cac:Attachment>
  </cac:AdditionalDocumentReference>`
}

var (
	existingQRPattern = regexp.MustCompile(`<cac:AdditionalDocumentReference>\s*<cbc:ID>QR</cbc:ID>[\s\S]*?</cac:AdditionalDocumentReference>`)
	ublExtensionsOpen = "<ext:UBLExtensions>"
	ublExtensionsFull = regexp.MustCompile(`<ext:UBLExtensions>[\s\S]*?</ext:UBLExtensions>`)
	ublExtensionsHead = regexp.MustCompile(`<ext:UBLExtensions\b[\s\S]*?</ext:UBLExtensions>`)
)

// InsertQR inserts (or replaces) the QR AdditionalDocumentReference in
// signed XML. Prefers the position before the first
// AdditionalDocumentReference, falls back to before cac:Signature, and
// errors when neither anchor exists — the TS insertQr twin.
func InsertQR(xmlWithSignature string, qrBase64 string) (string, error) {
	withoutExistingQR := existingQRPattern.ReplaceAllString(xmlWithSignature, "")
	insertionPoint := strings.Index(withoutExistingQR, "<cac:AdditionalDocumentReference")
	signaturePoint := strings.Index(withoutExistingQR, "<cac:Signature>")
	element := QRElement(qrBase64)
	switch {
	case insertionPoint != -1:
		return withoutExistingQR[:insertionPoint] + element + withoutExistingQR[insertionPoint:], nil
	case signaturePoint != -1:
		return withoutExistingQR[:signaturePoint] + element + withoutExistingQR[signaturePoint:], nil
	default:
		return "", fmt.Errorf("signing: unable to embed ZATCA QR: missing AdditionalDocumentReference or Signature anchor")
	}
}

// AssembleSignedXML splices the UBL signature block into the
// ext:UBLExtensions placeholder and, when a QR payload is supplied, embeds
// it — the TS assembleSignedXml twin (first-occurrence replacement).
func AssembleSignedXML(xml string, ublRootName string, signatureXML string, qrBase64 *string) (string, error) {
	ublSignature := BuildUBLSignatureBlock(signatureXML, ublRootName)
	signedXML := xml
	if loc := ublExtensionsFull.FindStringIndex(signedXML); loc != nil {
		signedXML = signedXML[:loc[0]] + ublExtensionsOpen + ublSignature + "</ext:UBLExtensions>" + signedXML[loc[1]:]
	}
	if qrBase64 != nil {
		return InsertQR(signedXML, *qrBase64)
	}
	return signedXML, nil
}

// UBLRoot identifies the UBL document root the signature wraps.
type UBLRoot struct {
	Name      string
	Namespace string
}

var (
	invoiceRootPattern    = regexp.MustCompile(`<Invoice(?:\s|>)`)
	creditNoteRootPattern = regexp.MustCompile(`<CreditNote(?:\s|>)`)
)

// GetUBLRoot detects the UBL document root — the TS getUblRoot twin.
func GetUBLRoot(xml string) (UBLRoot, error) {
	if invoiceRootPattern.MatchString(xml) {
		return UBLRoot{
			Name:      "Invoice",
			Namespace: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
		}, nil
	}
	if creditNoteRootPattern.MatchString(xml) {
		return UBLRoot{
			Name:      "CreditNote",
			Namespace: "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
		}, nil
	}
	return UBLRoot{}, fmt.Errorf("signing: unsupported UBL document: expected Invoice or CreditNote root element")
}

// HasUBLExtensionsPlaceholder reports whether the document carries the
// ext:UBLExtensions block the signing step replaces (the
// buildSigningContext precondition).
func HasUBLExtensionsPlaceholder(xml string) bool {
	return ublExtensionsHead.MatchString(xml)
}
