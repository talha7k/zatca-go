// XAdES SignedProperties + XMLDSig SignedInfo builders — the TS shared.js
// twins. Templates are byte-identical to the TS string builders (ZATCA's
// validator is strict about element order and attributes).
package signing

// Algorithm and namespace URIs (the TS shared.js constants).
const (
	ecdsaSha256URI  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	c14n11URI       = "http://www.w3.org/2006/12/xml-c14n11"
	sha256DigestURI = "http://www.w3.org/2001/04/xmlenc#sha256"
	dsNamespace     = "http://www.w3.org/2000/09/xmldsig#"
	xadesNamespace  = "http://uri.etsi.org/01903/v1.3.2#"

	xpathTransformURI = "http://www.w3.org/TR/1999/REC-xpath-19991116"
)

// BuildSignedProperties builds the xades:SignedProperties XML for the
// certificate (the non-digested form carried inside ds:Object).
func BuildSignedProperties(certificate CertificateInfo, signingTime string) string {
	return `<xades:SignedProperties xmlns:xades="` + xadesNamespace + `" xmlns:ds="` + dsNamespace + `" Id="xadesSignedProperties">` +
		`<xades:SignedSignatureProperties><xades:SigningTime>` + signingTime + `</xades:SigningTime>` +
		`<xades:SigningCertificate><xades:Cert><xades:CertDigest>` +
		`<ds:DigestMethod Algorithm="` + sha256DigestURI + `"/>` +
		`<ds:DigestValue>` + certificate.DigestValue + `</ds:DigestValue>` +
		`</xades:CertDigest><xades:IssuerSerial>` +
		`<ds:X509IssuerName>` + certificate.IssuerName + `</ds:X509IssuerName>` +
		`<ds:X509SerialNumber>` + certificate.SerialNumber + `</ds:X509SerialNumber>` +
		`</xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties>`
}

// BuildSdkSignedPropertiesDigestXML builds the SignedProperties XML exactly
// the way the ZATCA SDK digests it (namespace declarations moved onto the
// individual ds: elements) — the digest INPUT string.
func BuildSdkSignedPropertiesDigestXML(certificate CertificateInfo, signingTime string) string {
	return `<xades:SignedProperties xmlns:xades="` + xadesNamespace + `" Id="xadesSignedProperties">` +
		`<xades:SignedSignatureProperties><xades:SigningTime>` + signingTime + `</xades:SigningTime>` +
		`<xades:SigningCertificate><xades:Cert><xades:CertDigest>` +
		`<ds:DigestMethod xmlns:ds="` + dsNamespace + `" Algorithm="` + sha256DigestURI + `"/>` +
		`<ds:DigestValue xmlns:ds="` + dsNamespace + `">` + certificate.DigestValue + `</ds:DigestValue>` +
		`</xades:CertDigest><xades:IssuerSerial>` +
		`<ds:X509IssuerName xmlns:ds="` + dsNamespace + `">` + certificate.IssuerName + `</ds:X509IssuerName>` +
		`<ds:X509SerialNumber xmlns:ds="` + dsNamespace + `">` + certificate.SerialNumber + `</ds:X509SerialNumber>` +
		`</xades:IssuerSerial></xades:Cert></xades:SigningCertificate></xades:SignedSignatureProperties></xades:SignedProperties>`
}

// DigestSdkSignedProperties computes the SignedProperties reference digest:
// SHA-256 over the SDK digest XML, then the TS double encoding
// base64(hex(...)) — hashForDigestValue + digestSdkSignedProperties twins.
func DigestSdkSignedProperties(certificate CertificateInfo, signingTime string) string {
	return base64OfUtf8(sha256HexOf(BuildSdkSignedPropertiesDigestXML(certificate, signingTime)))
}

// BuildSignedInfo builds the ds:SignedInfo XML with the ZATCA exclusion
// transforms — the TS buildSignedInfo twin.
func BuildSignedInfo(invoiceHash string, signedPropertiesDigest string) string {
	return `<ds:SignedInfo xmlns:ds="` + dsNamespace + `"` +
		` xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"` +
		` xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"` +
		` xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">` +
		`<ds:CanonicalizationMethod Algorithm="` + c14n11URI + `"/>` +
		`<ds:SignatureMethod Algorithm="` + ecdsaSha256URI + `"/>` +
		`<ds:Reference Id="invoiceSignedData" URI="">` +
		`<ds:Transforms>` +
		`<ds:Transform Algorithm="` + xpathTransformURI + `"><ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath></ds:Transform>` +
		`<ds:Transform Algorithm="` + xpathTransformURI + `"><ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath></ds:Transform>` +
		`<ds:Transform Algorithm="` + xpathTransformURI + `"><ds:XPath>not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])</ds:XPath></ds:Transform>` +
		`<ds:Transform Algorithm="` + c14n11URI + `"/>` +
		`</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + sha256DigestURI + `"/>` +
		`<ds:DigestValue>` + invoiceHash + `</ds:DigestValue>` +
		`</ds:Reference>` +
		`<ds:Reference Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties" URI="#xadesSignedProperties">` +
		`<ds:DigestMethod Algorithm="` + sha256DigestURI + `"/>` +
		`<ds:DigestValue>` + signedPropertiesDigest + `</ds:DigestValue>` +
		`</ds:Reference></ds:SignedInfo>`
}
