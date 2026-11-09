package authority

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"

	"slices"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/oid"
)

// oidExtKeyUsageOCSPSigning is id-kp-OCSPSigning (RFC 5280, 4.2.1.12).
var oidExtKeyUsageOCSPSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}

// ekuHasOCSPSigning reports whether a DER extended key usage extension
// value lists id-kp-OCSPSigning.
func ekuHasOCSPSigning(der []byte) (bool, error) {
	var usages []asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &usages)
	if err != nil {
		return false, errors.Wrap(err, "invalid extended key usage extension")
	}
	if len(rest) > 0 {
		return false, errors.New("invalid extended key usage extension: trailing data")
	}
	return slices.ContainsFunc(usages, oidExtKeyUsageOCSPSigning.Equal), nil
}

// isOCSPSigningTemplate reports whether a certificate created from template
// carries the OCSP signing EKU. A raw EKU extension in ExtraExtensions
// overrides template.ExtKeyUsage in x509.CreateCertificate.
func isOCSPSigningTemplate(template *x509.Certificate) (bool, error) {
	if ext := certutil.FindExtension(template.ExtraExtensions, oid.ExtensionExtendedKeyUsage); ext != nil {
		return ekuHasOCSPSigning(ext.Value)
	}
	return certutil.IsOCSPSigner(template), nil
}

// mldsaForbiddenKeyUsage holds the key usages RFC 9881 section 5 forbids for an
// ML-DSA key, a signature scheme.
const mldsaForbiddenKeyUsage = x509.KeyUsageKeyEncipherment |
	x509.KeyUsageDataEncipherment |
	x509.KeyUsageKeyAgreement |
	x509.KeyUsageEncipherOnly |
	x509.KeyUsageDecipherOnly

// keyUsageBits is the number of key usage bits RFC 5280 4.2.1.3 defines.
const keyUsageBits = 9

// parseKeyUsage decodes the DER value of a key usage extension.
func parseKeyUsage(der []byte) (x509.KeyUsage, error) {
	var bits asn1.BitString
	rest, err := asn1.Unmarshal(der, &bits)
	if err != nil {
		return 0, errors.Wrap(err, "invalid key usage extension")
	}
	if len(rest) > 0 {
		return 0, errors.New("invalid key usage extension: trailing data")
	}
	var ku x509.KeyUsage
	for i := range keyUsageBits {
		if bits.At(i) != 0 {
			ku |= 1 << i
		}
	}
	return ku, nil
}

// rejectMLDSAKeyUsage returns an error naming the usages in ku that an ML-DSA
// key must not have.
func rejectMLDSAKeyUsage(ku x509.KeyUsage) error {
	if forbidden := ku & mldsaForbiddenKeyUsage; forbidden != 0 {
		return errors.Errorf("key usage not allowed for an ML-DSA key: %s",
			strings.Join(oid.KeyUsages(forbidden), ", "))
	}
	return nil
}

// checkMLDSATemplate rejects an ML-DSA certificate template with a forbidden key
// usage. A raw key usage extension in ExtraExtensions overrides
// template.KeyUsage in x509.CreateCertificate.
func checkMLDSATemplate(template *x509.Certificate) error {
	ku := template.KeyUsage
	if ext := certutil.FindExtension(template.ExtraExtensions, oid.ExtensionKeyUsage); ext != nil {
		var err error
		ku, err = parseKeyUsage(ext.Value)
		if err != nil {
			return err
		}
	}
	return rejectMLDSAKeyUsage(ku)
}

type policyInformation struct {
	PolicyIdentifier asn1.ObjectIdentifier
	Qualifiers       []any `asn1:"tag:optional,omitempty"`
}

type cpsPolicyQualifier struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         string `asn1:"tag:optional,ia5"`
}

type userNotice struct {
	ExplicitText string `asn1:"tag:optional,utf8"`
}
type userNoticePolicyQualifier struct {
	PolicyQualifierID asn1.ObjectIdentifier
	Qualifier         userNotice
}

var (
	// Per https://tools.ietf.org/html/rfc3280.html#page-106, this represents:
	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-cps(1)
	iDQTCertificationPracticeStatement = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
	// iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//   mechanisms(5) pkix(7) id-qt(2) id-qt-unotice(2)
	iDQTUserNotice = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}

	// CTPoisonOID is the object ID of the critical poison extension for precertificates
	// https://tools.ietf.org/html/rfc6962#page-9
	CTPoisonOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

	// SCTListOID is the object ID for the Signed Certificate Timestamp certificate extension
	// https://tools.ietf.org/html/rfc6962#page-14
	SCTListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// addPolicies adds Certificate Policies and optional Policy Qualifiers to a
// certificate, based on the input config. Go's x509 library allows setting
// Certificate Policies easily, but does not support nested Policy Qualifiers
// under those policies. So we need to construct the ASN.1 structure ourselves.
func addPolicies(template *x509.Certificate, policies []csr.CertificatePolicy, critical bool) error {
	asn1PolicyList := []policyInformation{}

	for _, policy := range policies {
		pi := policyInformation{
			// The PolicyIdentifier is an OID assigned to a given issuer.
			PolicyIdentifier: asn1.ObjectIdentifier(policy.ID),
		}
		for _, qualifier := range policy.Qualifiers {
			switch qualifier.Type {
			case "id-qt-unotice":
				pi.Qualifiers = append(pi.Qualifiers,
					userNoticePolicyQualifier{
						PolicyQualifierID: iDQTUserNotice,
						Qualifier: userNotice{
							ExplicitText: qualifier.Value,
						},
					})
			case "id-qt-cps":
				pi.Qualifiers = append(pi.Qualifiers,
					cpsPolicyQualifier{
						PolicyQualifierID: iDQTCertificationPracticeStatement,
						Qualifier:         qualifier.Value,
					})
			default:
				return errors.New("invalid qualifier type in Policies " + qualifier.Type)
			}
		}
		asn1PolicyList = append(asn1PolicyList, pi)
	}

	asn1Bytes, err := asn1.Marshal(asn1PolicyList)
	if err != nil {
		return errors.WithStack(err)
	}

	// the profile policies replace any supplied by the request (XPKI-050)
	template.ExtraExtensions = setExtension(template.ExtraExtensions, pkix.Extension{
		Id:       oid.ExtensionCertificatePolicies,
		Critical: critical,
		Value:    asn1Bytes,
	})
	return nil
}

// setExtension replaces the extension with the same OID in list, or appends it.
func setExtension(list []pkix.Extension, ext pkix.Extension) []pkix.Extension {
	for i := range list {
		if list[i].Id.Equal(ext.Id) {
			list[i] = ext
			return list
		}
	}
	return append(list, ext)
}

// computeSKI derives an SKI from the certificate's public key in a
// standard manner. This is done by computing the SHA-1 digest of the
// SubjectPublicKeyInfo component of the certificate.
func computeSKI(template *x509.Certificate) ([]byte, error) {
	pub := template.PublicKey
	encodedPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	pubHash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	return pubHash[:], nil
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}
