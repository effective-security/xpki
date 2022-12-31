package csr

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/oid"
	"github.com/effective-security/xpki/x/slices"
	"github.com/pkg/errors"
)

// Signer interface to sign CSR
type Signer interface {
	SignCertificate(req SignRequest) (cert []byte, err error)
}

// AllowedFields provides booleans for fields in the CSR.
// If a AllowedFields is not present in a CertProfile,
// all of these fields may be copied from the CSR into the signed certificate.
// If a AllowedFields *is* present in a CertProfile,
// only those fields with a `true` value in the AllowedFields may
// be copied from the CSR to the signed certificate.
// Note that some of these fields, like Subject, can be provided or
// partially provided through the API.
// Since API clients are expected to be trusted, but CSRs are not, fields
// provided through the API are not subject to validation through this
// mechanism.
type AllowedFields struct {
	Subject        bool `json:"subject" yaml:"subject"`
	DNSNames       bool `json:"dns" yaml:"dns"`
	IPAddresses    bool `json:"ip" yaml:"ip"`
	EmailAddresses bool `json:"email" yaml:"email"`
	URIs           bool `json:"uri" yaml:"uri"`
}

// CertificatePolicy represents the ASN.1 PolicyInformation structure from
// https://tools.ietf.org/html/rfc3280.html#page-106.
// Valid values of Type are "id-qt-unotice" and "id-qt-cps"
type CertificatePolicy struct {
	ID         OID                          `json:"oid" yaml:"oid"`
	Qualifiers []CertificatePolicyQualifier `json:"qualifiers" yaml:"qualifiers"`
}

// CertificatePolicyQualifier represents a single qualifier from an ASN.1
// PolicyInformation structure.
type CertificatePolicyQualifier struct {
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
}

// X509Name contains the SubjectInfo fields.
type X509Name struct {
	Country            string `json:"c" yaml:"c"`
	Province           string `json:"st" yaml:"st"`
	Locality           string `json:"l" yaml:"l"`
	Organization       string `json:"o" yaml:"o"`
	OrganizationalUnit string `json:"ou" yaml:"ou"`
	EmailAddress       string `json:"email" yaml:"email"` // 1.2.840.113549.1.9.1
	SerialNumber       string `json:"serial_number" yaml:"serial_number"`
}

// X509Subject contains the information that should be used to override the
// subject information when signing a certificate.
type X509Subject struct {
	CommonName   string     `json:"common_name" yaml:"common_name"`
	Names        []X509Name `json:"names" yaml:"names"`
	SerialNumber string     `json:"serial_number" yaml:"serial_number"`
}

// X509Extension represents a raw extension to be included in the certificate.  The
// "value" field must be hex encoded.
type X509Extension struct {
	ID       OID    `json:"id" yaml:"id"`
	Critical bool   `json:"critical" yaml:"critical"`
	Value    string `json:"value" yaml:"value"`
}

// GetValue returns raw value.
// if prefix is hex or base64, then it's decoded,
// otherwise hex decoding is tried first then base64
func (ext X509Extension) GetValue() ([]byte, error) {
	var rawValue []byte
	var err error
	if strings.HasPrefix(ext.Value, "hex:") {
		rawValue, err = hex.DecodeString(ext.Value[4:])
	} else if strings.HasPrefix(ext.Value, "base64:") {
		rawValue, err = base64.StdEncoding.DecodeString(ext.Value[7:])
	} else {
		rawValue, err = hex.DecodeString(ext.Value)
		if err != nil {
			rawValue, err = base64.StdEncoding.DecodeString(ext.Value)
		}
	}
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to decode extension: %s", ext.Value)
	}
	return rawValue, nil
}

// SignRequest stores a signature request, which contains the SAN,
// the pen-encoded CSR, optional subject information, and the signature profile.
//
// Extensions provided in the request are copied into the certificate, as
// long as they are in the allowed list for the issuer's policy.
// Extensions requested in the CSR are ignored, except for those processed by
// CreateCSR (mainly subjectAltName).
type SignRequest struct {
	SAN          []string        `json:"san" yaml:"san"`
	Request      string          `json:"certificate_request" yaml:"certificate_request"`
	Subject      *X509Subject    `json:"subject,omitempty" yaml:"subject,omitempty"`
	Profile      string          `json:"profile" yaml:"profile"`
	SerialNumber *big.Int        `json:"serial_number,omitempty" yaml:"serial_number,omitempty"`
	Extensions   []X509Extension `json:"extensions,omitempty" yaml:"extensions,omitempty"`

	// TODO: label, if supported
	//Label      string          `json:"label"`

	// If provided, NotBefore will be used without modification (except
	// for canonicalization) as the value of the notBefore field of the
	// certificate. In particular no backdating adjustment will be made
	// when NotBefore is provided.
	NotBefore time.Time `json:"-" yaml:"-"`
	// If provided, NotAfter will be used without modification (except
	// for canonicalization) as the value of the notAfter field of the
	// certificate.
	NotAfter time.Time `json:"-" yaml:"-"`
}

// SubjectCommonName returns CN in the request
func (r *SignRequest) SubjectCommonName() string {
	if r.Subject != nil {
		return r.Subject.CommonName
	}
	return ""
}

// ExtensionsIDs returns list of extension IDs in the request
func (r *SignRequest) ExtensionsIDs() []string {
	var list []string
	for _, ex := range r.Extensions {
		list = append(list, ex.ID.String())
	}
	return list
}

// A CertificateRequest encapsulates the API interface to the
// certificate request functionality.
type CertificateRequest struct {
	// CommonName of the Subject
	CommonName string `json:"common_name" yaml:"common_name"`
	// Names of the Subject
	Names []X509Name `json:"names" yaml:"names"`
	// SerialNumber of the Subject
	SerialNumber string `json:"serial_number,omitempty" yaml:"serial_number,omitempty"`
	// SAN is Subject Alt Names
	SAN []string `json:"san" yaml:"san"`
	// KeyRequest for generated key
	KeyRequest *KeyRequest `json:"key,omitempty" yaml:"key,omitempty"`
	// Extensions for the cert
	Extensions []X509Extension `json:"extensions,omitempty" yaml:"extensions,omitempty"`
}

// Validate provides the default validation logic for certificate
// authority certificates. The only requirement here is that the
// certificate have a non-empty subject field.
func (r *CertificateRequest) Validate() error {
	if r.CommonName != "" {
		return nil
	}

	// if len(r.Names) == 0 {
	//		return errors.New("missing subject information")
	//	}

	for _, n := range r.Names {
		if isNameEmpty(n) {
			return errors.New("empty name")
		}
	}

	return nil
}

// AddSAN adds a SAN value to the request
func (r *CertificateRequest) AddSAN(s string) {
	if found := slices.ContainsString(r.SAN, s); !found {
		r.SAN = append(r.SAN, s)
	}
}

// isNameEmpty returns true if the name has no identifying information in it.
func isNameEmpty(n X509Name) bool {
	empty := func(s string) bool { return strings.TrimSpace(s) == "" }

	if empty(n.Country) && empty(n.Province) && empty(n.Locality) && empty(n.Organization) && empty(n.OrganizationalUnit) {
		return true
	}
	return false
}

// appendIf appends to a if s is not an empty string.
func appendIf(s string, a *[]string) {
	if s != "" {
		*a = append(*a, s)
	}
}

// Parse takes an incoming certificate request and
// builds a certificate template from it.
func Parse(csrBytes []byte) (*x509.Certificate, error) {
	csrv, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse")
	}

	err = csrv.CheckSignature()
	if err != nil {
		return nil, errors.WithMessagef(err, "key mismatch")
	}

	template := &x509.Certificate{
		Subject:            csrv.Subject,
		PublicKeyAlgorithm: csrv.PublicKeyAlgorithm,
		PublicKey:          csrv.PublicKey,
		DNSNames:           csrv.DNSNames,
		IPAddresses:        csrv.IPAddresses,
		EmailAddresses:     csrv.EmailAddresses,
		URIs:               csrv.URIs,
	}

	for _, val := range csrv.Extensions {
		// Check the CSR for the X.509 BasicConstraints (RFC 5280, 4.2.1.9)
		// extension and append to template if necessary
		if val.Id.Equal(oid.ExtensionBasicConstraints) {
			var constraints BasicConstraints
			var rest []byte

			if rest, err = asn1.Unmarshal(val.Value, &constraints); err != nil {
				return nil, errors.WithMessage(err, "failed to parse BasicConstraints")
			} else if len(rest) != 0 {
				return nil, errors.New("failed to parse BasicConstraints: trailing data")
			}

			template.BasicConstraintsValid = true
			template.IsCA = constraints.IsCA
			template.MaxPathLen = constraints.MaxPathLen
			template.MaxPathLenZero = template.MaxPathLen == 0
		} else {
			template.ExtraExtensions = append(template.ExtraExtensions, val)
		}
	}

	return template, nil
}

// ParsePEM takes an incoming certificate request and
// builds a certificate template from it.
func ParsePEM(csrPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("unable to parse PEM")
	}

	if block.Type != "NEW CERTIFICATE REQUEST" && block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.Errorf("unsupported type in PEM: " + block.Type)
	}

	return Parse(block.Bytes)
}

// Name returns the PKIX name for the request.
func (r *CertificateRequest) Name() pkix.Name {
	subs := X509Subject{
		CommonName:   r.CommonName,
		SerialNumber: r.SerialNumber,
		Names:        r.Names,
	}

	return subs.Name()
}

// Name returns the PKIX name for the subject.
func (s *X509Subject) Name() pkix.Name {
	var name pkix.Name
	name.CommonName = s.CommonName
	name.SerialNumber = s.SerialNumber

	if s.CommonName != "" {
		name.Names = append(name.Names, pkix.AttributeTypeAndValue{
			Type:  oid.NameCN,
			Value: s.CommonName,
		})
	}

	if s.SerialNumber != "" {
		name.Names = append(name.Names, pkix.AttributeTypeAndValue{
			Type:  oid.NameSerial,
			Value: s.SerialNumber,
		})
	}

	for _, n := range s.Names {
		appendIf(n.Country, &name.Country)
		appendIf(n.Province, &name.Province)
		appendIf(n.Locality, &name.Locality)
		appendIf(n.Organization, &name.Organization)
		appendIf(n.OrganizationalUnit, &name.OrganizationalUnit)

		if n.Country != "" {
			name.Names = append(name.Names, pkix.AttributeTypeAndValue{
				Type:  oid.NameC,
				Value: n.Country,
			})
		}
		if n.Province != "" {
			name.Names = append(name.Names, pkix.AttributeTypeAndValue{
				Type:  oid.NameST,
				Value: n.Province,
			})
		}
		if n.Locality != "" {
			name.Names = append(name.Names, pkix.AttributeTypeAndValue{
				Type:  oid.NameL,
				Value: n.Locality,
			})
		}
		if n.Organization != "" {
			name.Names = append(name.Names, pkix.AttributeTypeAndValue{
				Type:  oid.NameO,
				Value: n.Organization,
			})
		}
		if n.OrganizationalUnit != "" {
			name.Names = append(name.Names, pkix.AttributeTypeAndValue{
				Type:  oid.NameOU,
				Value: n.OrganizationalUnit,
			})
		}
		if n.EmailAddress != "" {
			name.Names = append(name.Names, pkix.AttributeTypeAndValue{
				Type:  oid.NameEmailAddress,
				Value: n.EmailAddress,
			})
		}
		if n.SerialNumber != "" {
			name.Names = append(name.Names, pkix.AttributeTypeAndValue{
				Type:  oid.NameSerial,
				Value: n.SerialNumber,
			})
		}
	}
	return name
}

// PopulateName has functionality similar to Name, except
// it fills the fields of the resulting pkix.Name with req's if the
// subject's corresponding fields are empty
func PopulateName(raSubject *X509Subject, csrSubject pkix.Name) pkix.Name {
	// if no subject, use req
	if raSubject == nil {
		return csrSubject
	}

	name := raSubject.Name()
	if name.CommonName == "" {
		name.CommonName = csrSubject.CommonName
	}
	if name.SerialNumber == "" {
		name.SerialNumber = csrSubject.SerialNumber
	}

	replaceSliceIfEmpty(&name.Country, &csrSubject.Country)
	replaceSliceIfEmpty(&name.Province, &csrSubject.Province)
	replaceSliceIfEmpty(&name.Locality, &csrSubject.Locality)
	replaceSliceIfEmpty(&name.Organization, &csrSubject.Organization)
	replaceSliceIfEmpty(&name.OrganizationalUnit, &csrSubject.OrganizationalUnit)

	for _, n := range csrSubject.Names {
		if FindAttr(name.Names, n.Type) == nil {
			name.Names = append(name.Names, n)
		}
	}

	return name
}

// FindAttr returns attribute
func FindAttr(attrs []pkix.AttributeTypeAndValue, id asn1.ObjectIdentifier) *pkix.AttributeTypeAndValue {
	for idx, at := range attrs {
		if at.Type.Equal(id) {
			return &attrs[idx]
		}
	}
	return nil
}

// replaceSliceIfEmpty replaces the contents of replaced with newContents if
// the slice referenced by replaced is empty
func replaceSliceIfEmpty(replaced, newContents *[]string) {
	if len(*replaced) == 0 {
		*replaced = *newContents
	}
}

// SetSAN fills template's IPAddresses, EmailAddresses, and DNSNames with the
// content of SAN, if it is not nil.
func SetSAN(template *x509.Certificate, SAN []string) {
	if SAN != nil {
		template.IPAddresses = []net.IP{}
		template.EmailAddresses = []string{}
		template.DNSNames = []string{}
		template.URIs = []*url.URL{}

		for i := range template.ExtraExtensions {
			// remove SAN
			if template.ExtraExtensions[i].Id.Equal(oid.ExtensionSubjectAltName) {
				l := len(template.ExtraExtensions)
				template.ExtraExtensions[i] = template.ExtraExtensions[l-1]
				template.ExtraExtensions = template.ExtraExtensions[:l-1]
				break
			}
		}
	}

	for _, san := range SAN {
		if strings.Contains(san, "://") {
			u, err := url.Parse(san)
			if err != nil {
				logger.KV(xlog.ERROR, "uri", san, "err", err)
			}
			template.URIs = append(template.URIs, u)
		} else if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(san); err == nil && email != nil {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
}

// EncodeCDP returns CRLDP
func EncodeCDP(cdp []string) (*pkix.Extension, error) {
	ext := pkix.Extension{
		Id: oid.ExtensionCRLDistributionPoints,
	}
	var crlDp []DistributionPoint
	for _, name := range cdp {
		dp := DistributionPoint{
			DistributionPoint: DistributionPointName{
				FullName: []asn1.RawValue{
					{Tag: 6, Class: 2, Bytes: []byte(name)},
				},
			},
		}
		crlDp = append(crlDp, dp)
	}

	val, err := asn1.Marshal(crlDp)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	ext.Value = val
	return &ext, nil
}

// DecodeCDP returns list of CDP
func DecodeCDP(val []byte) ([]string, error) {
	var crlDp []DistributionPoint
	_, err := asn1.Unmarshal(val, &crlDp)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var list []string
	for _, c := range crlDp {
		for _, fn := range c.DistributionPoint.FullName {
			list = append(list, string(fn.Bytes))
		}
	}
	return list, nil
}

// DistributionPoint defines CDP as per RFC 5280, 4.2.1.14
type DistributionPoint struct {
	DistributionPoint DistributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

// DistributionPointName is a part of DistributionPoint
type DistributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}
