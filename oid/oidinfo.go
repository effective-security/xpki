package oid

import (
	"crypto/x509"
	"encoding/asn1"
)

// KeyUsage contains a mapping of string names to key usages.
var KeyUsage = map[string]x509.KeyUsage{
	"signing":            x509.KeyUsageDigitalSignature,
	"digital signature":  x509.KeyUsageDigitalSignature,
	"content commitment": x509.KeyUsageContentCommitment,
	"key encipherment":   x509.KeyUsageKeyEncipherment,
	"key agreement":      x509.KeyUsageKeyAgreement,
	"data encipherment":  x509.KeyUsageDataEncipherment,
	"cert sign":          x509.KeyUsageCertSign,
	"crl sign":           x509.KeyUsageCRLSign,
	"encipher only":      x509.KeyUsageEncipherOnly,
	"decipher only":      x509.KeyUsageDecipherOnly,
}

// KeyUsageName provides map of names
var KeyUsageName = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "signing",
	x509.KeyUsageContentCommitment: "content commitment",
	x509.KeyUsageKeyEncipherment:   "key encipherment",
	x509.KeyUsageKeyAgreement:      "key agreement",
	x509.KeyUsageDataEncipherment:  "data encipherment",
	x509.KeyUsageCertSign:          "cert sign",
	x509.KeyUsageCRLSign:           "crl sign",
	x509.KeyUsageEncipherOnly:      "encipher only",
	x509.KeyUsageDecipherOnly:      "decipher only",
}

// ExtKeyUsage contains a mapping of string names to extended key
// usages.
var ExtKeyUsage = map[string]x509.ExtKeyUsage{
	"any":              x509.ExtKeyUsageAny,
	"server auth":      x509.ExtKeyUsageServerAuth,
	"client auth":      x509.ExtKeyUsageClientAuth,
	"code signing":     x509.ExtKeyUsageCodeSigning,
	"email protection": x509.ExtKeyUsageEmailProtection,
	"s/mime":           x509.ExtKeyUsageEmailProtection,
	"ipsec end system": x509.ExtKeyUsageIPSECEndSystem,
	"ipsec tunnel":     x509.ExtKeyUsageIPSECTunnel,
	"ipsec user":       x509.ExtKeyUsageIPSECUser,
	"timestamping":     x509.ExtKeyUsageTimeStamping,
	"ocsp signing":     x509.ExtKeyUsageOCSPSigning,
	"microsoft sgc":    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"netscape sgc":     x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// ExtKeyUsageName provides map of names
var ExtKeyUsageName = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "any",
	x509.ExtKeyUsageServerAuth:                 "server auth",
	x509.ExtKeyUsageClientAuth:                 "client auth",
	x509.ExtKeyUsageCodeSigning:                "code signing",
	x509.ExtKeyUsageEmailProtection:            "email protection",
	x509.ExtKeyUsageIPSECEndSystem:             "ipsec end system",
	x509.ExtKeyUsageIPSECTunnel:                "ipsec tunnel",
	x509.ExtKeyUsageIPSECUser:                  "ipsec user",
	x509.ExtKeyUsageTimeStamping:               "timestamping",
	x509.ExtKeyUsageOCSPSigning:                "ocsp signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "microsoft sgc",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "netscape sgc",
}

// well-known OIDs
var (
	ExtensionSubjectKeyID          = asn1.ObjectIdentifier{2, 5, 29, 14}
	ExtensionKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	ExtensionSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	ExtensionBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	ExtensionCRLNumber             = asn1.ObjectIdentifier{2, 5, 29, 20}
	ExtensionNameConstraints       = asn1.ObjectIdentifier{2, 5, 29, 30}
	ExtensionCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	ExtensionCertificatePolicies   = asn1.ObjectIdentifier{2, 5, 29, 32}
	ExtensionAuthorityKeyID        = asn1.ObjectIdentifier{2, 5, 29, 35}
	ExtensionExtendedKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	ExtensionAuthorityInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	AuthorityInfoAccessOcsp        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	OCSPNoCheck                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	AuthorityInfoAccessIssuers     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}

	NameEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	NameCN           = asn1.ObjectIdentifier{2, 5, 4, 3}
	NameSerial       = asn1.ObjectIdentifier{2, 5, 4, 5}
	NameC            = asn1.ObjectIdentifier{2, 5, 4, 6}
	NameL            = asn1.ObjectIdentifier{2, 5, 4, 7}
	NameST           = asn1.ObjectIdentifier{2, 5, 4, 8}
	NameStreet       = asn1.ObjectIdentifier{2, 5, 4, 9}
	NameO            = asn1.ObjectIdentifier{2, 5, 4, 10}
	NameOU           = asn1.ObjectIdentifier{2, 5, 4, 11}
	NamePostal       = asn1.ObjectIdentifier{2, 5, 4, 17}
)

// DisplayName provides OID name
var DisplayName = map[string]string{
	"2.5.29.14":            "Subject KeyID",
	"2.5.29.15":            "Key Usage",
	"2.5.29.17":            "Subject Alt Name",
	"2.5.29.19":            "Basic Constraints",
	"2.5.29.20":            "CRL Number",
	"2.5.29.30":            "Name Constraints",
	"2.5.29.31":            "CRL Distribution Point",
	"2.5.29.32":            "Certificate Policies",
	"2.5.29.35":            "Authority KeyID",
	"2.5.29.37":            "Extended KeyUsage",
	"1.3.6.1.5.5.7.1.1":    "Authority Info Access",
	"1.3.6.1.5.5.7.48.1":   "OCPS",
	"1.3.6.1.5.5.7.48.1.5": "OCPS No Check",
	"1.3.6.1.5.5.7.48.2":   "Issuers",
}

// KeyUsages returns list of names
func KeyUsages(ku x509.KeyUsage) []string {
	list := make([]string, 0, len(KeyUsage))

	for k, v := range KeyUsage {
		if ku&v == v {
			list = append(list, k)
		}
	}

	return list
}

// ExtKeyUsages returns list of names
func ExtKeyUsages(eku ...x509.ExtKeyUsage) []string {
	list := make([]string, 0, len(eku))

	for _, k := range eku {
		list = append(list, ExtKeyUsageName[k])
	}

	return list
}

// Strings returns list of OID string values
func Strings(ids ...asn1.ObjectIdentifier) []string {
	list := make([]string, 0, len(ids))

	for _, k := range ids {
		list = append(list, k.String())
	}

	return list
}
