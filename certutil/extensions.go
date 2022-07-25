package certutil

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// FindExtensionValue returns extension value, or nil
func FindExtensionValue(list []pkix.Extension, oid asn1.ObjectIdentifier) []byte {
	for _, e := range list {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	return nil
}

// FindExtension returns extension, or nil
func FindExtension(list []pkix.Extension, oid asn1.ObjectIdentifier) *pkix.Extension {
	for idx, e := range list {
		if e.Id.Equal(oid) {
			return &list[idx]
		}
	}
	return nil
}

// IsOCSPSigner returns true for OCSP key usage
func IsOCSPSigner(crt *x509.Certificate) bool {
	for _, eku := range crt.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	return false
}

var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// HasOCSPNoCheck returns true if certificate has ocsp-no-check
func HasOCSPNoCheck(crt *x509.Certificate) bool {
	return FindExtension(crt.Extensions, oidOCSPNoCheck) != nil
}
