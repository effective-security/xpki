package certutil

import (
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
