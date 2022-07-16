package certutil_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
)

func TestFindExtension(t *testing.T) {
	list := []pkix.Extension{
		{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 25},
			Value: []byte{05, 00},
		},
	}

	ext := certutil.FindExtension(nil, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26})
	assert.Nil(t, ext)
	ext = certutil.FindExtension(list, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 25})
	assert.Equal(t, list[0], *ext)

	val := certutil.FindExtensionValue(nil, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 26})
	assert.Nil(t, val)
	val = certutil.FindExtensionValue(list, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 25})
	assert.Equal(t, list[0].Value, val)
}
