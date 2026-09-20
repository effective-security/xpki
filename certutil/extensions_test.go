package certutil_test

import (
	"crypto/x509"
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

func TestHasOCSPNoCheck(t *testing.T) {
	noCheck := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
		Value: []byte{0x05, 0x00},
	}
	other := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1},
		Value: []byte{0x05, 0x00},
	}

	tcases := []struct {
		name string
		crt  x509.Certificate
		exp  bool
	}{
		{name: "empty", crt: x509.Certificate{}, exp: false},
		{name: "other_only", crt: x509.Certificate{Extensions: []pkix.Extension{other}}, exp: false},
		{name: "parsed", crt: x509.Certificate{Extensions: []pkix.Extension{other, noCheck}}, exp: true},
		{name: "template", crt: x509.Certificate{ExtraExtensions: []pkix.Extension{noCheck}}, exp: true},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.exp, certutil.HasOCSPNoCheck(&tc.crt))
		})
	}
}
