package oid_test

import (
	"crypto/x509"
	"testing"

	"github.com/effective-security/xpki/oid"
	"github.com/stretchr/testify/assert"
)

func Test_KeyUsages(t *testing.T) {
	tcases := []struct {
		name string
		ku   x509.KeyUsage
		exp  []string
	}{
		{"none", 0, []string{}},
		{"single", x509.KeyUsageCertSign, []string{"cert sign"}},
		{
			"signing_reported_once",
			x509.KeyUsageDigitalSignature,
			[]string{"signing"},
		},
		{
			"bit_order",
			x509.KeyUsageCRLSign | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			[]string{"signing", "key encipherment", "cert sign", "crl sign"},
		},
		{
			"all",
			x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign |
				x509.KeyUsageCRLSign | x509.KeyUsageEncipherOnly | x509.KeyUsageDecipherOnly,
			[]string{
				"signing", "content commitment", "key encipherment", "data encipherment",
				"key agreement", "cert sign", "crl sign", "encipher only", "decipher only",
			},
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			// run several times: the result must not depend on map iteration order
			for range 5 {
				assert.Equal(t, tc.exp, oid.KeyUsages(tc.ku))
			}
		})
	}
}

func Test_ExtKeyUsages(t *testing.T) {
	assert.Equal(t, []string{"client auth"}, oid.ExtKeyUsages(x509.ExtKeyUsageClientAuth))
}

func Test_PolicyIdentifiers(t *testing.T) {
	assert.Equal(t, []string{"1.3.6.1.5.5.7.48.2"}, oid.Strings(oid.AuthorityInfoAccessIssuers))
}
