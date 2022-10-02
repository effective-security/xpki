package oid_test

import (
	"crypto/x509"
	"testing"

	"github.com/effective-security/xpki/oid"
	"github.com/stretchr/testify/assert"
)

func Test_KeyUsages(t *testing.T) {
	assert.Equal(t, []string{"cert sign"}, oid.KeyUsages(x509.KeyUsageCertSign))
}

func Test_ExtKeyUsages(t *testing.T) {
	assert.Equal(t, []string{"client auth"}, oid.ExtKeyUsages(x509.ExtKeyUsageClientAuth))
}

func Test_PolicyIdentifiers(t *testing.T) {
	assert.Equal(t, []string{"1.3.6.1.5.5.7.48.2"}, oid.Strings(oid.AuthorityInfoAccessIssuers))
}
