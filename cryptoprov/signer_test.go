package cryptoprov_test

import (
	"testing"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/testprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSigner(t *testing.T) {
	p11 := loadP11Provider(t)

	inm, err := testprov.Init()
	require.NoError(t, err)

	cp, err := cryptoprov.New(p11, []cryptoprov.Provider{inm})
	require.NoError(t, err)

	_, err = cp.NewSignerFromFromFile("not_found")
	assert.EqualError(t, err, "load key file: open not_found: no such file or directory")

	_, err = cp.NewSignerFromFromFile("testdata/invalid_uri.json")
	assert.EqualError(t, err, "load key file: open testdata/invalid_uri.json: no such file or directory")
}
