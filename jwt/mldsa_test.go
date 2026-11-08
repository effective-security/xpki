package jwt_test

import (
	"crypto/mldsa"
	"testing"

	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/require"
)

// TestNewProviderFromCryptoSignerMLDSA records that the JWT provider does
// not sign with ML-DSA keys yet (RFC 9964 is a later milestone): the key is
// rejected with an error, never signed with a hash or panicked on.
func TestNewProviderFromCryptoSignerMLDSA(t *testing.T) {
	t.Parallel()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	_, err = jwt.NewProviderFromCryptoSigner(key)
	require.EqualError(t, err, "public key not supported: *mldsa.PublicKey")
	_, err = jwt.NewSignerInfo(key)
	require.EqualError(t, err, "public key not supported: *mldsa.PublicKey")
}
