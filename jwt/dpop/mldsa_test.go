package dpop_test

import (
	"crypto"
	"crypto/mldsa"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/v2/jwt/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testAccessToken = "access-token"

// TestSignerMLDSA creates proofs through a provider key that enforces the
// ML-DSA signer contract and verifies them as a server does, with the token
// binding and the replay cache.
func TestSignerMLDSA(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		alg    jose.SignatureAlgorithm
		params mldsa.Parameters
	}{
		{jose.MLDSA44, mldsa.MLDSA44()},
		{jose.MLDSA65, mldsa.MLDSA65()},
		{jose.MLDSA87, mldsa.MLDSA87()},
	} {
		t.Run(string(tc.alg), func(t *testing.T) {
			t.Parallel()
			priv, err := inmemcrypto.NewProvider().GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
				Label: "dpop",
				Type:  certutil.KeyTypeMLDSA,
				Size:  cryptoprov.MLDSASize(tc.params),
			})
			require.NoError(t, err)
			signer, err := dpop.NewSigner(priv.(crypto.Signer))
			require.NoError(t, err)
			assert.NotEmpty(t, signer.JWKThumbprint())

			req := httptest.NewRequest(http.MethodPost, testHTU, nil)
			proof, err := dpop.ForRequest(signer, req, map[string]any{
				dpop.ClaimAccessTokenHash: dpop.AccessTokenHash(testAccessToken),
			})
			require.NoError(t, err)
			assert.Equal(t, proof, req.Header.Get(dpop.HTTPHeader))
			t.Logf("%s proof: %d bytes", tc.alg, len(proof))

			cache := dpop.NewMemoryReplayCache(1)
			cfg := dpop.VerifyConfig{
				ReplayCache:        cache,
				AccessToken:        testAccessToken,
				ExpectedThumbprint: signer.JWKThumbprint(),
			}
			res, err := dpop.VerifyRequestClaims(cfg, req)
			require.NoError(t, err)
			assert.Equal(t, signer.JWKThumbprint(), res.Thumbprint)
			assert.Equal(t, dpop.AccessTokenHash(testAccessToken), res.AccessTokenHash)
			require.NotNil(t, res.Key)
			assert.True(t, res.Key.IsPublic())
			pub, ok := res.Key.Key.(*mldsa.PublicKey)
			require.True(t, ok, "%T", res.Key.Key)
			assert.Equal(t, tc.params, pub.Parameters())

			// the proof is used once
			_, err = dpop.VerifyRequestClaims(cfg, req)
			require.ErrorIs(t, err, dpop.ErrReplay)

			// and is bound to its key
			other, err := dpop.NewSigner(newMLDSAKey(t, tc.params))
			require.NoError(t, err)
			cfg.ReplayCache = nil
			cfg.ExpectedThumbprint = other.JWKThumbprint()
			_, err = dpop.VerifyRequestClaims(cfg, req)
			require.EqualError(t, err, "dpop: proof key does not match cnf.jkt")

			info := dpop.GetTokenInfo(proof)
			require.NotNil(t, info)
			assert.Equal(t, signer.JWKThumbprint(), info.Thumbprint)
			assert.True(t, info.IsPublicKey)
		})
	}
}

// TestKeysMLDSA stores an ML-DSA key as an AKP JWK, reads it back and signs
// with it.
func TestKeysMLDSA(t *testing.T) {
	t.Parallel()
	key := newMLDSAKey(t, mldsa.MLDSA65())
	jwk := &jose.JSONWebKey{Key: key, KeyID: "mldsa"}

	fn, err := dpop.SaveKey(t.TempDir(), jwk)
	require.NoError(t, err)
	info, err := os.Stat(fn)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the file holds the private seed")

	loaded, thumbprint, err := dpop.LoadKey(fn)
	require.NoError(t, err)
	assert.False(t, loaded.IsPublic())
	assert.Equal(t, "mldsa", loaded.KeyID)
	want, err := dpop.Thumbprint(jwk)
	require.NoError(t, err)
	assert.Equal(t, want, thumbprint)

	signer, err := dpop.NewSigner(loaded.Key.(crypto.Signer))
	require.NoError(t, err)
	assert.Equal(t, want, signer.JWKThumbprint())
	req := httptest.NewRequest(http.MethodGet, testHTU, nil)
	_, err = dpop.ForRequest(signer, req, nil)
	require.NoError(t, err)
	res, err := dpop.VerifyRequestClaims(dpop.VerifyConfig{ExpectedThumbprint: want}, req)
	require.NoError(t, err)
	assert.Equal(t, want, res.Thumbprint)
}

// TestThumbprintInvalidKey keeps uninitialized keys, on which go-jose panics,
// to an error, for every function that takes a JWK from a caller.
func TestThumbprintInvalidKey(t *testing.T) {
	t.Parallel()
	var nilPub *mldsa.PublicKey
	for name, key := range map[string]*jose.JSONWebKey{
		"nil JWK":        nil,
		"no key":         {},
		"zero public":    {Key: &mldsa.PublicKey{}},
		"nil public":     {Key: nilPub},
		"zero private":   {Key: &mldsa.PrivateKey{}},
		"not a real key": {Key: "secret"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := dpop.Thumbprint(key)
			require.EqualError(t, err, "dpop: unable to get thumbprint")
			_, err = dpop.SaveKey(t.TempDir(), key)
			require.Error(t, err)
		})
	}
	_, err := dpop.NewSigner(&mldsa.PrivateKey{})
	require.EqualError(t, err, "invalid ML-DSA private key")
}
