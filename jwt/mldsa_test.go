package jwt_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/v2/jwt"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mldsaTestIssuer  = "mldsa-issuer"
	mldsaTestSubject = "alice"
)

// mldsaCases tables the RFC 9964 algorithms.
var mldsaCases = []struct {
	alg    string
	jose   jose.SignatureAlgorithm
	params mldsa.Parameters
}{
	{"ML-DSA-44", jose.MLDSA44, mldsa.MLDSA44()},
	{"ML-DSA-65", jose.MLDSA65, mldsa.MLDSA65()},
	{"ML-DSA-87", jose.MLDSA87, mldsa.MLDSA87()},
}

func mldsaTestClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": mldsaTestIssuer,
		"sub": mldsaTestSubject,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
	}
}

func newMLDSAKey(t testing.TB, params mldsa.Parameters) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(params)
	require.NoError(t, err)
	return key
}

// signWithJose returns a token signed by go-jose, the independent RFC 9964
// implementation.
func signWithJose(t *testing.T, alg jose.SignatureAlgorithm, key crypto.Signer, kid string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader(jose.HeaderKey("kid"), kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}, opts)
	require.NoError(t, err)
	token, err := josejwt.Signed(signer).Claims(map[string]any(mldsaTestClaims())).Serialize()
	require.NoError(t, err)
	return token
}

// TestProviderMLDSA signs through a provider key that enforces the ML-DSA
// signer contract, verifies with the provider and with go-jose, and verifies
// a go-jose token with the provider.
func TestProviderMLDSA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range mldsaCases {
		t.Run(tc.alg, func(t *testing.T) {
			t.Parallel()
			priv, err := inmemcrypto.NewProvider().GenerateKey(ctx, &cryptoprov.GenerateKeyRequest{
				Label: "jwt",
				Type:  certutil.KeyTypeMLDSA,
				Size:  cryptoprov.MLDSASize(tc.params),
			})
			require.NoError(t, err)
			signer := priv.(crypto.Signer)
			p, err := jwt.NewProviderFromCryptoSigner(signer)
			require.NoError(t, err)
			assert.Equal(t, signer.Public(), p.PublicKey())

			token, err := p.Sign(ctx, mldsaTestClaims())
			require.NoError(t, err)

			header := tokenHeader(t, token)
			assert.Equal(t, tc.alg, header["alg"])
			assert.Equal(t, "JWT", header["typ"])
			jwk, ok := header["jwk"].(map[string]any)
			require.True(t, ok, "%v", header["jwk"])
			assert.Equal(t, "AKP", jwk["kty"])
			assert.Equal(t, tc.alg, jwk["alg"])
			assert.NotEmpty(t, jwk["pub"])
			assert.NotContains(t, jwk, "priv")

			claims, err := p.ParseToken(ctx, token, &jwt.VerifyConfig{ExpectedSubject: mldsaTestSubject})
			require.NoError(t, err)
			assert.Equal(t, mldsaTestSubject, claims["sub"])

			// go-jose verifies what the provider signed
			parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{tc.jose})
			require.NoError(t, err)
			out := map[string]any{}
			require.NoError(t, parsed.Claims(signer.Public(), &out))
			assert.Equal(t, mldsaTestSubject, out["sub"])
			require.NotNil(t, parsed.Headers[0].JSONWebKey)
			assert.True(t, parsed.Headers[0].JSONWebKey.IsPublic())

			// the provider verifies what go-jose signed with the same key
			seedKey := newMLDSAKey(t, tc.params)
			joseProvider, err := jwt.NewProviderFromCryptoSigner(seedKey)
			require.NoError(t, err)
			claims, err = joseProvider.ParseToken(ctx, signWithJose(t, tc.jose, seedKey, ""), &jwt.VerifyConfig{})
			require.NoError(t, err)
			assert.Equal(t, mldsaTestSubject, claims["sub"])

			// tampered payload, and tampered signature
			parts := strings.Split(token, ".")
			require.Len(t, parts, 3)
			forged := parts[0] + "." + jwt.EncodeSegment([]byte(`{"sub":"mallory"}`)) + "." + parts[2]
			_, err = p.ParseToken(ctx, forged, &jwt.VerifyConfig{})
			require.ErrorContains(t, err, "unable to verify token")

			sig, err := jwt.DecodeSegment(parts[2])
			require.NoError(t, err)
			sig[0] ^= 0xFF
			forged = parts[0] + "." + parts[1] + "." + jwt.EncodeSegment(sig)
			_, err = p.ParseToken(ctx, forged, &jwt.VerifyConfig{})
			require.ErrorContains(t, err, "unable to verify token")
		})
	}
}

// TestNewProviderMLDSAFromPEM loads a provider from a PEM configuration, as
// LoadProvider does.
func TestNewProviderMLDSAFromPEM(t *testing.T) {
	t.Parallel()
	key := newMLDSAKey(t, mldsa.MLDSA65())
	keyPEM, err := certutil.EncodePrivateKeyToPEM(key)
	require.NoError(t, err)
	providers, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
	require.NoError(t, err)

	p, err := jwt.NewProvider(t.Context(), &jwt.ProviderConfig{
		Issuer:     mldsaTestIssuer,
		PrivateKey: string(keyPEM),
	}, providers)
	require.NoError(t, err)
	assert.True(t, key.PublicKey().Equal(p.PublicKey()))

	token, err := p.Sign(context.Background(), mldsaTestClaims())
	require.NoError(t, err)
	assert.Equal(t, "ML-DSA-65", tokenHeader(t, token)["alg"])
	_, err = p.ParseToken(context.Background(), token, &jwt.VerifyConfig{ExpectedIssuer: mldsaTestIssuer})
	require.NoError(t, err)
}

// TestProviderMLDSAAlgorithmPin keeps a provider to its own algorithm
// (XPKI-112): the same parameter set from another key fails the signature,
// any other algorithm fails before the key is used.
func TestProviderMLDSAAlgorithmPin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := newMLDSAKey(t, mldsa.MLDSA65())
	p, err := jwt.NewProviderFromCryptoSigner(key)
	require.NoError(t, err)

	_, err = p.ParseToken(ctx, signWithJose(t, jose.MLDSA44, newMLDSAKey(t, mldsa.MLDSA44()), ""), &jwt.VerifyConfig{})
	require.EqualError(t, err, "unable to verify token: unsupported signing method: ML-DSA-44")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = p.ParseToken(ctx, signWithJose(t, jose.RS256, rsaKey, ""), &jwt.VerifyConfig{})
	require.EqualError(t, err, "unable to verify token: unsupported signing method: RS256")

	_, err = p.ParseToken(ctx, signWithJose(t, jose.MLDSA65, newMLDSAKey(t, mldsa.MLDSA65()), ""), &jwt.VerifyConfig{})
	require.ErrorContains(t, err, "unable to verify token")

	// an alg header that contradicts the key is a constructor error
	_, err = jwt.NewProviderFromCryptoSigner(key, jwt.WithHeaders(map[string]any{"alg": "ML-DSA-87"}))
	require.EqualError(t, err, "alg header ML-DSA-87 does not match the signing algorithm ML-DSA-65")
}

// stubSigner is a crypto.Signer with a given public key and Sign result.
type stubSigner struct {
	pub crypto.PublicKey
	err error
}

func (s stubSigner) Public() crypto.PublicKey { return s.pub }

func (s stubSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

// TestNewSignerInfoMLDSAErrors covers keys that must fail, not panic.
func TestNewSignerInfoMLDSAErrors(t *testing.T) {
	t.Parallel()
	var nilKey *mldsa.PublicKey
	_, err := jwt.NewSignerInfo(stubSigner{pub: nilKey})
	require.EqualError(t, err, "invalid ML-DSA public key")
	_, err = jwt.NewSignerInfo(stubSigner{pub: &mldsa.PublicKey{}})
	require.EqualError(t, err, "invalid ML-DSA public key")
	var nilPriv *mldsa.PrivateKey
	_, err = jwt.NewSignerInfo(nilPriv)
	require.EqualError(t, err, "invalid ML-DSA private key")
	_, err = jwt.NewSignerInfo(&mldsa.PrivateKey{})
	require.EqualError(t, err, "invalid ML-DSA private key")

	// a backend failure reaches the caller
	p, err := jwt.NewProviderFromCryptoSigner(stubSigner{
		pub: newMLDSAKey(t, mldsa.MLDSA44()).Public(),
		err: errors.New("backend failed"),
	})
	require.NoError(t, err)
	_, err = p.Sign(context.Background(), mldsaTestClaims())
	require.EqualError(t, err, "backend failed")
}

// TestVerifySignatureMLDSA tables the failures of a verification.
func TestVerifySignatureMLDSA(t *testing.T) {
	t.Parallel()
	const signingString = "header.payload"
	key := newMLDSAKey(t, mldsa.MLDSA65())
	sig, err := key.Sign(rand.Reader, []byte(signingString), nil)
	require.NoError(t, err)
	encoded := jwt.EncodeSegment(sig)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var nilKey *mldsa.PublicKey

	require.NoError(t, jwt.VerifySignature("ML-DSA-65", signingString, encoded, key.PublicKey()))

	for _, tc := range []struct {
		name          string
		alg           string
		signingString string
		signature     string
		key           any
		err           string
	}{
		{
			name:      "other key of the parameter set",
			alg:       "ML-DSA-65",
			signature: encoded,
			key:       newMLDSAKey(t, mldsa.MLDSA65()).PublicKey(),
			err:       "mldsa: invalid signature",
		},
		{
			name:          "other message",
			alg:           "ML-DSA-65",
			signingString: signingString + "x",
			signature:     encoded,
			key:           key.PublicKey(),
			err:           "mldsa: invalid signature",
		},
		{
			name:      "truncated signature",
			alg:       "ML-DSA-65",
			signature: jwt.EncodeSegment(sig[:len(sig)-1]),
			key:       key.PublicKey(),
			err:       "mldsa: invalid signature",
		},
		{
			name:      "not base64url",
			alg:       "ML-DSA-65",
			signature: "!",
			key:       key.PublicKey(),
			err:       "invalid signature",
		},
		{
			name:      "algorithm of another parameter set",
			alg:       "ML-DSA-44",
			signature: encoded,
			key:       key.PublicKey(),
			err:       "invalid key for ML-DSA-44 signature: *mldsa.PublicKey",
		},
		{
			name:      "RSA key",
			alg:       "ML-DSA-65",
			signature: encoded,
			key:       &rsaKey.PublicKey,
			err:       "invalid key for ML-DSA-65 signature: *rsa.PublicKey",
		},
		{
			name:      "private key",
			alg:       "ML-DSA-65",
			signature: encoded,
			key:       key,
			err:       "invalid key for ML-DSA-65 signature: *mldsa.PrivateKey",
		},
		{
			name:      "nil key",
			alg:       "ML-DSA-65",
			signature: encoded,
			key:       nilKey,
			err:       "invalid key for ML-DSA-65 signature: *mldsa.PublicKey",
		},
		{
			name:      "zero key",
			alg:       "ML-DSA-65",
			signature: encoded,
			key:       &mldsa.PublicKey{},
			err:       "invalid key for ML-DSA-65 signature: *mldsa.PublicKey",
		},
		{
			name:      "no key",
			alg:       "ML-DSA-65",
			signature: encoded,
			err:       "invalid key for ML-DSA-65 signature: <nil>",
		},
		{
			name:      "ML-DSA key for RS256",
			alg:       "RS256",
			signature: encoded,
			key:       key.PublicKey(),
			err:       "invalid key type for RSA signature: *mldsa.PublicKey",
		},
		{
			name:      "ML-DSA key for ES256",
			alg:       "ES256",
			signature: jwt.EncodeSegment(make([]byte, 64)),
			key:       key.PublicKey(),
			err:       "invalid key type for ECDSA signature: *mldsa.PublicKey",
		},
		{
			name:      "ECDSA key",
			alg:       "ML-DSA-87",
			signature: encoded,
			key:       &ecKey.PublicKey,
			err:       "invalid key for ML-DSA-87 signature: *ecdsa.PublicKey",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			message := tc.signingString
			if message == "" {
				message = signingString
			}
			err := jwt.VerifySignature(tc.alg, message, tc.signature, tc.key)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.err)
		})
	}
}

// TestParserMLDSA verifies tokens with a third-party parser: an AKP key from a
// JWKS document, selected by kid, by thumbprint or as the only key, statically
// and over HTTP.
func TestParserMLDSA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range mldsaCases {
		t.Run(tc.alg, func(t *testing.T) {
			t.Parallel()
			key := newMLDSAKey(t, tc.params)
			const kid = "mldsa-key-1"

			document, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key:   key.PublicKey(),
				KeyID: kid,
				Use:   "sig",
			}}})
			require.NoError(t, err)
			assert.Contains(t, string(document), `"kty":"AKP"`)
			assert.Contains(t, string(document), `"alg":"`+tc.alg+`"`)
			set := new(jose.JSONWebKeySet)
			require.NoError(t, json.Unmarshal(document, set))

			static, err := jwt.NewParser(&jwt.ParserConfig{JWKeySet: set})
			require.NoError(t, err)
			token := signWithJose(t, tc.jose, key, kid)
			claims, err := static.ParseToken(ctx, token, &jwt.VerifyConfig{ExpectedSubject: mldsaTestSubject})
			require.NoError(t, err)
			assert.Equal(t, mldsaTestSubject, claims["sub"])

			// without a kid the only eligible key is used
			_, err = static.ParseToken(ctx, signWithJose(t, tc.jose, key, ""), &jwt.VerifyConfig{})
			require.NoError(t, err)

			// another key under the same kid fails the signature
			_, err = static.ParseToken(ctx, signWithJose(t, tc.jose, newMLDSAKey(t, tc.params), kid), &jwt.VerifyConfig{})
			require.Error(t, err)

			remote := newJWKSServer(t, jose.JSONWebKey{Key: key.PublicKey(), KeyID: kid})
			overHTTP, err := jwt.NewParser(&jwt.ParserConfig{JWKSURI: remote.URL})
			require.NoError(t, err)
			_, err = overHTTP.ParseToken(ctx, token, &jwt.VerifyConfig{})
			require.NoError(t, err)
		})
	}
}

// TestStaticKeySetMLDSA covers the key selection rules for ML-DSA keys.
func TestStaticKeySetMLDSA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key65 := newMLDSAKey(t, mldsa.MLDSA65()).PublicKey()
	key44 := newMLDSAKey(t, mldsa.MLDSA44()).PublicKey()

	set := &jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{key65}}
	got, err := set.GetKey(ctx, "")
	require.NoError(t, err)
	assert.True(t, key65.Equal(got))

	// a raw public key is found by its RFC 7638 thumbprint
	tp, err := (&jose.JSONWebKey{Key: key65}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	got, err = set.GetKey(ctx, base64.RawURLEncoding.EncodeToString(tp))
	require.NoError(t, err)
	assert.True(t, key65.Equal(got))
	_, err = set.GetKey(ctx, "other")
	require.ErrorIs(t, err, jwt.ErrKeyNotFound)

	// the alg picks the parameter set
	mixed := &jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{key65, key44}}
	got, err = mixed.GetKeyForAlgorithm(ctx, "", "ML-DSA-44")
	require.NoError(t, err)
	assert.True(t, key44.Equal(got))
	_, err = mixed.GetKeyForAlgorithm(ctx, "", "ML-DSA-87")
	require.ErrorIs(t, err, jwt.ErrKeyNotFound)
	_, err = mixed.GetKey(ctx, "")
	require.ErrorIs(t, err, jwt.ErrAmbiguousKey, "no alg: two eligible keys")
	_, err = mixed.GetKeyForAlgorithm(ctx, "", "RS256")
	require.ErrorIs(t, err, jwt.ErrKeyNotFound)

	// a JWK that restricts itself, and a private key, are not eligible
	for name, jwk := range map[string]jose.JSONWebKey{
		"encryption use": {Key: key65, Use: "enc"},
		"other alg":      {Key: key65, Algorithm: "ML-DSA-44"},
		"private key":    {Key: newMLDSAKey(t, mldsa.MLDSA65())},
	} {
		_, err = (&jwt.StaticKeySet{KeySet: []jose.JSONWebKey{jwk}}).GetKeyForAlgorithm(ctx, "", "ML-DSA-65")
		require.ErrorIs(t, err, jwt.ErrKeyNotFound, name)
	}

	// an uninitialized key fails the lookup, never panics
	var nilKey *mldsa.PublicKey
	for _, bad := range []*mldsa.PublicKey{nilKey, {}} {
		_, err = (&jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{bad}}).GetKey(ctx, "")
		require.EqualError(t, err, "invalid ML-DSA public key at index 0")
		_, err = (&jwt.StaticKeySet{KeySet: []jose.JSONWebKey{{Key: bad}}}).GetKeyForAlgorithm(ctx, "", "ML-DSA-65")
		require.ErrorIs(t, err, jwt.ErrKeyNotFound)
	}
}
