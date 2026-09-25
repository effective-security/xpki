package jwt_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/x/configloader"
	"github.com/effective-security/xpki/jwt"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParserConfig(t *testing.T) {
	var cfg jwt.ParserConfig
	err := configloader.UnmarshalAndExpand("testdata/oidc_parser.json", &cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", cfg.Issuer)
	require.NotNil(t, cfg.JWKeySet)
	assert.Equal(t, 2, len(cfg.JWKeySet.Keys))

	var cfg2 jwt.ParserConfig
	err = configloader.UnmarshalAndExpand("testdata/oidc_parser.yaml", &cfg2)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", cfg2.Issuer)
	require.NotNil(t, cfg2.JWKeySet)
	assert.Equal(t, 2, len(cfg2.JWKeySet.Keys))

	var cfg3 jwt.ParserConfig
	err = configloader.UnmarshalAndExpand("testdata/oidc_parser_uri.yaml", &cfg3)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", cfg3.Issuer)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/certs", cfg3.JWKSURI)
	assert.Nil(t, cfg3.JWKeySet)
}

func Test_ParseJwks(t *testing.T) {
	var cfg jwt.ParserConfig
	err := configloader.UnmarshalAndExpand("testdata/oidc_parser_cognito.json", &cfg)
	require.NoError(t, err)

	ctx := context.Background()
	parser, err := jwt.NewParser(&cfg)
	require.NoError(t, err)

	t.Run("cognito", func(t *testing.T) {
		_, err = parser.ParseToken(ctx, idTokenCognito, nil)
		assert.Error(t, err)

		jwt.TimeNowFn = func() time.Time {
			return time.Date(2023, time.October, 13, 9, 40, 0, 0, time.UTC)
		}
		defer func() {
			jwt.TimeNowFn = time.Now
		}()
		claims, err := parser.ParseToken(ctx, idTokenCognito, nil)
		require.NoError(t, err)

		var stdClaims jwt.Claims
		require.NoError(t, claims.To(&stdClaims))
		assert.Empty(t, stdClaims.Email)
		assert.False(t, stdClaims.EmailVerified)
		assert.Equal(t, "5cc08bb4-4ce8-4df2-9af8-cd28af927dd9", stdClaims.Subject)
		assert.NotNil(t, stdClaims.Expiry)
		assert.NotNil(t, stdClaims.IssuedAt)
		assert.Empty(t, stdClaims.Audience)
	})
}

func Test_RemoteKeySet_GetKey_CacheHit(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	body, err := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: "test-kid", Algorithm: "RS256", Use: "sig"},
		},
	})
	require.NoError(t, err)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ctx := context.Background()
	ks := jwt.NewRemoteKeySet(ctx, srv.URL)

	// First call: cache miss, fetched fresh from the server.
	key, err := ks.GetKey(ctx, "test-kid")
	require.NoError(t, err)
	_, ok := key.(*rsa.PublicKey)
	assert.True(t, ok, "expected *rsa.PublicKey on cache miss, got %T", key)

	// Second call: cache hit, fetched from the cache rather than the server.
	key, err = ks.GetKey(ctx, "test-kid")
	require.NoError(t, err)
	_, ok = key.(*rsa.PublicKey)
	assert.True(t, ok, "expected *rsa.PublicKey on cache hit, got %T", key)

	// Confirms the second call came from cache rather than
	// coincidentally succeeding via another real fetch.
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits), "server should only be hit once")
}

type jwksTestKeys struct {
	rsa  *rsa.PrivateKey
	rsa2 *rsa.PrivateKey
	p256 *ecdsa.PrivateKey
	p384 *ecdsa.PrivateKey
}

func newJWKSTestKeys(t *testing.T) *jwksTestKeys {
	t.Helper()
	rsa1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsa2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	return &jwksTestKeys{rsa: rsa1, rsa2: rsa2, p256: p256, p384: p384}
}

func thumbprintKeyID(t *testing.T, key crypto.PublicKey) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: key}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(tp)
}

// TestStaticKeySetSelection covers XPKI-071 and XPKI-072 key selection.
func TestStaticKeySetSelection(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	rsaPub, rsa2Pub := &k.rsa.PublicKey, &k.rsa2.PublicKey
	p256Pub, p384Pub := &k.p256.PublicKey, &k.p384.PublicKey

	encRSA := jose.JSONWebKey{Key: rsaPub, KeyID: "enc", Use: "enc"}
	sigRSA := jose.JSONWebKey{Key: rsaPub, KeyID: "rsa", Use: "sig", Algorithm: "RS256"}
	sigRSA2 := jose.JSONWebKey{Key: rsa2Pub, KeyID: "rsa2"}
	sigEC := jose.JSONWebKey{Key: p256Pub, KeyID: "ec", Use: "sig"}
	sameKidRSA := jose.JSONWebKey{Key: rsaPub, KeyID: "same"}
	sameKidEC := jose.JSONWebKey{Key: p256Pub, KeyID: "same"}
	rs384Only := jose.JSONWebKey{Key: rsaPub, KeyID: "rs384", Algorithm: "RS384"}
	p384Key := jose.JSONWebKey{Key: p384Pub, KeyID: "p384"}

	for _, tc := range []struct {
		name       string
		set        jwt.StaticKeySet
		kid, alg   string
		want       any
		wantErr    string
		wantErrIs  error
		wantAnyAlg bool // also run GetKey (alg-agnostic) with the same expectation
	}{
		{name: "empty kid single key", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigRSA}}, alg: "RS256", want: rsaPub, wantAnyAlg: true},
		{name: "empty kid skips enc key", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{encRSA, sigEC}}, alg: "ES256", want: p256Pub, wantAnyAlg: true},
		{name: "empty kid skips enc key reordered", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigEC, encRSA}}, alg: "ES256", want: p256Pub, wantAnyAlg: true},
		{name: "empty kid only enc key", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{encRSA}}, alg: "RS256", wantErr: `no signing key for kid="" alg="RS256": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "empty kid two signing keys", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigRSA, sigRSA2}}, alg: "RS256", wantErr: `kid="" alg="RS256" matches 2 keys: ambiguous key`, wantErrIs: jwt.ErrAmbiguousKey},
		{name: "empty kid alg picks key type", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigRSA, sigEC}}, alg: "ES256", want: p256Pub},
		{name: "empty kid alg picks key type reordered", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigEC, sigRSA}}, alg: "RS256", want: rsaPub},
		{name: "empty kid no alg is ambiguous", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigRSA, sigEC}}, wantErr: `kid="" alg="" matches 2 keys: ambiguous key`, wantErrIs: jwt.ErrAmbiguousKey},
		{name: "empty set", set: jwt.StaticKeySet{}, alg: "RS256", wantErr: `kid="": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "kid match", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigRSA, sigEC}}, kid: "ec", alg: "ES256", want: p256Pub, wantAnyAlg: true},
		{name: "kid unknown", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigRSA}}, kid: "missing", alg: "RS256", wantErr: `kid="missing": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "kid of enc key", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{encRSA, sigRSA}}, kid: "enc", alg: "RS256", wantErr: `no signing key for kid="enc" alg="RS256": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "kid with wrong key type", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigRSA}}, kid: "rsa", alg: "ES256", wantErr: `no signing key for kid="rsa" alg="ES256": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "kid with other jwk alg", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{rs384Only}}, kid: "rs384", alg: "RS256", wantErr: `no signing key for kid="rs384" alg="RS256": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "kid with matching jwk alg", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{rs384Only}}, kid: "rs384", alg: "RS384", want: rsaPub},
		{name: "kid with wrong curve", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{p384Key}}, kid: "p384", alg: "ES256", wantErr: `no signing key for kid="p384" alg="ES256": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "kid with matching curve", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{p384Key}}, kid: "p384", alg: "ES384", want: p384Pub},
		{name: "unsupported alg", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sigRSA2}}, kid: "rsa2", alg: "PS256", wantErr: `no signing key for kid="rsa2" alg="PS256": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "duplicate kid split by alg", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sameKidRSA, sameKidEC}}, kid: "same", alg: "ES256", want: p256Pub},
		{name: "duplicate kid no alg", set: jwt.StaticKeySet{KeySet: []jose.JSONWebKey{sameKidRSA, sameKidEC}}, kid: "same", wantErr: `kid="same" alg="" matches 2 keys: ambiguous key`, wantErrIs: jwt.ErrAmbiguousKey},
		{name: "public keys rsa only", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsaPub}}, alg: "RS256", want: rsaPub, wantAnyAlg: true},
		{name: "public keys ec only", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{p256Pub}}, alg: "ES256", want: p256Pub, wantAnyAlg: true},
		{name: "public keys alg picks key type", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsaPub, p256Pub}}, alg: "ES256", want: p256Pub},
		{name: "public keys two rsa", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsaPub, rsa2Pub}}, alg: "RS256", wantErr: `kid="" alg="RS256" matches 2 keys: ambiguous key`, wantErrIs: jwt.ErrAmbiguousKey},
		{name: "public keys by thumbprint", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsaPub, rsa2Pub}}, kid: thumbprintKeyID(t, rsa2Pub), alg: "RS256", want: rsa2Pub, wantAnyAlg: true},
		{name: "public keys unknown kid", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsaPub}}, kid: "missing", alg: "RS256", wantErr: `kid="missing": key not found`, wantErrIs: jwt.ErrKeyNotFound},
		{name: "mixed empty kid across both lists", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsa2Pub}, KeySet: []jose.JSONWebKey{sigRSA}}, alg: "RS256", wantErr: `kid="" alg="RS256" matches 2 keys: ambiguous key`, wantErrIs: jwt.ErrAmbiguousKey},
		{name: "mixed empty kid one eligible", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{p256Pub}, KeySet: []jose.JSONWebKey{sigRSA}}, alg: "ES256", want: p256Pub},
		{name: "mixed kid prefers key set", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsa2Pub}, KeySet: []jose.JSONWebKey{sigRSA}}, kid: "rsa", alg: "RS256", want: rsaPub},
		{name: "mixed thumbprint falls back to public keys", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsa2Pub}, KeySet: []jose.JSONWebKey{sigRSA}}, kid: thumbprintKeyID(t, rsa2Pub), alg: "RS256", want: rsa2Pub},
		{name: "unsupported public key", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{rsaPub, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}}, alg: "RS256", wantErr: "unsupported public key type at index 1: ed25519.PublicKey"},
		{name: "nil public key", set: jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{nil}, KeySet: []jose.JSONWebKey{sigRSA}}, kid: "rsa", alg: "RS256", wantErr: "unsupported public key type at index 0: <nil>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			check := func(key any, err error) {
				if tc.wantErr != "" {
					require.EqualError(t, err, tc.wantErr)
					if tc.wantErrIs != nil {
						assert.ErrorIs(t, err, tc.wantErrIs)
					}
					assert.Nil(t, key)
					return
				}
				require.NoError(t, err)
				assert.Same(t, tc.want, key)
			}
			check(tc.set.GetKeyForAlgorithm(ctx, tc.kid, tc.alg))
			if tc.wantAnyAlg {
				check(tc.set.GetKey(ctx, tc.kid))
			}
		})
	}
}

// TestParserKeySelection verifies real tokens through NewParser and through
// TokenParser with a PublicKeys-only StaticKeySet (XPKI-071, XPKI-072).
func TestParserKeySelection(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()

	sign := func(t *testing.T, signer crypto.Signer, headers map[string]any) string {
		t.Helper()
		var opts []jwt.Option
		if headers != nil {
			opts = append(opts, jwt.WithHeaders(headers))
		}
		provider, err := jwt.NewProviderFromCryptoSigner(signer, opts...)
		require.NoError(t, err)
		token, err := provider.Sign(ctx, jwt.MapClaims{"sub": "subject"})
		require.NoError(t, err)
		return token
	}
	rsaToken := sign(t, k.rsa, nil)
	ecToken := sign(t, k.p256, nil)

	t.Run("jwks without kid", func(t *testing.T) {
		t.Parallel()
		// Both signing keys, in either order, plus an encryption key with the
		// same RSA material that must never be chosen by position.
		for _, keys := range [][]jose.JSONWebKey{
			{{Key: &k.rsa2.PublicKey, Use: "enc"}, {Key: &k.rsa.PublicKey, Use: "sig"}, {Key: &k.p256.PublicKey}},
			{{Key: &k.p256.PublicKey}, {Key: &k.rsa.PublicKey, Use: "sig"}, {Key: &k.rsa2.PublicKey, Use: "enc"}},
		} {
			parser, err := jwt.NewParser(&jwt.ParserConfig{JWKeySet: &jose.JSONWebKeySet{Keys: keys}})
			require.NoError(t, err)
			for _, token := range []string{rsaToken, ecToken} {
				claims, err := parser.ParseToken(ctx, token, nil)
				require.NoError(t, err)
				assert.Equal(t, "subject", claims.String("sub"))
			}
		}
	})

	t.Run("jwks without kid ambiguous", func(t *testing.T) {
		t.Parallel()
		parser, err := jwt.NewParser(&jwt.ParserConfig{JWKeySet: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &k.rsa2.PublicKey},
			{Key: &k.rsa.PublicKey},
		}}})
		require.NoError(t, err)
		claims, err := parser.ParseToken(ctx, rsaToken, nil)
		require.EqualError(t, err, `unable to verify token: kid="" alg="RS256" matches 2 keys: ambiguous key`)
		assert.ErrorIs(t, err, jwt.ErrAmbiguousKey)
		assert.Nil(t, claims)
	})

	t.Run("public keys only", func(t *testing.T) {
		t.Parallel()
		ks := &jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{&k.rsa.PublicKey, &k.p256.PublicKey}}
		thumbprintToken := sign(t, k.rsa, map[string]any{"kid": thumbprintKeyID(t, &k.rsa.PublicKey)})
		p := jwt.TokenParser{UseJSONNumber: true}
		for _, token := range []string{rsaToken, ecToken, thumbprintToken} {
			parsed, err := p.Parse(token, nil, func(tk *jwt.Token) (any, error) {
				kid, _ := tk.Header["kid"].(string)
				return ks.GetKeyForAlgorithm(ctx, kid, tk.SigningMethod)
			})
			require.NoError(t, err)
			assert.True(t, parsed.Valid)
		}

		// A key that did not sign the token is selected but fails verification.
		wrong := &jwt.StaticKeySet{PublicKeys: []crypto.PublicKey{&k.rsa2.PublicKey}}
		_, err := p.Parse(rsaToken, nil, func(tk *jwt.Token) (any, error) {
			return wrong.GetKeyForAlgorithm(ctx, "", tk.SigningMethod)
		})
		require.EqualError(t, err, "crypto/rsa: verification error")
	})
}

// jwksServer serves a mutable JWKS document and counts requests.
type jwksServer struct {
	*httptest.Server
	hits atomic.Int32

	mu     sync.Mutex
	body   []byte
	status int
	gate   chan struct{} // when non-nil, requests block until it is closed
}

func newJWKSServer(t *testing.T, keys ...jose.JSONWebKey) *jwksServer {
	t.Helper()
	s := &jwksServer{status: http.StatusOK}
	s.setKeys(t, keys...)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		body, status, gate := s.body, s.status, s.gate
		s.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) setKeys(t *testing.T, keys ...jose.JSONWebKey) {
	t.Helper()
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	require.NoError(t, err)
	s.setBody(http.StatusOK, body)
}

func (s *jwksServer) setBody(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

func (s *jwksServer) setGate(gate chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gate = gate
}

// TestRemoteKeySetRefresh covers XPKI-070 fetch bounds and throttling.
func TestRemoteKeySetRefresh(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	keyA := jose.JSONWebKey{Key: &k.rsa.PublicKey, KeyID: "a", Use: "sig"}
	keyB := jose.JSONWebKey{Key: &k.p256.PublicKey, KeyID: "b", Use: "sig"}

	t.Run("unknown kid flood is throttled", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL)
		for i := range 50 {
			key, err := ks.GetKey(ctx, "missing-"+strconv.Itoa(i))
			require.EqualError(t, err, `kid="missing-`+strconv.Itoa(i)+`": key not found`)
			assert.ErrorIs(t, err, jwt.ErrKeyNotFound)
			assert.Nil(t, key)
		}
		key, err := ks.GetKey(ctx, "a")
		require.NoError(t, err)
		assert.Equal(t, &k.rsa.PublicKey, key)
		assert.Equal(t, int32(1), srv.hits.Load())
	})

	t.Run("rotation without cooldown", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL, jwt.WithRefreshCooldown(0))
		_, err := ks.GetKeyForAlgorithm(ctx, "a", "RS256")
		require.NoError(t, err)
		srv.setKeys(t, keyA, keyB)
		key, err := ks.GetKeyForAlgorithm(ctx, "b", "ES256")
		require.NoError(t, err)
		assert.Equal(t, &k.p256.PublicKey, key)
		assert.Equal(t, int32(2), srv.hits.Load())
	})

	t.Run("empty kid refetches when cache is ambiguous", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA, jose.JSONWebKey{Key: &k.rsa2.PublicKey, KeyID: "a2"})
		ks := jwt.NewRemoteKeySet(ctx, srv.URL, jwt.WithRefreshCooldown(0))
		_, err := ks.GetKeyForAlgorithm(ctx, "", "RS256")
		require.EqualError(t, err, `kid="" alg="RS256" matches 2 keys: ambiguous key`)
		srv.setKeys(t, keyA)
		key, err := ks.GetKeyForAlgorithm(ctx, "", "RS256")
		require.NoError(t, err)
		assert.Equal(t, &k.rsa.PublicKey, key)
		assert.Equal(t, int32(2), srv.hits.Load())
	})

	t.Run("cached kid of wrong type", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL)
		key, err := ks.GetKeyForAlgorithm(ctx, "a", "ES256")
		require.EqualError(t, err, `no signing key for kid="a" alg="ES256": key not found`)
		assert.ErrorIs(t, err, jwt.ErrKeyNotFound)
		assert.Nil(t, key)
	})

	t.Run("stalled endpoint times out", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA)
		gate := make(chan struct{})
		srv.setGate(gate)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL, jwt.WithFetchTimeout(100*time.Millisecond), jwt.WithRefreshCooldown(0))
		start := time.Now()
		key, err := ks.GetKey(ctx, "a")
		require.ErrorContains(t, err, "unable to fetch JWKS key: failed to fetch keys: ")
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Nil(t, key)
		assert.Less(t, time.Since(start), 5*time.Second)

		// The failed fetch released its inflight slot, so a recovered
		// endpoint is used on the next lookup.
		srv.setGate(nil)
		close(gate)
		key, err = ks.GetKey(ctx, "a")
		require.NoError(t, err)
		assert.Equal(t, &k.rsa.PublicKey, key)
	})

	t.Run("canceled waiter does not cancel shared fetch", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA)
		gate := make(chan struct{})
		srv.setGate(gate)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL)

		type result struct {
			key any
			err error
		}
		const waiters = 8
		results := make(chan result, waiters)
		for range waiters {
			go func() {
				key, err := ks.GetKey(ctx, "a")
				results <- result{key, err}
			}()
		}
		require.Eventually(t, func() bool { return srv.hits.Load() == 1 }, 5*time.Second, time.Millisecond)

		cctx, cancel := context.WithCancel(ctx)
		cancel()
		key, err := ks.GetKey(cctx, "a")
		require.EqualError(t, err, "unable to fetch JWKS key: context canceled")
		assert.ErrorIs(t, err, context.Canceled)
		assert.Nil(t, key)

		close(gate)
		for range waiters {
			r := <-results
			require.NoError(t, r.err)
			assert.Equal(t, &k.rsa.PublicKey, r.key)
		}
		assert.Equal(t, int32(1), srv.hits.Load())
	})

	t.Run("response size limit", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA)
		srv.mu.Lock()
		size := int64(len(srv.body))
		srv.mu.Unlock()

		ks := jwt.NewRemoteKeySet(ctx, srv.URL, jwt.WithMaxResponseSize(size))
		key, err := ks.GetKey(ctx, "a")
		require.NoError(t, err)
		assert.Equal(t, &k.rsa.PublicKey, key)

		ks = jwt.NewRemoteKeySet(ctx, srv.URL, jwt.WithMaxResponseSize(size-1))
		key, err = ks.GetKey(ctx, "a")
		require.EqualError(t, err, "unable to fetch JWKS key: JWKS response exceeds "+strconv.FormatInt(size-1, 10)+" bytes")
		assert.Nil(t, key)
	})

	t.Run("max int64 size limit", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL, jwt.WithMaxResponseSize(math.MaxInt64))
		key, err := ks.GetKey(ctx, "a")
		require.NoError(t, err)
		assert.Equal(t, &k.rsa.PublicKey, key)
	})

	t.Run("default size limit", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t)
		srv.setBody(http.StatusOK, append([]byte(`{"keys":[]}`), bytes.Repeat([]byte(" "), jwt.DefaultJWKSMaxResponseSize)...))
		_, err := jwt.NewRemoteKeySet(ctx, srv.URL).GetKey(ctx, "a")
		require.EqualError(t, err, "unable to fetch JWKS key: JWKS response exceeds 1048576 bytes")
	})

	t.Run("http error is not echoed and is throttled", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t)
		srv.setBody(http.StatusInternalServerError, []byte("secret upstream detail"))
		ks := jwt.NewRemoteKeySet(ctx, srv.URL)
		_, err := ks.GetKey(ctx, "a")
		require.EqualError(t, err, "unable to fetch JWKS key: get keys failed: 500 Internal Server Error")

		_, err = ks.GetKey(ctx, "a")
		require.EqualError(t, err, "unable to fetch JWKS key: JWKS refresh throttled after failure: get keys failed: 500 Internal Server Error")
		assert.Equal(t, int32(1), srv.hits.Load())
	})

	t.Run("invalid document", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t)
		srv.setBody(http.StatusOK, []byte(`{"keys":`))
		_, err := jwt.NewRemoteKeySet(ctx, srv.URL).GetKey(ctx, "a")
		require.EqualError(t, err, "unable to fetch JWKS key: failed to decode keys: unexpected end of JSON input")
	})

	t.Run("injected client", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, keyA)
		var trips atomic.Int32
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			trips.Add(1)
			return http.DefaultTransport.RoundTrip(r)
		})}
		var nilCtx context.Context
		ks := jwt.NewRemoteKeySet(nilCtx, srv.URL, jwt.WithHTTPClient(client), jwt.WithHTTPClient(nil))
		key, err := ks.GetKey(ctx, "a")
		require.NoError(t, err)
		assert.Equal(t, &k.rsa.PublicKey, key)
		assert.Equal(t, int32(1), trips.Load())
	})

	t.Run("parser uses remote set", func(t *testing.T) {
		t.Parallel()
		srv := newJWKSServer(t, jose.JSONWebKey{Key: &k.p256.PublicKey, Use: "sig"})
		parser, err := jwt.NewParser(&jwt.ParserConfig{JWKSURI: srv.URL})
		require.NoError(t, err)
		provider, err := jwt.NewProviderFromCryptoSigner(k.p256)
		require.NoError(t, err)
		token, err := provider.Sign(ctx, jwt.MapClaims{"sub": "subject"})
		require.NoError(t, err)
		claims, err := parser.ParseToken(ctx, token, nil)
		require.NoError(t, err)
		assert.Equal(t, "subject", claims.String("sub"))
	})
}

// TestRemoteKeySetConcurrentRotation overlaps lookups with key rotation so
// the race detector sees cache reads, refresh writes and inflight hand-off.
func TestRemoteKeySetConcurrentRotation(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	keys := []jose.JSONWebKey{
		{Key: &k.rsa.PublicKey, KeyID: "k0"},
		{Key: &k.rsa2.PublicKey, KeyID: "k1"},
		{Key: &k.p256.PublicKey, KeyID: "k2"},
		{Key: &k.p384.PublicKey, KeyID: "k3"},
	}
	srv := newJWKSServer(t, keys[0])
	ks := jwt.NewRemoteKeySet(ctx, srv.URL, jwt.WithRefreshCooldown(0))

	const workers = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			<-start
			for i := range 50 {
				kid := keys[(w+i)%len(keys)].KeyID
				key, err := ks.GetKey(ctx, kid)
				if err != nil {
					assert.ErrorIs(t, err, jwt.ErrKeyNotFound)
					continue
				}
				assert.NotNil(t, key)
			}
		})
	}
	close(start)
	for i := 1; i < len(keys); i++ {
		srv.setKeys(t, keys[:i+1]...)
	}
	wg.Wait()

	for _, want := range keys {
		key, err := ks.GetKey(ctx, want.KeyID)
		require.NoError(t, err)
		assert.Equal(t, want.Key, key)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
