package dpop_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testHTU    = "https://api.example.com/v1/Resource"
	testMethod = http.MethodGet
)

// signProof returns a compact DPoP proof signed with key and alg that embeds
// the public jwk. claims are merged over jti/htm/htu/iat defaults.
func signProof(t testing.TB, alg jose.SignatureAlgorithm, key crypto.Signer, claims map[string]any) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       key,
	}, &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]any{
			jose.HeaderType: "dpop+jwt",
		},
	})
	require.NoError(t, err)
	c := map[string]any{
		"jti": rand.Text(),
		"htm": testMethod,
		"htu": testHTU,
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		c[k] = v
	}
	token, err := jwt.Signed(s).Claims(c).Serialize()
	require.NoError(t, err)
	return token
}

func newECKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

type recordingCache struct {
	lock      sync.Mutex
	keys      []string
	expiresAt []time.Time
	err       error
}

func (c *recordingCache) Add(_ context.Context, key string, expiresAt time.Time) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.err != nil {
		return c.err
	}
	c.keys = append(c.keys, key)
	c.expiresAt = append(c.expiresAt, expiresAt)
	return nil
}

func TestVerifyClaims_Replay(t *testing.T) {
	t.Parallel()
	key := newECKey(t)

	t.Run("nil cache accepts a replayed proof", func(t *testing.T) {
		t.Parallel()
		proof := signProof(t, jose.ES256, key, nil)
		for range 2 {
			_, err := dpop.VerifyClaims(dpop.VerifyConfig{}, proof, testMethod, testHTU)
			require.NoError(t, err)
		}
	})

	t.Run("second use is rejected", func(t *testing.T) {
		t.Parallel()
		cfg := dpop.VerifyConfig{ReplayCache: dpop.NewMemoryReplayCache(0)}
		proof := signProof(t, jose.ES256, key, nil)
		_, err := dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
		require.NoError(t, err)
		_, err = dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
		require.Error(t, err)
		assert.ErrorIs(t, err, dpop.ErrReplay)
		assert.EqualError(t, err, "dpop: proof rejected: dpop: proof replayed")
	})

	t.Run("new proof with the same jti is rejected", func(t *testing.T) {
		t.Parallel()
		cfg := dpop.VerifyConfig{ReplayCache: dpop.NewMemoryReplayCache(0)}
		jti := map[string]any{"jti": "same-jti"}
		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, jti), testMethod, testHTU)
		require.NoError(t, err)
		_, err = dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, jti), testMethod, testHTU)
		assert.ErrorIs(t, err, dpop.ErrReplay)
	})

	t.Run("jti is scoped by the proof key", func(t *testing.T) {
		t.Parallel()
		cfg := dpop.VerifyConfig{ReplayCache: dpop.NewMemoryReplayCache(0)}
		jti := map[string]any{"jti": "same-jti"}
		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, jti), testMethod, testHTU)
		require.NoError(t, err)
		_, err = dpop.VerifyClaims(cfg, signProof(t, jose.ES256, newECKey(t), jti), testMethod, testHTU)
		require.NoError(t, err)
	})

	t.Run("request context and store error", func(t *testing.T) {
		t.Parallel()
		storeErr := errors.New("store unavailable")
		cfg := dpop.VerifyConfig{ReplayCache: &recordingCache{err: storeErr}}
		req := httptest.NewRequest(testMethod, testHTU, nil)
		req.Header.Set(dpop.HTTPHeader, signProof(t, jose.ES256, key, nil))
		_, err := dpop.VerifyRequestClaims(cfg, req)
		require.Error(t, err)
		assert.ErrorIs(t, err, storeErr)
		assert.EqualError(t, err, "dpop: proof rejected: store unavailable")
	})

	t.Run("rejected proofs do not consume the jti", func(t *testing.T) {
		t.Parallel()
		rc := &recordingCache{}
		cfg := dpop.VerifyConfig{ReplayCache: rc}
		proof := signProof(t, jose.ES256, key, nil)

		_, err := dpop.VerifyClaims(cfg, proof, testMethod, "https://api.example.com/other")
		require.Error(t, err)
		parts := strings.Split(proof, ".")
		parts[2] = strings.Repeat("A", len(parts[2]))
		_, err = dpop.VerifyClaims(cfg, strings.Join(parts, "."), testMethod, testHTU)
		assert.ErrorContains(t, err, "dpop: unable to verify token")
		_, err = dpop.VerifyClaims(dpop.VerifyConfig{ReplayCache: rc, ExpectedNonce: "n"}, proof, testMethod, testHTU)
		assert.EqualError(t, err, "dpop: invalid nonce")
		assert.Empty(t, rc.keys)

		_, err = dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
		require.NoError(t, err)
		assert.Len(t, rc.keys, 1)
	})

	t.Run("retention ends with the acceptance window", func(t *testing.T) {
		t.Parallel()
		rc := &recordingCache{}
		cfg := dpop.VerifyConfig{ReplayCache: rc}
		iat := time.Now().Add(-time.Minute).Truncate(time.Second)
		exp := iat.Add(2 * time.Minute)

		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{
			"iat": iat.Unix(),
		}), testMethod, testHTU)
		require.NoError(t, err)
		_, err = dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{
			"iat": iat.Unix(),
			"exp": exp.Unix(),
		}), testMethod, testHTU)
		require.NoError(t, err)

		require.Len(t, rc.expiresAt, 2)
		assert.True(t, iat.Add(dpop.DefaultExpiration).Equal(rc.expiresAt[0]), rc.expiresAt[0])
		assert.True(t, exp.Equal(rc.expiresAt[1]), rc.expiresAt[1])
		assert.NotEqual(t, rc.keys[0], rc.keys[1])
		assert.Len(t, rc.keys[0], 43, "fixed-length SHA-256 key")
	})

	t.Run("long jti is stored as a fixed-length key", func(t *testing.T) {
		t.Parallel()
		rc := &recordingCache{}
		_, err := dpop.VerifyClaims(dpop.VerifyConfig{ReplayCache: rc}, signProof(t, jose.ES256, key, map[string]any{
			"jti": strings.Repeat("x", 4096),
		}), testMethod, testHTU)
		require.NoError(t, err)
		require.Len(t, rc.keys, 1)
		assert.Len(t, rc.keys[0], 43)
	})
}

// TestVerifyClaims_ConcurrentReplay releases simultaneous verifications of
// the same proof and requires exactly one to be accepted.
func TestVerifyClaims_ConcurrentReplay(t *testing.T) {
	t.Parallel()
	const workers = 32
	cache := dpop.NewMemoryReplayCache(0)
	cfg := dpop.VerifyConfig{ReplayCache: cache}
	proof := signProof(t, jose.ES256, newECKey(t), nil)

	var accepted, replayed atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			<-start
			_, err := dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, dpop.ErrReplay):
				replayed.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), accepted.Load())
	assert.Equal(t, int32(workers-1), replayed.Load())
	assert.Equal(t, 1, cache.Len())
}

// TestMemoryReplayCache_Expiry is not parallel: it replaces dpop.TimeNowFn,
// which parallel tests only read after sequential tests have finished.
func TestMemoryReplayCache_Expiry(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	restore := dpop.TimeNowFn
	dpop.TimeNowFn = func() time.Time { return now }
	t.Cleanup(func() { dpop.TimeNowFn = restore })

	ctx := context.Background()
	c := dpop.NewMemoryReplayCache(2)

	require.NoError(t, c.Add(ctx, "a", now.Add(time.Minute)))
	require.NoError(t, c.Add(ctx, "b", now.Add(2*time.Minute)))
	assert.ErrorIs(t, c.Add(ctx, "a", now.Add(time.Hour)), dpop.ErrReplay)

	// full of unexpired entries: fail closed
	err := c.Add(ctx, "c", now.Add(time.Minute))
	assert.ErrorIs(t, err, dpop.ErrReplayCacheFull)
	assert.EqualError(t, err, "dpop: replay cache is full")
	assert.Equal(t, 2, c.Len())

	// "a" is kept at its expiry instant, which the verifier still accepts
	now = now.Add(time.Minute)
	assert.ErrorIs(t, c.Add(ctx, "a", now.Add(time.Minute)), dpop.ErrReplay)
	assert.ErrorIs(t, c.Add(ctx, "c", now.Add(time.Minute)), dpop.ErrReplayCacheFull)
	// and evicted just after it, to admit "c"
	now = now.Add(time.Nanosecond)
	require.NoError(t, c.Add(ctx, "c", now.Add(time.Minute)))
	assert.Equal(t, 2, c.Len())
	// the evicted "a" is no longer a replay, but "b" and "c" fill the cache
	assert.ErrorIs(t, c.Add(ctx, "a", now.Add(time.Minute)), dpop.ErrReplayCacheFull)

	now = now.Add(time.Hour)
	require.NoError(t, c.Add(ctx, "a", now.Add(time.Minute)))
	assert.Equal(t, 1, c.Len(), "expired b and c evicted")
	assert.ErrorIs(t, c.Add(ctx, "a", now.Add(time.Minute)), dpop.ErrReplay)

	// a proof older than the retention window is rejected by the verifier
	// before it reaches the cache, so eviction cannot reopen replay
	key := newECKey(t)
	cfg := dpop.VerifyConfig{ReplayCache: dpop.NewMemoryReplayCache(1)}
	iat := now.Unix()
	proof := signProof(t, jose.ES256, key, map[string]any{"iat": iat})
	_, err = dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
	require.NoError(t, err)
	// at the last accepted instant (iat has whole seconds) the replay is
	// still detected
	now = time.Unix(iat, 0).Add(dpop.DefaultExpiration)
	_, err = dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
	assert.ErrorIs(t, err, dpop.ErrReplay)
	now = now.Add(time.Second)
	_, err = dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
	assert.ErrorContains(t, err, "dpop: iat claim expired")
	// the expired entry was evicted, so a new proof fits in the cache
	_, err = dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{"iat": now.Unix()}), testMethod, testHTU)
	require.NoError(t, err)
}

func TestVerifyClaims_AccessTokenBinding(t *testing.T) {
	t.Parallel()
	const accessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
	// RFC 9449 §7.1 example ath for the access token above
	const ath = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
	assert.Equal(t, ath, dpop.AccessTokenHash(accessToken))

	key := newECKey(t)
	signer, err := dpop.NewSigner(key)
	require.NoError(t, err)
	req := httptest.NewRequest(testMethod, testHTU, nil)
	_, err = dpop.ForRequest(signer, req, map[string]any{
		dpop.ClaimAccessTokenHash: dpop.AccessTokenHash(accessToken),
	})
	require.NoError(t, err)
	withATH := req.Header.Get(dpop.HTTPHeader)
	withoutATH := signProof(t, jose.ES256, key, nil)

	res, err := dpop.VerifyClaims(dpop.VerifyConfig{
		AccessToken:        accessToken,
		ExpectedThumbprint: signer.JWKThumbprint(),
	}, withATH, testMethod, testHTU)
	require.NoError(t, err)
	assert.Equal(t, ath, res.AccessTokenHash)
	assert.Equal(t, signer.JWKThumbprint(), res.Thumbprint)

	tcases := []struct {
		name  string
		cfg   dpop.VerifyConfig
		proof string
		err   string
	}{
		{
			name:  "missing ath",
			cfg:   dpop.VerifyConfig{AccessToken: accessToken, ExpectedThumbprint: signer.JWKThumbprint()},
			proof: withoutATH,
			err:   "dpop: claim not found: ath",
		},
		{
			name:  "substituted access token",
			cfg:   dpop.VerifyConfig{AccessToken: accessToken + "x", ExpectedThumbprint: signer.JWKThumbprint()},
			proof: withATH,
			err:   "dpop: claim mismatch: ath",
		},
		{
			// a thief of the token computes ath with a key of their own
			name:  "ath without cnf.jkt",
			cfg:   dpop.VerifyConfig{AccessToken: accessToken},
			proof: signProof(t, jose.ES256, newECKey(t), map[string]any{dpop.ClaimAccessTokenHash: ath}),
			err:   "dpop: ExpectedThumbprint is required with AccessToken",
		},
		{
			name:  "token bound to another key",
			cfg:   dpop.VerifyConfig{AccessToken: accessToken, ExpectedThumbprint: "G4vNslPjQIRNz9T0Kj_di4mTvv_ymoT2lQmbKqS8cS8"},
			proof: withATH,
			err:   "dpop: proof key does not match cnf.jkt",
		},
		{
			name:  "token endpoint ignores ath",
			cfg:   dpop.VerifyConfig{},
			proof: withATH,
		},
		{
			name:  "token endpoint without ath",
			cfg:   dpop.VerifyConfig{ExpectedThumbprint: signer.JWKThumbprint()},
			proof: withoutATH,
		},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := dpop.VerifyClaims(tc.cfg, tc.proof, testMethod, testHTU)
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestVerifyRequestClaims_RequestURI(t *testing.T) {
	t.Parallel()
	key := newECKey(t)

	// serverRequest returns a request as net/http passes it to a handler:
	// no URL scheme or host, the Host header in req.Host.
	serverRequest := func(t *testing.T, target, host, htu string) *http.Request {
		req := httptest.NewRequest(testMethod, target, nil)
		req.Host = host
		req.TLS = nil
		require.Empty(t, req.URL.Scheme)
		require.Empty(t, req.URL.Host)
		req.Header.Set(dpop.HTTPHeader, signProof(t, jose.ES256, key, map[string]any{"htu": htu}))
		return req
	}

	tcases := []struct {
		name   string
		target string
		host   string
		ext    string
		htu    string
		err    string
	}{
		{name: "https default", target: "/v1/Resource", host: "api.example.com", htu: testHTU},
		{name: "query and fragment ignored", target: "/v1/Resource?x=1#f", host: "api.example.com", htu: testHTU + "?y=2#g"},
		{name: "host case and default port", target: "/v1/Resource", host: "API.Example.com:443", htu: "HTTPS://api.EXAMPLE.com/v1/Resource"},
		{name: "unreserved escapes", target: "/v1/%52esource", host: "api.example.com", htu: testHTU},
		{
			// a router that does not clean paths may dispatch this to /admin/
			name: "dot segments are not resolved", target: "/admin/../v1/Resource", host: "api.example.com", htu: testHTU,
			err: `dpop: claim mismatch: http_uri: "https://api.example.com/v1/Resource", actual: "https://api.example.com/admin/../v1/Resource"`,
		},
		{name: "reserved escape preserved", target: "/v1/a%2fb", host: "api.example.com", htu: "https://api.example.com/v1/a%2Fb"},
		{name: "empty path", target: "/", host: "api.example.com", htu: "https://api.example.com"},
		{
			name: "reserved escape differs from separator", target: "/v1/a/b", host: "api.example.com",
			htu: "https://api.example.com/v1/a%2Fb",
			err: `dpop: claim mismatch: http_uri: "https://api.example.com/v1/a%2Fb", actual: "https://api.example.com/v1/a/b"`,
		},
		{
			name: "path is case-sensitive", target: "/v1/resource", host: "api.example.com", htu: testHTU,
			err: `dpop: claim mismatch: http_uri: "https://api.example.com/v1/Resource", actual: "https://api.example.com/v1/resource"`,
		},
		{
			name: "plain HTTP needs ExternalURL", target: "/v1/Resource", host: "api.example.com", htu: "http://api.example.com/v1/Resource",
			err: `dpop: claim mismatch: http_uri: "http://api.example.com/v1/Resource", actual: "https://api.example.com/v1/Resource"`,
		},
		{name: "plain HTTP with ExternalURL", target: "/v1/Resource", host: "api.example.com", ext: "http://api.example.com", htu: "http://api.example.com/v1/Resource"},
		{name: "ExternalURL overrides Host", target: "/v1/Resource", host: "internal:8080", ext: "https://api.example.com/", htu: testHTU},
		{
			name: "ExternalURL ignores spoofed Host", target: "/v1/Resource", host: "evil.example.com", ext: "https://api.example.com",
			htu: "https://evil.example.com/v1/Resource",
			err: `dpop: claim mismatch: http_uri: "https://evil.example.com/v1/Resource", actual: "https://api.example.com/v1/Resource"`,
		},
		{name: "ExternalURL with path", target: "/", host: "h", ext: "https://api.example.com/v1", htu: testHTU, err: `dpop: invalid ExternalURL "https://api.example.com/v1": expected scheme://host[:port]`},
		{name: "ExternalURL with query", target: "/", host: "h", ext: "https://api.example.com?x", htu: testHTU, err: `dpop: invalid ExternalURL "https://api.example.com?x": expected scheme://host[:port]`},
		{name: "ExternalURL without scheme", target: "/", host: "h", ext: "api.example.com", htu: testHTU, err: `dpop: invalid ExternalURL "api.example.com": expected scheme://host[:port]`},
		{name: "ExternalURL unsupported scheme", target: "/", host: "h", ext: "ftp://api.example.com", htu: testHTU, err: `dpop: invalid ExternalURL "ftp://api.example.com": expected scheme://host[:port]`},
		{name: "ExternalURL unparsable", target: "/", host: "h", ext: "https://api example.com", htu: testHTU, err: `dpop: invalid ExternalURL "https://api example.com": parse "https://api example.com": invalid character " " in host name`},
		{name: "relative htu", target: "/v1/Resource", host: "api.example.com", htu: "/v1/Resource", err: `dpop: invalid http_uri claim: invalid URI "/v1/Resource"`},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := serverRequest(t, tc.target, tc.host, tc.htu)
			_, err := dpop.VerifyRequestClaims(dpop.VerifyConfig{ExternalURL: tc.ext}, req)
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}

	t.Run("TLS request", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(testMethod, "https://api.example.com/v1/Resource", nil)
		require.NotNil(t, req.TLS)
		req.Header.Set(dpop.HTTPHeader, signProof(t, jose.ES256, key, nil))
		_, err := dpop.VerifyRequestClaims(dpop.VerifyConfig{}, req)
		require.NoError(t, err)
	})

	t.Run("signer escaped path round trip", func(t *testing.T) {
		t.Parallel()
		signer, err := dpop.NewSigner(key)
		require.NoError(t, err)
		creq, err := http.NewRequest(testMethod, "https://api.example.com/v1/a%2Fb?q=1", nil)
		require.NoError(t, err)
		proof, err := dpop.ForRequest(signer, creq, nil)
		require.NoError(t, err)

		sreq := httptest.NewRequest(testMethod, "/v1/a%2Fb", nil)
		sreq.Host = "api.example.com"
		sreq.Header.Set(dpop.HTTPHeader, proof)
		res, err := dpop.VerifyRequestClaims(dpop.VerifyConfig{}, sreq)
		require.NoError(t, err)
		assert.Equal(t, "https://api.example.com/v1/a%2Fb", res.Claims.HTTPUri)
		assert.Len(t, res.Claims.ID, 22)
	})
}

// TestVerifyClaims_MemberNameCase requires claim and header names to match
// exactly, as go-jose (and GetTokenInfo) read them.
func TestVerifyClaims_MemberNameCase(t *testing.T) {
	t.Parallel()
	key := newECKey(t)

	proof := signProof(t, jose.ES256, key, map[string]any{
		"jti": nil,
		"JTI": "upper",
	})
	_, err := dpop.VerifyClaims(dpop.VerifyConfig{}, proof, testMethod, testHTU)
	assert.EqualError(t, err, "dpop: claim not found: jti")

	proof = signProof(t, jose.ES256, key, map[string]any{
		"htu": "https://api.example.com/v1/Other",
		"HTU": testHTU,
	})
	_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, proof, testMethod, testHTU)
	assert.EqualError(t, err, `dpop: claim mismatch: http_uri: "https://api.example.com/v1/Other", actual: "https://api.example.com/v1/Resource"`)

	jwk, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	require.NoError(t, err)
	_, rest, _ := strings.Cut(signProof(t, jose.ES256, key, nil), ".")
	upperTyp := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","TYP":"dpop+jwt","jwk":` + string(jwk) + `}`))
	_, err = dpop.VerifyClaims(dpop.VerifyConfig{}, upperTyp+"."+rest, testMethod, testHTU)
	assert.EqualError(t, err, "dpop: typ field not found in header")
}

func TestVerifyClaims_Algorithms(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256 := newECKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tcases := []struct {
		alg jose.SignatureAlgorithm
		key crypto.Signer
	}{
		{jose.RS256, rsaKey},
		{jose.RS384, rsaKey},
		{jose.RS512, rsaKey},
		{jose.PS256, rsaKey},
		{jose.PS384, rsaKey},
		{jose.PS512, rsaKey},
		{jose.ES256, p256},
		{jose.ES384, p384},
		{jose.ES512, p521},
		{jose.EdDSA, edKey},
	}
	for _, tc := range tcases {
		t.Run(string(tc.alg), func(t *testing.T) {
			t.Parallel()
			res, err := dpop.VerifyClaims(dpop.VerifyConfig{}, signProof(t, tc.alg, tc.key, nil), testMethod, testHTU)
			require.NoError(t, err)
			assert.NotEmpty(t, res.Thumbprint)
		})
	}

	t.Run("signature by another key", func(t *testing.T) {
		t.Parallel()
		proof := withHeader(t, signProof(t, jose.ES256, p256, nil), jose.ES256, newECKey(t).Public())
		_, err := dpop.VerifyClaims(dpop.VerifyConfig{}, proof, testMethod, testHTU)
		assert.ErrorContains(t, err, "dpop: unable to verify token")
	})
	t.Run("ES256 with P-384 jwk", func(t *testing.T) {
		t.Parallel()
		proof := withHeader(t, signProof(t, jose.ES384, p384, nil), jose.ES256, p384.Public())
		_, err := dpop.VerifyClaims(dpop.VerifyConfig{}, proof, testMethod, testHTU)
		assert.ErrorContains(t, err, "dpop: unable to verify token")
	})
	t.Run("RS256 header with EC jwk", func(t *testing.T) {
		t.Parallel()
		proof := withHeader(t, signProof(t, jose.RS256, rsaKey, nil), jose.RS256, p256.Public())
		_, err := dpop.VerifyClaims(dpop.VerifyConfig{}, proof, testMethod, testHTU)
		assert.ErrorContains(t, err, "dpop: unable to verify token")
	})
	t.Run("EdDSA header with RSA jwk", func(t *testing.T) {
		t.Parallel()
		proof := withHeader(t, signProof(t, jose.EdDSA, edKey, nil), jose.EdDSA, rsaKey.Public())
		_, err := dpop.VerifyClaims(dpop.VerifyConfig{}, proof, testMethod, testHTU)
		assert.ErrorContains(t, err, "dpop: unable to verify token")
	})
	t.Run("ES256K not allowed", func(t *testing.T) {
		t.Parallel()
		proof := withHeader(t, signProof(t, jose.ES256, p256, nil), "ES256K", p256.Public())
		_, err := dpop.VerifyClaims(dpop.VerifyConfig{}, proof, testMethod, testHTU)
		assert.EqualError(t, err, "dpop: alg not allowed: ES256K")
	})
}

// withHeader replaces the protected header of proof with a dpop+jwt header
// naming alg and embedding pub, keeping the original payload and signature.
// It builds combinations go-jose refuses to sign.
func withHeader(t *testing.T, proof string, alg jose.SignatureAlgorithm, pub crypto.PublicKey) string {
	t.Helper()
	jwk, err := (&jose.JSONWebKey{Key: pub}).MarshalJSON()
	require.NoError(t, err)
	protected := `{"alg":"` + string(alg) + `","typ":"dpop+jwt","jwk":` + string(jwk) + `}`
	_, rest, ok := strings.Cut(proof, ".")
	require.True(t, ok)
	return base64.RawURLEncoding.EncodeToString([]byte(protected)) + "." + rest
}
