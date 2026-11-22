package dpop_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/jwt/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// base64URLAlphabet is the alphabet of base64.RawURLEncoding.
	base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// encodedNonceSize is the length of an HMACNonceSource nonce: 25 bytes
	// in unpadded base64url.
	encodedNonceSize = 34
)

func newSecret(t testing.TB) []byte {
	t.Helper()
	secret := make([]byte, dpop.MinNonceSecretSize)
	_, err := rand.Read(secret)
	require.NoError(t, err)
	return secret
}

func newNonceSource(t testing.TB, cfg dpop.HMACNonceConfig) *dpop.HMACNonceSource {
	t.Helper()
	s, err := dpop.NewHMACNonceSource(cfg)
	require.NoError(t, err)
	return s
}

func currentNonce(t testing.TB, s dpop.NonceSource) string {
	t.Helper()
	n, err := s.Nonce(context.Background())
	require.NoError(t, err)
	return n
}

// assertUseNonce checks that err is the nonce rejection msg and that both
// the standard library and cockroachdb/errors match it to ErrUseDPoPNonce.
func assertUseNonce(t *testing.T, err error, msg string) {
	t.Helper()
	require.Error(t, err)
	assert.EqualError(t, err, msg)
	assert.True(t, stderrors.Is(err, dpop.ErrUseDPoPNonce), "errors.Is (stdlib)")
	assert.True(t, errors.Is(err, dpop.ErrUseDPoPNonce), "errors.Is (cockroachdb)")
	assert.False(t, stderrors.Is(err, dpop.ErrReplay), "not a replay")
	assert.False(t, stderrors.Is(err, context.Canceled), "not a context error")
}

func TestNewHMACNonceSource(t *testing.T) {
	t.Parallel()
	secret := newSecret(t)

	for _, tc := range []struct {
		name string
		cfg  dpop.HMACNonceConfig
		err  string
	}{
		{
			name: "no secret",
			cfg:  dpop.HMACNonceConfig{},
			err:  "dpop: nonce secret is required",
		},
		{
			name: "short secret",
			cfg: dpop.HMACNonceConfig{
				Secrets: [][]byte{secret, secret[:dpop.MinNonceSecretSize-1]},
			},
			err: "dpop: nonce secret 1 is shorter than 32 bytes",
		},
		{
			name: "short rotation",
			cfg: dpop.HMACNonceConfig{
				Secrets:  [][]byte{secret},
				Rotation: time.Second - time.Nanosecond,
			},
			err: "dpop: nonce rotation 999.999999ms is shorter than 1s",
		},
		{
			name: "negative rotation",
			cfg: dpop.HMACNonceConfig{
				Secrets:  [][]byte{secret},
				Rotation: -time.Minute,
			},
			err: "dpop: nonce rotation -1m0s is shorter than 1s",
		},
		{
			name: "long rotation",
			cfg: dpop.HMACNonceConfig{
				Secrets:  [][]byte{secret},
				Rotation: time.Hour + time.Nanosecond,
			},
			err: "dpop: nonce rotation 1h0m0.000000001s is longer than 1h0m0s",
		},
		{
			name: "maximum rotation",
			cfg: dpop.HMACNonceConfig{
				Secrets:  [][]byte{secret},
				Rotation: dpop.MaxNonceRotation,
			},
		},
		{
			name: "default rotation",
			cfg: dpop.HMACNonceConfig{
				Secrets: [][]byte{secret},
			},
		},
		{
			name: "minimum rotation",
			cfg: dpop.HMACNonceConfig{
				Secrets:  [][]byte{secret},
				Rotation: dpop.MinNonceRotation,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := dpop.NewHMACNonceSource(tc.cfg)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, s)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, s)
		})
	}

	t.Run("secrets are copied", func(t *testing.T) {
		t.Parallel()
		mine := newSecret(t)
		s := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{mine}})
		n := currentNonce(t, s)
		for i := range mine {
			mine[i] = 0
		}
		// a zeroed secret would compute another MAC
		require.NoError(t, s.VerifyNonce(context.Background(), n))
	})
}

func TestHMACNonceSource_Format(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{newSecret(t)}})
	n := currentNonce(t, s)

	// unpadded base64url is within the RFC 9449 §8.1 nonce syntax (NQCHAR)
	require.Len(t, n, encodedNonceSize)
	for _, c := range n {
		assert.Contains(t, base64URLAlphabet, string(c))
	}
	require.NoError(t, s.VerifyNonce(ctx, n))

	raw, err := base64.RawURLEncoding.DecodeString(n)
	require.NoError(t, err)
	encode := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	modified := func(i int, b byte) string {
		c := bytes.Clone(raw)
		c[i] = b
		return encode(c)
	}

	// the last character carries 2 data bits and 4 unused bits; the
	// decoder ignores the unused bits, so this decodes to the same bytes
	last := strings.IndexByte(base64URLAlphabet, n[len(n)-1])
	nonCanonical := n[:len(n)-1] + string(base64URLAlphabet[last^1])
	decoded, err := base64.RawURLEncoding.DecodeString(nonCanonical)
	require.NoError(t, err)
	require.Equal(t, raw, decoded)

	for name, nonce := range map[string]string{
		"not base64url":      "not a nonce!",
		"padded":             n + "==",
		"short":              encode(raw[:len(raw)-1]),
		"long":               encode(append(bytes.Clone(raw), 0)),
		"unknown version":    modified(0, raw[0]+1),
		"other window":       modified(8, raw[8]^1),
		"modified MAC":       modified(len(raw)-1, raw[len(raw)-1]^1),
		"non-canonical":      nonCanonical,
		"other source's":     currentNonce(t, newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{newSecret(t)}})),
		"surrounding spaces": " " + n + " ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertUseNonce(t, s.VerifyNonce(ctx, nonce), "dpop: invalid nonce")
		})
	}

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		assertUseNonce(t, s.VerifyNonce(ctx, ""), "dpop: claim not found: nonce")
	})
}

func TestHMACNonceSource_LabelAndRotation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	oldSecret, newSecretValue := newSecret(t), newSecret(t)

	t.Run("label separates sources that share a secret", func(t *testing.T) {
		t.Parallel()
		as := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{oldSecret}, Label: "token endpoint"})
		rs := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{oldSecret}, Label: "api"})
		asNonce := currentNonce(t, as)
		require.NoError(t, as.VerifyNonce(ctx, asNonce))
		assertUseNonce(t, rs.VerifyNonce(ctx, asNonce), "dpop: invalid nonce")
		assertUseNonce(t, as.VerifyNonce(ctx, currentNonce(t, rs)), "dpop: invalid nonce")
	})

	t.Run("secret rotation", func(t *testing.T) {
		t.Parallel()
		before := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{oldSecret}})
		appended := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{oldSecret, newSecretValue}})
		moved := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{newSecretValue, oldSecret}})
		after := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{newSecretValue}})

		oldNonce, newNonce := currentNonce(t, before), currentNonce(t, moved)
		require.NotEqual(t, oldNonce, newNonce)
		// appending a secret changes nothing that is issued
		require.NoError(t, before.VerifyNonce(ctx, currentNonce(t, appended)))
		// an instance that already issues with the new secret is
		// understood by those that appended it, not by those that did not
		require.NoError(t, appended.VerifyNonce(ctx, newNonce))
		assertUseNonce(t, before.VerifyNonce(ctx, newNonce), "dpop: invalid nonce")
		// nonces of the old secret stay valid until it is removed
		require.NoError(t, moved.VerifyNonce(ctx, oldNonce))
		assertUseNonce(t, after.VerifyNonce(ctx, oldNonce), "dpop: invalid nonce")
		require.NoError(t, after.VerifyNonce(ctx, newNonce))
	})
}

// TestHMACNonceSource_Windows is not parallel: it replaces dpop.TimeNowFn.
func TestHMACNonceSource_Windows(t *testing.T) {
	const rotation = time.Minute
	// the start of a window
	start := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	now := start
	restore := dpop.TimeNowFn
	dpop.TimeNowFn = func() time.Time { return now }
	t.Cleanup(func() { dpop.TimeNowFn = restore })

	ctx := context.Background()
	s := newNonceSource(t, dpop.HMACNonceConfig{
		Secrets:  [][]byte{newSecret(t)},
		Rotation: rotation,
	})
	nonceAt := func(at time.Time) string {
		now = at
		return currentNonce(t, s)
	}
	verifyAt := func(at time.Time, nonce string) error {
		now = at
		return s.VerifyNonce(ctx, nonce)
	}

	n := nonceAt(start)
	assert.Equal(t, n, nonceAt(start.Add(rotation-time.Nanosecond)), "one nonce per window")
	next := nonceAt(start.Add(rotation))
	assert.NotEqual(t, n, next, "a new nonce in the next window")

	// accepted in its window and the next one
	require.NoError(t, verifyAt(start, n))
	require.NoError(t, verifyAt(start.Add(2*rotation-time.Nanosecond), n))
	assertUseNonce(t, verifyAt(start.Add(2*rotation), n), "dpop: nonce expired")
	assertUseNonce(t, verifyAt(start.Add(24*time.Hour), n), "dpop: nonce expired")

	// an instance whose clock runs ahead issues the next window's nonce
	require.NoError(t, verifyAt(start, next))
	later := nonceAt(start.Add(2 * rotation))
	assertUseNonce(t, verifyAt(start.Add(rotation-time.Nanosecond), later), "dpop: nonce is not valid yet")
	require.NoError(t, verifyAt(start.Add(rotation), later))

	// the verifier rejects a proof whose nonce has expired; the replay
	// cache does not see it
	cache := &recordingCache{}
	cfg := dpop.VerifyConfig{NonceSource: s, ReplayCache: cache}
	now = start.Add(2 * rotation)
	proof := signProof(t, jose.ES256, newECKey(t), map[string]any{
		"iat":           now.Unix(),
		dpop.ClaimNonce: n,
	})
	_, err := dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
	assertUseNonce(t, err, "dpop: nonce expired")
	assert.Empty(t, cache.keys)
}

func TestVerifyClaims_Nonce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key := newECKey(t)
	source := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{newSecret(t)}})

	t.Run("proof without nonce", func(t *testing.T) {
		t.Parallel()
		cache := &recordingCache{}
		cfg := dpop.VerifyConfig{NonceSource: source, ReplayCache: cache}
		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, nil), testMethod, testHTU)
		assertUseNonce(t, err, "dpop: claim not found: nonce")
		assert.Empty(t, cache.keys, "a rejected proof does not consume its jti")
	})

	t.Run("proof with the server nonce", func(t *testing.T) {
		t.Parallel()
		cache := &recordingCache{}
		cfg := dpop.VerifyConfig{NonceSource: source, ReplayCache: cache}
		n := currentNonce(t, source)
		res, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{dpop.ClaimNonce: n}), testMethod, testHTU)
		require.NoError(t, err)
		assert.Equal(t, n, res.Claims.Nonce)
		assert.Len(t, cache.keys, 1)
	})

	t.Run("proof with an unknown nonce", func(t *testing.T) {
		t.Parallel()
		cfg := dpop.VerifyConfig{NonceSource: source}
		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{dpop.ClaimNonce: "eyJ7S_zG.eyJH0-Z.HX4w-7v"}), testMethod, testHTU)
		assertUseNonce(t, err, "dpop: invalid nonce")
	})

	t.Run("ExpectedNonce mismatch is a nonce rejection", func(t *testing.T) {
		t.Parallel()
		cfg := dpop.VerifyConfig{ExpectedNonce: "n1"}
		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{dpop.ClaimNonce: "n2"}), testMethod, testHTU)
		assertUseNonce(t, err, "dpop: invalid nonce")
		_, err = dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{dpop.ClaimNonce: "n1"}), testMethod, testHTU)
		require.NoError(t, err)
	})

	t.Run("ExpectedNonce and NonceSource together", func(t *testing.T) {
		t.Parallel()
		cfg := dpop.VerifyConfig{ExpectedNonce: currentNonce(t, source), NonceSource: source}
		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, nil), testMethod, testHTU)
		assert.EqualError(t, err, "dpop: ExpectedNonce and NonceSource are mutually exclusive")
		assert.False(t, errors.Is(err, dpop.ErrUseDPoPNonce))
	})

	t.Run("source error is not a nonce rejection", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("nonce store unavailable")
		cfg := dpop.VerifyConfig{NonceSource: &probeNonceSource{err: boom}}
		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{dpop.ClaimNonce: "n"}), testMethod, testHTU)
		assert.ErrorIs(t, err, boom)
		assert.False(t, errors.Is(err, dpop.ErrUseDPoPNonce))
		assert.EqualError(t, err, "dpop: unable to verify nonce: nonce store unavailable")
	})

	t.Run("request context reaches the source", func(t *testing.T) {
		t.Parallel()
		type ctxKey struct{}
		probe := &probeNonceSource{}
		req := httptest.NewRequestWithContext(
			context.WithValue(ctx, ctxKey{}, "request"), testMethod, testHTU, nil)
		req.Header.Set(dpop.HTTPHeader, signProof(t, jose.ES256, key, map[string]any{dpop.ClaimNonce: "n"}))
		_, err := dpop.VerifyRequestClaims(dpop.VerifyConfig{NonceSource: probe}, req)
		require.NoError(t, err)
		require.NotNil(t, probe.ctx)
		assert.Equal(t, "request", probe.ctx.Value(ctxKey{}))
		assert.Equal(t, "n", probe.nonce)
	})

	t.Run("uninitialized source", func(t *testing.T) {
		t.Parallel()
		var nilSource *dpop.HMACNonceSource
		cfg := dpop.VerifyConfig{NonceSource: nilSource}
		_, err := dpop.VerifyClaims(cfg, signProof(t, jose.ES256, key, map[string]any{dpop.ClaimNonce: currentNonce(t, source)}), testMethod, testHTU)
		assert.EqualError(t, err, "dpop: unable to verify nonce: dpop: nonce source is not initialized")
		assert.False(t, errors.Is(err, dpop.ErrUseDPoPNonce))
	})

	t.Run("client retries with the nonce of the challenge", func(t *testing.T) {
		t.Parallel()
		signer, err := dpop.NewSigner(key)
		require.NoError(t, err)

		// the resource server answers a proof without nonce with a
		// use_dpop_nonce challenge and a fresh nonce; it listens on plain
		// HTTP, so its external URL is the test server's
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg := dpop.VerifyConfig{NonceSource: source, ExternalURL: srv.URL}
			_, err := dpop.VerifyRequestClaims(cfg, r)
			if errors.Is(err, dpop.ErrUseDPoPNonce) {
				n, nerr := source.Nonce(r.Context())
				if nerr != nil {
					http.Error(w, nerr.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set(dpop.NonceHTTPHeader, n)
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("WWW-Authenticate", dpop.UseDPoPNonceChallenge)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(srv.Close)

		call := func(extra any) *http.Response {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/v1/resource", nil)
			require.NoError(t, err)
			_, err = dpop.ForRequest(signer, req, extra)
			require.NoError(t, err)
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })
			return resp
		}

		resp := call(nil)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, `DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"`, resp.Header.Get("WWW-Authenticate"))
		n := resp.Header.Get(dpop.NonceHTTPHeader)
		require.NotEmpty(t, n)

		resp = call(map[string]any{dpop.ClaimNonce: n})
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestHMACNonceSource_Concurrent issues and checks nonces from many
// goroutines; run it with -race.
func TestHMACNonceSource_Concurrent(t *testing.T) {
	t.Parallel()
	const workers = 16
	ctx := context.Background()
	s := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{newSecret(t), newSecret(t)}})

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range 100 {
				n, err := s.Nonce(ctx)
				if err != nil {
					t.Errorf("Nonce: %v", err)
					return
				}
				if err := s.VerifyNonce(ctx, n); err != nil {
					t.Errorf("VerifyNonce: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestHMACNonceSource_KnownAnswer pins the nonce format, which the instances
// of a server share during a rolling upgrade, and the default rotation. It is
// not parallel: it replaces dpop.TimeNowFn.
func TestHMACNonceSource_KnownAnswer(t *testing.T) {
	const label = "api.example.com"
	// a multiple of DefaultNonceRotation: the start of a window
	start := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	now := start
	restore := dpop.TimeNowFn
	dpop.TimeNowFn = func() time.Time { return now }
	t.Cleanup(func() { dpop.TimeNowFn = restore })

	ctx := context.Background()
	secret := make([]byte, dpop.MinNonceSecretSize)
	for i := range secret {
		secret[i] = byte(i)
	}
	s := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{secret}, Label: label})

	// version 1 || window || HMAC-SHA256(secret, domain || 0 || label || 0 ||
	// rotation || window)[:16], both numbers 8 bytes big-endian
	window := binary.BigEndian.AppendUint64(nil, uint64(start.UnixNano()/int64(5*time.Minute)))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("xpki/dpop/nonce/v1\x00" + label + "\x00"))
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(5*time.Minute)))
	mac.Write(window)
	raw := append(append([]byte{1}, window...), mac.Sum(nil)[:16]...)

	n := currentNonce(t, s)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(raw), n)
	assert.Equal(t, "AQAAAAAAW1Dw_YuieE_aqNvRvYJrsbGZtw", n)

	// the default rotation is 5 minutes
	now = start.Add(5*time.Minute - time.Nanosecond)
	assert.Equal(t, n, currentNonce(t, s))
	now = start.Add(5 * time.Minute)
	assert.NotEqual(t, n, currentNonce(t, s))

	// the rotation is part of the MAC: a source with another rotation does
	// not take the window number of this one for its own
	now = start
	other := newNonceSource(t, dpop.HMACNonceConfig{Secrets: [][]byte{secret}, Label: label, Rotation: 10 * time.Minute})
	assertUseNonce(t, other.VerifyNonce(ctx, n), "dpop: invalid nonce")
}

func TestHMACNonceSource_Uninitialized(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var nilSource *dpop.HMACNonceSource
	for name, s := range map[string]dpop.NonceSource{
		"zero value": &dpop.HMACNonceSource{},
		"nil":        nilSource,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			n, err := s.Nonce(ctx)
			assert.EqualError(t, err, "dpop: nonce source is not initialized")
			assert.Empty(t, n)
			err = s.VerifyNonce(ctx, "n")
			assert.EqualError(t, err, "dpop: nonce source is not initialized")
			assert.False(t, errors.Is(err, dpop.ErrUseDPoPNonce))
		})
	}
}

// probeNonceSource is a NonceSource that records what VerifyNonce gets and
// returns err, as a source whose store is unavailable does.
type probeNonceSource struct {
	err   error
	ctx   context.Context
	nonce string
}

func (s *probeNonceSource) Nonce(context.Context) (string, error) {
	return "", s.err
}

func (s *probeNonceSource) VerifyNonce(ctx context.Context, nonce string) error {
	s.ctx = ctx
	s.nonce = nonce
	if s.err != nil {
		return errors.WithStack(s.err)
	}
	return nil
}
