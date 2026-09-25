package accesstoken_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/accesstoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSecret  = `accesstoken`
	jwtProvFile = "../testdata/jwtprov.json"
)

// setClock pins jwt.TimeNowFn; tests using it must not call t.Parallel.
func setClock(t *testing.T, now time.Time) {
	t.Helper()
	orig := jwt.TimeNowFn
	jwt.TimeNowFn = func() time.Time { return now }
	t.Cleanup(func() { jwt.TimeNowFn = orig })
}

func newDP(t *testing.T) dataprotection.Provider {
	t.Helper()
	dp, err := dataprotection.NewSymmetric([]byte(testSecret))
	require.NoError(t, err)
	return dp
}

// legacyToken builds a pat. token the way Sign did before XPKI-078: the
// claims are encrypted as given, without an exp.
func legacyToken(t *testing.T, dp dataprotection.Provider, claims jwt.MapClaims) string {
	t.Helper()
	js, err := json.Marshal(claims)
	require.NoError(t, err)
	protected, err := dp.Protect(context.Background(), js)
	require.NoError(t, err)
	return accesstoken.TokenPrefix + base64.RawURLEncoding.EncodeToString(protected)
}

func unix(t time.Time) json.Number {
	return json.Number(strconv.FormatInt(t.Unix(), 10))
}

func TestAT(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	setClock(t, now)

	p := accesstoken.New(newDP(t), nil, accesstoken.WithTokenExpiry(time.Hour))
	claims := jwt.MapClaims{
		"sub":   "123454",
		"email": "denis@at.com",
	}

	assert.Empty(t, p.Issuer())
	assert.Equal(t, time.Hour, p.TokenExpiry())

	at, err := p.Sign(ctx, claims)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(at, accesstoken.TokenPrefix))
	// the caller's map is not modified
	assert.Equal(t, jwt.MapClaims{
		"sub":   "123454",
		"email": "denis@at.com",
	}, claims)

	c2, err := p.ParseToken(ctx, at, nil)
	require.NoError(t, err)
	assert.Equal(t, jwt.MapClaims{
		"sub":   "123454",
		"email": "denis@at.com",
		"iat":   unix(now),
		"nbf":   unix(now.Add(jwt.DefaultNotBefore)),
		"exp":   unix(now.Add(time.Hour)),
	}, c2)

	_, err = p.ParseToken(ctx, "12345", nil)
	assert.EqualError(t, err, "token not supported")
}

func TestATExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	p := accesstoken.New(newDP(t), nil)
	claims := jwt.MapClaims{
		"sub":   "123454",
		"email": "denis@at.com",
		"exp":   time.Now().Add(-time.Second).Unix(),
	}

	assert.Empty(t, p.Issuer())
	assert.Equal(t, time.Duration(0), p.TokenExpiry())

	// a caller-supplied exp does not need a configured expiry
	at, err := p.Sign(ctx, claims)
	require.NoError(t, err)

	_, err = p.ParseToken(ctx, at, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at:")
}

// TestSign_Expiry covers the XPKI-078 lifetime policy: WithTokenExpiry, then
// the inner provider's TokenExpiry, else an error.
func TestSign_Expiry(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	setClock(t, now)

	jp, err := jwt.LoadProvider(jwtProvFile, nil)
	require.NoError(t, err)
	dp := newDP(t)

	tcs := []struct {
		name   string
		inner  jwt.Provider
		opts   []accesstoken.Option
		expiry time.Duration
		err    string
	}{
		{
			name:   "option",
			opts:   []accesstoken.Option{accesstoken.WithTokenExpiry(time.Minute)},
			expiry: time.Minute,
		},
		{
			name:   "inner",
			inner:  jp,
			expiry: 8 * time.Hour,
		},
		{
			name:   "option over inner",
			inner:  jp,
			opts:   []accesstoken.Option{accesstoken.WithTokenExpiry(time.Minute)},
			expiry: time.Minute,
		},
		{
			name:   "zero option keeps inner",
			inner:  jp,
			opts:   []accesstoken.Option{accesstoken.WithTokenExpiry(0)},
			expiry: 8 * time.Hour,
		},
		{
			name: "not configured",
			err:  "token expiry not configured",
		},
		{
			// reported as 0, and does not fall back to the inner provider
			name:  "negative",
			inner: jp,
			opts:  []accesstoken.Option{accesstoken.WithTokenExpiry(-time.Minute)},
			err:   "token expiry not configured",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			p := accesstoken.New(dp, tc.inner, tc.opts...)
			assert.Equal(t, tc.expiry, p.TokenExpiry())

			at, err := p.Sign(ctx, jwt.MapClaims{"sub": "s"})
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Empty(t, at)
				return
			}
			require.NoError(t, err)
			c2, err := p.ParseToken(ctx, at, nil)
			require.NoError(t, err)
			assert.Equal(t, unix(now.Add(tc.expiry)), c2["exp"])
		})
	}
}

func TestSign_CallerClaims(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	setClock(t, now)

	// a long caller exp is kept even though it exceeds the configured expiry
	exp := now.Add(365 * 24 * time.Hour)
	p := accesstoken.New(newDP(t), nil, accesstoken.WithTokenExpiry(time.Hour))

	for name, v := range map[string]any{
		"int64":       exp.Unix(),
		"int":         int(exp.Unix()),
		"float64":     float64(exp.Unix()),
		"json.Number": unix(exp),
		"time.Time":   exp,
		"*time.Time":  &exp,
		"string":      strconv.FormatInt(exp.Unix(), 10),
	} {
		t.Run(name, func(t *testing.T) {
			claims := jwt.MapClaims{"sub": "s", "exp": v}
			at, err := p.Sign(ctx, claims)
			require.NoError(t, err)
			assert.Equal(t, v, claims["exp"], "caller map modified")

			c2, err := p.ParseToken(ctx, at, nil)
			require.NoError(t, err)
			// exp is normalized to NumericDate; iat and nbf are not added
			assert.Equal(t, jwt.MapClaims{"sub": "s", "exp": unix(exp)}, c2)
		})
	}

	t.Run("caller iat and nbf kept", func(t *testing.T) {
		iat := now.Add(-time.Minute)
		// time.Time with a fraction would marshal to a string Time cannot parse
		at, err := p.Sign(ctx, jwt.MapClaims{
			"iat": iat.Add(time.Millisecond),
			"nbf": iat.Unix(),
		})
		require.NoError(t, err)
		c2, err := p.ParseToken(ctx, at, nil)
		require.NoError(t, err)
		assert.Equal(t, jwt.MapClaims{
			"iat": unix(iat),
			"nbf": unix(iat),
			"exp": unix(now.Add(time.Hour)),
		}, c2)
	})

	t.Run("future nbf as time.Time is enforced", func(t *testing.T) {
		nbf := now.Add(24*time.Hour + time.Millisecond)
		at, err := p.Sign(ctx, jwt.MapClaims{"sub": "s", "nbf": nbf})
		require.NoError(t, err)
		_, err = p.ParseToken(ctx, at, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not valid yet")
	})

	for _, k := range []string{"exp", "iat", "nbf"} {
		for name, v := range map[string]any{
			"nil":     nil,
			"text":    "tomorrow",
			"bool":    true,
			"NaN str": "NaN",
		} {
			t.Run("invalid "+k+" "+name, func(t *testing.T) {
				at, err := p.Sign(ctx, jwt.MapClaims{"sub": "s", k: v})
				assert.EqualError(t, err, "invalid "+k+" claim")
				assert.Empty(t, at)
			})
		}
	}
}

func TestParse_ExpiryBoundary(t *testing.T) {
	ctx := context.Background()
	issued := time.Unix(1_800_000_000, 0)
	setClock(t, issued)

	p := accesstoken.New(newDP(t), nil, accesstoken.WithTokenExpiry(time.Hour))
	at, err := p.Sign(ctx, jwt.MapClaims{"sub": "s"})
	require.NoError(t, err)

	setClock(t, issued.Add(time.Hour))
	_, err = p.ParseToken(ctx, at, nil)
	require.NoError(t, err, "valid at the exp instant")

	setClock(t, issued.Add(time.Hour+time.Second))
	_, err = p.ParseToken(ctx, at, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at:")
}

// TestParse_LegacyNoExpiry covers pat. tokens issued before XPKI-078.
func TestParse_LegacyNoExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dp := newDP(t)

	claims := jwt.MapClaims{
		"jti": "legacy-1",
		"sub": "123454",
	}
	legacy := legacyToken(t, dp, claims)

	_, err := accesstoken.New(dp, nil).ParseToken(ctx, legacy, nil)
	assert.EqualError(t, err, "exp claim not found")

	v := &validator{revoked: map[string]bool{}}
	p := accesstoken.New(dp, nil, accesstoken.WithAllowNoExpiry())
	p.SetRevocation(v)

	c2, err := p.ParseToken(ctx, legacy, nil)
	require.NoError(t, err)
	assert.Equal(t, jwt.MapClaims{
		"jti": "legacy-1",
		"sub": "123454",
	}, c2)
	_, ok := c2["exp"]
	assert.False(t, ok)

	// revocation still applies to legacy tokens
	require.NoError(t, v.Revoke(ctx, legacy, claims))
	_, err = p.ParseToken(ctx, legacy, nil)
	assert.EqualError(t, err, "invalid token: revoked")

	// a present but unusable exp is never treated as absent, including a
	// time.Time exp that the old Sign marshaled to an RFC 3339 string
	for _, exp := range []any{nil, "tomorrow", true, time.Now().Add(time.Hour)} {
		bad := legacyToken(t, dp, jwt.MapClaims{"sub": "s", "exp": exp})
		_, err = p.ParseToken(ctx, bad, nil)
		assert.EqualError(t, err, "invalid exp claim", "exp=%v", exp)
	}
}

type validator struct {
	revoked map[string]bool
}

func (v *validator) Validate(ctx context.Context, _ string, claims jwt.MapClaims) error {
	if v.revoked[claims.String("jti")] {
		return errors.New("revoked")
	}
	return nil
}

func (v *validator) Revoke(ctx context.Context, _ string, claims jwt.MapClaims) error {
	v.revoked[claims.String("jti")] = true
	return nil
}

func TestATRevoked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	v := &validator{
		revoked: map[string]bool{},
	}

	p := accesstoken.New(newDP(t), nil)
	p.SetRevocation(v)

	claims := jwt.MapClaims{
		"jti":   "123454",
		"sub":   "123454",
		"email": "denis@at.com",
		"exp":   time.Now().Add(time.Minute).Unix(),
	}

	assert.Empty(t, p.Issuer())
	assert.Equal(t, time.Duration(0), p.TokenExpiry())

	at, err := p.Sign(ctx, claims)
	require.NoError(t, err)
	_, err = p.ParseToken(ctx, at, nil)
	assert.NoError(t, err)

	require.NoError(t, v.Revoke(ctx, at, claims))
	_, err = p.ParseToken(ctx, at, nil)
	assert.EqualError(t, err, "invalid token: revoked")
}

func TestATWithProvider(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	setClock(t, now)

	jp, err := jwt.LoadProvider(jwtProvFile, nil)
	require.NoError(t, err)

	p := accesstoken.New(newDP(t), jp)
	claims := jwt.MapClaims{
		"sub":   "123454",
		"email": "denis@at.com",
	}

	assert.Equal(t, "trusty.com", p.Issuer())
	assert.Equal(t, time.Duration(8)*time.Hour, p.TokenExpiry())

	t.Run("access token", func(t *testing.T) {
		at, err := p.Sign(ctx, claims)
		require.NoError(t, err)

		c2, err := p.ParseToken(ctx, at, nil)
		require.NoError(t, err)
		assert.Equal(t, jwt.MapClaims{
			"sub":   "123454",
			"email": "denis@at.com",
			"iat":   unix(now),
			"nbf":   unix(now.Add(jwt.DefaultNotBefore)),
			"exp":   unix(now.Add(8 * time.Hour)),
		}, c2)
	})
	t.Run("JWT", func(t *testing.T) {
		// plain JWTs are delegated to the inner provider unchanged
		jt, err := jp.Sign(ctx, claims)
		require.NoError(t, err)

		c2, err := p.ParseToken(ctx, jt, nil)
		require.NoError(t, err)
		assert.Equal(t, claims, c2)
	})
}

// TestATRevokedPlainJWT verifies that SetRevocation is forwarded to the
// wrapped jwt.Provider so revoked plain JWTs are rejected (XPKI-077).
func TestATRevokedPlainJWT(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	jp, err := jwt.LoadProvider(jwtProvFile, nil)
	require.NoError(t, err)

	v := &validator{
		revoked: map[string]bool{},
	}

	p := accesstoken.New(newDP(t), jp)
	p.SetRevocation(v)
	assert.Same(t, v, p.GetRevocation())
	assert.Same(t, v, jp.GetRevocation())

	claims := jwt.MapClaims{
		"jti":   "plain-1",
		"sub":   "123454",
		"email": "denis@at.com",
		"exp":   time.Now().Add(time.Minute).Unix(),
	}

	// sign a plain JWT with the wrapped provider, not a pat. token
	jt, err := jp.Sign(ctx, claims)
	require.NoError(t, err)
	require.False(t, strings.HasPrefix(jt, accesstoken.TokenPrefix))

	_, err = p.ParseToken(ctx, jt, nil)
	require.NoError(t, err)

	require.NoError(t, v.Revoke(ctx, jt, claims))
	_, err = p.ParseToken(ctx, jt, nil)
	assert.EqualError(t, err, "invalid token: revoked")

	// pat. tokens are checked by the same revocation list
	at, err := p.Sign(ctx, claims)
	require.NoError(t, err)
	_, err = p.ParseToken(ctx, at, nil)
	assert.EqualError(t, err, "invalid token: revoked")
}

// asymDP is a dataprotection.Provider stub that reports a public key, to
// check that PublicKey returns the data protection key unchanged.
type asymDP struct {
	dataprotection.Provider
	pub crypto.PublicKey
}

func (a asymDP) PublicKey() crypto.PublicKey { return a.pub }

// TestPublicKey covers XPKI-079: a nil data protection provider must not
// panic.
func TestPublicKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	jp, err := jwt.LoadProvider(jwtProvFile, nil)
	require.NoError(t, err)
	dp := newDP(t)

	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	assert.Nil(t, accesstoken.New(dp, nil).PublicKey(), "symmetric")
	assert.Nil(t, accesstoken.New(dp, jp).PublicKey(), "symmetric with inner")
	assert.Equal(t, pub, accesstoken.New(asymDP{Provider: dp, pub: pub}, nil).PublicKey())

	for name, inner := range map[string]jwt.Provider{"no inner": nil, "inner": jp} {
		t.Run("nil dp "+name, func(t *testing.T) {
			p := accesstoken.New(nil, inner, accesstoken.WithTokenExpiry(time.Hour))
			assert.Nil(t, p.PublicKey())

			at, err := p.Sign(ctx, jwt.MapClaims{"sub": "s"})
			assert.EqualError(t, err, "data protection not configured")
			assert.Empty(t, at)

			_, err = p.ParseToken(ctx, legacyToken(t, dp, jwt.MapClaims{"sub": "s"}), nil)
			assert.EqualError(t, err, "data protection not configured")
		})
	}

	// plain JWTs still go to the inner provider when dp is nil
	claims := jwt.MapClaims{"sub": "s"}
	jt, err := jp.Sign(ctx, claims)
	require.NoError(t, err)
	c2, err := accesstoken.New(nil, jp).ParseToken(ctx, jt, nil)
	require.NoError(t, err)
	assert.Equal(t, claims, c2)
}
