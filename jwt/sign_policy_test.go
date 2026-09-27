package jwt_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenClaims returns the decoded payload of a compact token.
func tokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := jwt.DecodeSegment(parts[1])
	require.NoError(t, err)
	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &claims))
	return claims
}

// signRSA returns a compact token with the given header, signed with key by
// RSASSA-PKCS1-v1_5 and the hash of alg, independent of the provider under
// test.
func signRSA(t *testing.T, alg string, key *rsa.PrivateKey, header map[string]any) string {
	t.Helper()
	hashes := map[string]crypto.Hash{
		"RS256": crypto.SHA256,
		"RS384": crypto.SHA384,
		"RS512": crypto.SHA512,
	}
	hash, ok := hashes[alg]
	require.True(t, ok, alg)
	h := map[string]any{"alg": alg}
	maps.Copy(h, header)
	rawHeader, err := json.Marshal(h)
	require.NoError(t, err)
	signing := jwt.EncodeSegment(rawHeader) + "." + jwt.EncodeSegment([]byte(`{"sub":"subject"}`))
	digest := hash.New()
	digest.Write([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest.Sum(nil))
	require.NoError(t, err)
	return signing + "." + jwt.EncodeSegment(sig)
}

// ringProvider returns the testdata HS256 key ring provider and its signing
// key (kid "1").
func ringProvider(t *testing.T) (jwt.Provider, []byte) {
	t.Helper()
	cfg, err := jwt.LoadProviderConfig("testdata/jwtprov.json")
	require.NoError(t, err)
	p, err := jwt.NewProvider(cfg, nil)
	require.NoError(t, err)
	var seed string
	for _, k := range cfg.Keys {
		if k.ID == cfg.KeyID {
			seed = k.Seed
		}
	}
	require.NotEmpty(t, seed)
	return p, certutil.SHA256([]byte(seed))
}

// TestSign_TokenIdentifier covers XPKI-073: the JOSE header carries no jti,
// and the payload jti is the caller's.
func TestSign_TokenIdentifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ring, _ := ringProvider(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := jwt.NewProviderFromCryptoSigner(ecKey)
	require.NoError(t, err)
	symmetric, err := jwt.NewProviderWithSymmetricKey(newSymmetricKey(t))
	require.NoError(t, err)

	for _, tc := range []struct {
		name       string
		provider   jwt.Provider
		headerKeys []string
	}{
		{"key ring", ring, []string{"alg", "kid", "typ"}},
		{"crypto signer", signer, []string{"alg", "jwk", "typ"}},
		{"symmetric key", symmetric, []string{"alg", "typ"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// a caller-provided jti is signed as given
			withID := jwt.MapClaims{"sub": "subject", "jti": "caller-1"}
			token, err := tc.provider.Sign(ctx, withID)
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.headerKeys, slices.Collect(maps.Keys(tokenHeader(t, token))))
			assert.Equal(t, "caller-1", tokenClaims(t, token)["jti"])
			claims, err := tc.provider.ParseToken(ctx, token, nil)
			require.NoError(t, err)
			assert.Equal(t, "caller-1", claims.String("jti"))

			// none is generated when absent, in the header or the payload
			token, err = tc.provider.Sign(ctx, jwt.MapClaims{"sub": "subject"})
			require.NoError(t, err)
			assert.NotContains(t, tokenHeader(t, token), "jti")
			assert.NotContains(t, tokenClaims(t, token), "jti")
			claims, err = tc.provider.ParseToken(ctx, token, nil)
			require.NoError(t, err)
			assert.NotContains(t, claims, "jti")
			assert.Equal(t, jwt.MapClaims{"sub": "subject"}, claims)

			// deterministic algorithms sign identical claims identically
			again, err := tc.provider.Sign(ctx, jwt.MapClaims{"sub": "subject"})
			require.NoError(t, err)
			if strings.HasPrefix(tokenHeader(t, token)["alg"].(string), "HS") {
				assert.Equal(t, token, again)
			}
		})
	}
}

// TestProvider_AlgorithmPinned covers XPKI-112: every provider verifies only
// tokens with its own signing algorithm, even when the same key would verify
// another hash.
func TestProvider_AlgorithmPinned(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("HS256 key ring", func(t *testing.T) {
		t.Parallel()
		ring, key := ringProvider(t)
		claims, err := ring.ParseToken(ctx, signHMAC(t, "HS256", key, map[string]any{"kid": "1"}), nil)
		require.NoError(t, err)
		assert.Equal(t, "subject", claims.String("sub"))
		for _, alg := range []string{"HS384", "HS512"} {
			_, err := ring.ParseToken(ctx, signHMAC(t, alg, key, map[string]any{"kid": "1"}), nil)
			require.EqualError(t, err, "unable to verify token: unsupported signing method: "+alg, alg)
		}
	})

	t.Run("RSA private key", func(t *testing.T) {
		t.Parallel()
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		p, err := jwt.NewProviderFromCryptoSigner(rsaKey)
		require.NoError(t, err)
		token, err := p.Sign(ctx, jwt.MapClaims{"sub": "subject"})
		require.NoError(t, err)
		assert.Equal(t, "RS256", tokenHeader(t, token)["alg"])
		claims, err := p.ParseToken(ctx, signRSA(t, "RS256", rsaKey, nil), nil)
		require.NoError(t, err)
		assert.Equal(t, "subject", claims.String("sub"))
		for _, alg := range []string{"RS384", "RS512"} {
			_, err := p.ParseToken(ctx, signRSA(t, alg, rsaKey, nil), nil)
			require.EqualError(t, err, "unable to verify token: unsupported signing method: "+alg, alg)
		}
		// nor an HS token keyed with anything
		_, err = p.ParseToken(ctx, signHMAC(t, "HS256", []byte("key"), nil), nil)
		require.EqualError(t, err, "unable to verify token: unsupported signing method: HS256")
	})

	t.Run("EC private key", func(t *testing.T) {
		t.Parallel()
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		p, err := jwt.NewProviderFromCryptoSigner(ecKey)
		require.NoError(t, err)
		other, err := jwt.NewProviderFromCryptoSigner(ecKey, jwt.WithHeaders(map[string]any{"typ": "at+jwt"}))
		require.NoError(t, err)
		token, err := other.Sign(ctx, jwt.MapClaims{"sub": "subject"})
		require.NoError(t, err)
		_, err = p.ParseToken(ctx, token, nil)
		require.NoError(t, err)
		_, err = p.ParseToken(ctx, signRSA(t, "RS256", mustRSAKey(t), nil), nil)
		require.EqualError(t, err, "unable to verify token: unsupported signing method: RS256")
	})
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// TestSign_TimeClaims covers XPKI-109: exp, iat and nbf are signed as
// NumericDate whatever their Go type, so ParseToken checks them.
func TestSign_TimeClaims(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p, _ := ringProvider(t)
	now := time.Now().Truncate(time.Second)
	tomorrow := now.Add(24 * time.Hour)
	yesterday := now.Add(-24 * time.Hour)

	t.Run("normalized", func(t *testing.T) {
		t.Parallel()
		for name, v := range map[string]any{
			"time.Time":      tomorrow,
			"*time.Time":     &tomorrow,
			"RFC 3339":       tomorrow.UTC().Format(time.RFC3339),
			"RFC 3339 nano":  tomorrow.Add(500 * time.Millisecond).Format(time.RFC3339Nano),
			"local RFC 3339": tomorrow.In(time.FixedZone("x", -7*3600)).Format(time.RFC3339),
			"int64":          tomorrow.Unix(),
			"int":            int(tomorrow.Unix()),
			"float64":        float64(tomorrow.Unix()),
			"json.Number":    json.Number(jsonUnix(tomorrow)),
			"string unix":    jsonUnix(tomorrow),
			"NumericDate":    *jwt.NewNumericDate(tomorrow),
			"*NumericDate":   jwt.NewNumericDate(tomorrow),
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				claims := jwt.MapClaims{"sub": "subject", "exp": v}
				token, err := p.Sign(ctx, claims)
				require.NoError(t, err)
				// the caller map is not modified
				assert.Equal(t, jwt.MapClaims{"sub": "subject", "exp": v}, claims)
				payload := tokenClaims(t, token)
				assert.Equal(t, float64(tomorrow.Unix()), payload["exp"], "%T", v)
				parsed, err := p.ParseToken(ctx, token, nil)
				require.NoError(t, err)
				assert.Equal(t, json.Number(jsonUnix(tomorrow)), parsed["exp"])
				assert.Equal(t, tomorrow.Unix(), parsed.TimeVal("exp").Unix())
			})
		}
	})

	t.Run("checked", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name   string
			claims jwt.MapClaims
			expErr string
		}{
			{"nbf tomorrow", jwt.MapClaims{"nbf": tomorrow}, "token not valid yet"},
			{"exp yesterday", jwt.MapClaims{"exp": yesterday}, "token expired at"},
			{"iat tomorrow", jwt.MapClaims{"iat": &tomorrow}, "after now"},
			{"nbf tomorrow string", jwt.MapClaims{"nbf": tomorrow.UTC().Format(time.RFC3339)}, "token not valid yet"},
			{"all valid", jwt.MapClaims{"iat": now, "nbf": now.Add(-time.Minute), "exp": tomorrow}, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				token, err := p.Sign(ctx, tc.claims)
				require.NoError(t, err)
				_, err = p.ParseToken(ctx, token, nil)
				if tc.expErr == "" {
					require.NoError(t, err)
					return
				}
				require.ErrorContains(t, err, tc.expErr)
			})
		}
	})

	t.Run("rejected", func(t *testing.T) {
		t.Parallel()
		for name, v := range map[string]any{
			"nil":        nil,
			"text":       "tomorrow",
			"bool":       true,
			"zero time":  time.Time{},
			"struct":     struct{ X int }{1},
			"huge float": float64(1e300),
			// int64(uint64) would wrap to a 1969 time that Valid accepts
			"uint64 wrap": uint64(math.MaxInt64) + 1,
			"uint64 max":  uint64(math.MaxUint64),
			"json uint":   json.Number("18446744073709551615"),
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				for _, k := range []string{"exp", "iat", "nbf"} {
					_, err := p.Sign(ctx, jwt.MapClaims{"sub": "subject", k: v})
					require.ErrorContains(t, err, "invalid "+k+" claim", k)
				}
			})
		}
	})

	// without time claims the caller map is signed as is, and other claims
	// of type time.Time are untouched
	custom := jwt.MapClaims{"sub": "subject", "auth_time": tomorrow}
	token, err := p.Sign(ctx, custom)
	require.NoError(t, err)
	assert.Equal(t, tomorrow.Format(time.RFC3339Nano), tokenClaims(t, token)["auth_time"])
}

// TestNormalizeTimeClaims covers the method Sign uses: every time claim is
// replaced in place, and an error leaves the map unchanged.
func TestNormalizeTimeClaims(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	claims := jwt.MapClaims{
		"sub":       "subject",
		"exp":       now.Add(time.Hour),
		"iat":       now.UTC().Format(time.RFC3339),
		"nbf":       jwt.NewNumericDate(now.Add(-time.Minute)),
		"auth_time": now,
	}
	require.NoError(t, claims.NormalizeTimeClaims())
	assert.Equal(t, jwt.MapClaims{
		"sub":       "subject",
		"exp":       now.Add(time.Hour).Unix(),
		"iat":       now.Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"auth_time": now,
	}, claims)
	require.NoError(t, claims.NormalizeTimeClaims(), "idempotent")

	// an unparsable claim after a valid one changes nothing
	bad := jwt.MapClaims{"exp": now, "iat": "tomorrow", "nbf": now}
	require.EqualError(t, bad.NormalizeTimeClaims(), "invalid iat claim: tomorrow")
	assert.Equal(t, jwt.MapClaims{"exp": now, "iat": "tomorrow", "nbf": now}, bad)

	var none jwt.MapClaims
	require.NoError(t, none.NormalizeTimeClaims())
	assert.Nil(t, none)
}

func jsonUnix(t time.Time) string {
	return strconv.FormatInt(t.Unix(), 10)
}
