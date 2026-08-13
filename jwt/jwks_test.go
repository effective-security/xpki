package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/x/configloader"
	"github.com/effective-security/xpki/jwt"
	jose "github.com/go-jose/go-jose/v3"
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
