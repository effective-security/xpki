package jwt_test

import (
	"context"
	"testing"

	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/x/fileutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParserConfig(t *testing.T) {
	var cfg jwt.ParserConfig
	err := fileutil.Unmarshal("testdata/oidc_parser.json", &cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", cfg.Issuer)
	require.NotNil(t, cfg.JWKeySet)
	assert.Equal(t, 2, len(cfg.JWKeySet.Keys))

	var cfg2 jwt.ParserConfig
	err = fileutil.Unmarshal("testdata/oidc_parser.yaml", &cfg2)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", cfg2.Issuer)
	require.NotNil(t, cfg2.JWKeySet)
	assert.Equal(t, 2, len(cfg2.JWKeySet.Keys))

	var cfg3 jwt.ParserConfig
	err = fileutil.Unmarshal("testdata/oidc_parser_uri.yaml", &cfg3)
	require.NoError(t, err)
	assert.Equal(t, "https://accounts.google.com", cfg3.Issuer)
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/certs", cfg3.JWKSURI)
	assert.Nil(t, cfg3.JWKeySet)
}

func Test_ParseJwks(t *testing.T) {
	var cfg jwt.ParserConfig
	err := fileutil.Unmarshal("testdata/oidc_parser_cognito.json", &cfg)
	require.NoError(t, err)

	ctx := context.Background()
	parser, err := jwt.NewParser(&cfg)
	require.NoError(t, err)

	t.Run("cognito", func(t *testing.T) {
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
