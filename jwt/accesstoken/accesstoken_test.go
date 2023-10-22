package accesstoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/accesstoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAT(t *testing.T) {
	ctx := context.Background()

	dp, err := dataprotection.NewSymmetric([]byte(`accesstoken`))
	require.NoError(t, err)

	p := accesstoken.New(dp, nil)
	claims := jwt.MapClaims{
		"sub":   "123454",
		"email": "denis@at.com",
	}

	assert.Empty(t, p.Issuer())
	assert.Equal(t, time.Duration(0), p.TokenExpiry())

	at, err := p.Sign(ctx, claims)
	require.NoError(t, err)

	c2, err := p.ParseToken(ctx, at, nil)
	require.NoError(t, err)
	assert.Equal(t, claims, c2)

	c2, err = p.ParseToken(context.Background(), "12345", nil)
	require.NoError(t, err)
	assert.Nil(t, c2)
}

func TestATWithProvider(t *testing.T) {
	ctx := context.Background()
	jp, err := jwt.LoadProvider("../testdata/jwtprov.json", nil)
	require.NoError(t, err)

	dp, err := dataprotection.NewSymmetric([]byte(`accesstoken`))
	require.NoError(t, err)

	p := accesstoken.New(dp, jp)
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
		assert.Equal(t, claims, c2)
	})
	t.Run("JWP", func(t *testing.T) {
		jt, err := p.Sign(ctx, claims)
		require.NoError(t, err)

		c2, err := p.ParseToken(ctx, jt, nil)
		require.NoError(t, err)
		assert.Equal(t, claims, c2)
	})
}
