package accesstoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/accesstoken"
	"github.com/pkg/errors"
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

	_, err = p.ParseToken(context.Background(), "12345", nil)
	assert.EqualError(t, err, "token not supported")
}

func TestATExpired(t *testing.T) {
	ctx := context.Background()

	dp, err := dataprotection.NewSymmetric([]byte(`accesstoken`))
	require.NoError(t, err)

	p := accesstoken.New(dp, nil)
	claims := jwt.MapClaims{
		"sub":   "123454",
		"email": "denis@at.com",
		"exp":   time.Now().Add(-time.Second).Unix(),
	}

	assert.Empty(t, p.Issuer())
	assert.Equal(t, time.Duration(0), p.TokenExpiry())

	at, err := p.Sign(ctx, claims)
	require.NoError(t, err)

	_, err = p.ParseToken(ctx, at, nil)
	assert.Error(t, err)
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
	ctx := context.Background()

	dp, err := dataprotection.NewSymmetric([]byte(`accesstoken`))
	require.NoError(t, err)

	v := &validator{
		revoked: map[string]bool{},
	}

	p := accesstoken.New(dp, nil)
	p.SetRevocation(v)

	claims := jwt.MapClaims{
		"jti":   "123454",
		"sub":   "123454",
		"email": "denis@at.com",
		"exp":   time.Now().Add(time.Second).Unix(),
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
