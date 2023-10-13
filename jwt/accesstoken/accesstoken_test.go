package accesstoken_test

import (
	"context"
	"testing"

	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/accesstoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAT(t *testing.T) {
	dp, err := dataprotection.NewSymmetric([]byte(`accesstoken`))
	require.NoError(t, err)

	p := accesstoken.New(dp, nil)
	claims := jwt.MapClaims{
		"sub":   "123454",
		"email": "denis@at.com",
	}

	at, err := p.Protect(context.Background(), claims)
	require.NoError(t, err)

	c2, err := p.ParseToken(context.Background(), at, nil)
	require.NoError(t, err)
	assert.Equal(t, claims, c2)

	c2, err = p.ParseToken(context.Background(), "12345", nil)
	require.NoError(t, err)
	assert.Nil(t, c2)
}