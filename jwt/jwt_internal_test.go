package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrentKeyLastWithoutID(t *testing.T) {
	p, err := New(&Config{
		Issuer: "issuer.com",
		Keys: []*Key{
			{ID: "1", Seed: "seed1"},
			{ID: "2", Seed: "seed2"},
		},
	}, nil)
	require.NoError(t, err)
	id, _ := p.(*provider).currentKey()
	assert.Equal(t, "2", id)
}

func TestClaims(t *testing.T) {
	c := Claims{
		"jti": "123",
	}
	c2 := Claims{
		"jti": "2",
	}
	c3 := jwt.MapClaims{
		"c3": 333,
	}
	c4 := map[string]interface{}{
		"c4": "444",
	}
	err := c.Add(c2)
	require.NoError(t, err)
	assert.Equal(t, "2", c["jti"])

	err = c.Add(c3)
	require.NoError(t, err)
	assert.Equal(t, 333, c["c3"])

	err = c.Add(c4)
	require.NoError(t, err)
	assert.Equal(t, "444", c["c4"])

	std := jwt.StandardClaims{
		IssuedAt: time.Now().Unix(),
	}
	err = c.Add(std)
	require.NoError(t, err)
	assert.Len(t, c, 4)

	err = c.Add(3)
	assert.EqualError(t, err, "unsupported claims interface")
	assert.NoError(t, c.Valid())

	var std2 jwt.StandardClaims
	err = c.To(&std2)
	require.NoError(t, err)
	assert.NoError(t, std2.Valid())

	std2.NotBefore = time.Now().Add(time.Hour).Unix()
	std2.ExpiresAt = time.Now().Add(-time.Hour).Unix()
	assert.EqualError(t, std2.Valid(), "token is not valid yet")
}
