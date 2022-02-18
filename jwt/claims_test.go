package jwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestClaims_String(t *testing.T) {
	c := func(o Claims, k, exp string) {
		act := o.String(k)
		assert.Equal(t, act, exp)
	}
	o := Claims{"foo": "bar", "blank": "", "count": uint64(1)}
	c(o, "foo", "bar")
	c(o, "blank", "")
	c(o, "unknown", "")
	c(o, "count", "1")
}

func TestClaims_Int(t *testing.T) {
	c := func(o Claims, k string, exp int) {
		act := o.Int(k)
		assert.Equal(t, act, exp)
	}

	o := Claims{
		"nil":    nil,
		"struct": struct{}{},
		"z":      "123",
		"ze":     "abc",
		"n":      int(-1),
		"int":    int(1),
		"int32":  int32(32),
		"int64":  int64(64),
		"uint":   uint(123),
		"uint32": uint32(132),
		"uint64": uint64(164),
	}
	c(o, "nil", 0)
	c(o, "struct", 0)
	c(o, "z", 123)
	c(o, "ze", 0)
	c(o, "n", -1)
	c(o, "int", 1)
	c(o, "int32", 32)
	c(o, "int64", 64)
	c(o, "uint", 123)
	c(o, "uint32", 132)
	c(o, "uint64", 164)
}

func TestClaims_Bool(t *testing.T) {
	c := func(o Claims, k string, exp bool) {
		act := o.Bool(k)
		assert.Equal(t, act, exp)
	}

	o := Claims{
		"nil":    nil,
		"struct": struct{}{},
		"true":   true,
		"false":  false,
	}
	c(o, "nil", false)
	c(o, "struct", false)
	c(o, "true", true)
	c(o, "false", false)
}

func TestClaims_Time(t *testing.T) {
	c := func(o Claims, k string, exp *time.Time) {
		act := o.Time(k)
		if exp != nil {
			require.NotNil(t, act)
			assert.Equal(t, *act, *exp)
		} else {
			assert.Nil(t, act)
		}
	}
	t2, err := time.Parse("2006-01-02T15:04:05.000-0700", "2007-02-03T15:05:06.123-0701")
	require.NoError(t, err)

	t3 := time.Unix(1645187555, 0)

	o := Claims{
		"t1":     "2007-02-03T15:05:06.123-0701",
		"t2":     t2,
		"t3":     &t2,
		"tnil":   1,
		"tnil2":  "notime",
		"unix":   1645187555,
		"uint64": uint64(1645187555),
		"int64":  int64(1645187555),
	}
	c(o, "t1", &t2)
	c(o, "t2", &t2)
	c(o, "t3", &t2)
	c(o, "tnil2", nil)
	c(o, "unix", &t3)
	c(o, "uint64", &t3)
	c(o, "int64", &t3)
}
