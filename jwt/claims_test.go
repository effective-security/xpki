package jwt

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type standardClaims struct {
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	ID        string   `json:"jti,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	Subject   string   `json:"sub,omitempty"`

	valid bool
}

func TestMain(m *testing.M) {
	xlog.SetGlobalLogLevel(xlog.DEBUG)
	retCode := m.Run()
	os.Exit(retCode)
}

func (c standardClaims) Valid() error {
	if !c.valid {
		return errors.Errorf("invalid claims")
	}
	return nil
}

func TestClaims(t *testing.T) {
	now := time.Now()
	c := Claims{
		"jti": "123",
		"aud": []string{"t1"},
	}
	assert.Equal(t, `{"aud":["t1"],"jti":"123"}`, c.Marshal())

	err := c.VerifyAudience([]string{"t2"}, true)
	assert.EqualError(t, err, "token missing audience: t2")
	err = c.VerifyIssuer("iss", true)
	assert.EqualError(t, err, "iss claim not found")
	err = c.VerifyExpiresAt(now, true)
	assert.EqualError(t, err, "exp claim not found")
	err = c.VerifyIssuedAt(now, true)
	assert.EqualError(t, err, "iat claim not found")
	err = c.VerifyNotBefore(now, true)
	assert.EqualError(t, err, "nbf claim not found")

	c2 := Claims{
		"jti": "2",
		"iss": "123",
		"aud": "t1",
		"nbf": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(time.Hour).Unix(),
	}

	err = c2.VerifyIssuer("iss", true)
	assert.EqualError(t, err, "invalid issuer: 123, expected: iss")
	err = c2.VerifyAudience([]string{"t2"}, true)
	assert.EqualError(t, err, "token missing audience: t2")
	err = c2.VerifyIssuedAt(now, true)
	assert.Contains(t, err.Error(), "token issued after now")
	err = c2.VerifyNotBefore(now, true)
	assert.Contains(t, err.Error(), "token not valid yet")

	c4 := map[string]interface{}{
		"c4":  "444",
		"aud": []string{"t1", "t2"},
		"exp": time.Now().Add(-time.Hour).Unix(),
	}
	err = c.Add(c2)
	require.NoError(t, err)
	assert.Equal(t, "2", c["jti"])

	err = c.Add(c4)
	require.NoError(t, err)
	assert.Equal(t, "444", c["c4"])
	err = c.VerifyExpiresAt(now, true)
	assert.Contains(t, err.Error(), "token expired at:")

	std := standardClaims{
		IssuedAt: time.Now().Unix(),
	}
	err = c.Add(std)
	require.NoError(t, err)
	assert.Len(t, c, 7)

	err = c.Add(3)
	assert.EqualError(t, err, "unsupported claims interface")

	c["exp"] = time.Now().Add(time.Hour).Unix()
	err = c.Valid()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token not valid yet, not before")

	c["nbf"] = time.Now().Add(-2 * time.Hour).Unix()
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	err = c.Valid()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at")

	var std2 standardClaims
	err = c.To(&std2)
	require.NoError(t, err)
	assert.EqualError(t, std2.Valid(), "invalid claims")
}

func TestClaims_String(t *testing.T) {
	c := func(o Claims, k, exp string) {
		act := o.String(k)
		assert.Equal(t, act, exp)
	}

	stru := struct {
		Foo string
		B   bool
		I   int
	}{Foo: "foo", B: true, I: -1}

	o := Claims{
		"foo":    "bar",
		"blank":  "",
		"count":  uint64(1),
		"struct": stru,
	}
	c(o, "foo", "bar")
	c(o, "blank", "")
	c(o, "unknown", "")
	c(o, "count", "1")
	c(o, "struct", `{"Foo":"foo","B":true,"I":-1}`)
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
		"struct": struct{}{},
		"tnil":   1,
		"tnil2":  "notime",
		"unix":   1645187555,
		"unixs":  "1645187555",
		"json":   json.Number("1645187555"),
		"uint64": uint64(1645187555),
		"int64":  int64(1645187555),
	}
	c(o, "t1", &t2)
	c(o, "t2", &t2)
	c(o, "t3", &t2)
	c(o, "tnil2", nil)
	c(o, "struct", nil)
	c(o, "unix", &t3)
	c(o, "unixs", &t3)
	c(o, "uint64", &t3)
	c(o, "int64", &t3)
	c(o, "json", &t3)
}
