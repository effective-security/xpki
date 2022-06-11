package jwt

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	xlog.SetGlobalLogLevel(xlog.DEBUG)
	retCode := m.Run()
	os.Exit(retCode)
}

func TestClaims(t *testing.T) {
	now := time.Now()
	c := &Claims{
		ID: "123",
	}
	assert.Equal(t, `{"jti":"123"}`, c.Marshal())
	assert.EqualError(t, c.VerifyExpiresAt(now, true), "exp claim not found")
	assert.EqualError(t, c.VerifyIssuedAt(now, true), "iat claim not found")
	assert.EqualError(t, c.VerifyNotBefore(now, true), "nbf claim not found")
	assert.EqualError(t, c.VerifyAudience([]string{"t2"}), "aud claim not found")
	assert.EqualError(t, c.VerifyIssuer("iss"), "iss claim not found")
	assert.EqualError(t, c.VerifySubject("sub"), "sub claim not found")

	assert.NoError(t, c.VerifyExpiresAt(now, false))
	assert.NoError(t, c.VerifyIssuedAt(now, false))
	assert.NoError(t, c.VerifyNotBefore(now, false))

	c.Issuer = "iss1"
	c.Audience = []string{"aud1"}
	c.Subject = "sub1"

	assert.EqualError(t, c.VerifyAudience([]string{"t2"}), "token missing audience: t2")
	assert.EqualError(t, c.VerifyIssuer("iss"), "invalid issuer: iss1, expected: iss")
	assert.EqualError(t, c.VerifySubject("sub"), "invalid subject: sub1, expected: sub")

	cfg := VerifyConfig{
		ExpectedIssuer:   c.Issuer,
		ExpectedAudience: c.Audience,
		ExpectedSubject:  c.Subject,
	}
	assert.NoError(t, c.Valid(cfg))
	cfg = VerifyConfig{}
	assert.NoError(t, c.Valid(cfg))

	c.IssuedAt = NewNumericDate(now.Add(time.Hour))
	err := c.Valid(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token issued after now:")

	c.IssuedAt = NewNumericDate(now.Add(-time.Hour))
	c.NotBefore = NewNumericDate(now.Add(time.Hour))
	err = c.Valid(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token not valid yet, not before:")

	c.NotBefore = NewNumericDate(now.Add(-time.Hour))
	c.Expiry = NewNumericDate(now.Add(-time.Hour))
	err = c.Valid(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at:")

	c.Expiry = NewNumericDate(now.Add(time.Hour))
	assert.NoError(t, c.Valid(cfg))
}

func TestAudience(t *testing.T) {
	var a Audience
	require.NoError(t, a.UnmarshalJSON([]byte(`"123"`)))
	assert.Equal(t, Audience{"123"}, a)
	require.NoError(t, a.UnmarshalJSON([]byte(`["123", "aaa"]`)))
	assert.Equal(t, Audience{"123", "aaa"}, a)
	assert.EqualError(t, a.UnmarshalJSON([]byte(`{"aud":"123"}`)), "audience: unsupported type: 'map[string]interface {}'")
	assert.EqualError(t, a.UnmarshalJSON([]byte(`["1", 0.1]`)), "audience: expected string or array value")
	assert.EqualError(t, a.UnmarshalJSON([]byte(`[}`)), "invalid character '}' looking for beginning of value")
}

func TestNumericDate(t *testing.T) {
	var tim time.Time
	assert.Nil(t, NewNumericDate(tim))
	var val NumericDate
	assert.EqualError(t, val.UnmarshalJSON([]byte(`"abc"`)), "expected number value to unmarshal NumericDate: \"abc\"")

	var nn *NumericDate
	assert.True(t, nn.Time().IsZero())
}

func TestMapClaims(t *testing.T) {
	now := time.Now()
	cfg := VerifyConfig{}
	c := MapClaims{}
	assert.EqualError(t, c.VerifyExpiresAt(now, true), "exp claim not found")
	assert.EqualError(t, c.VerifyIssuedAt(now, true), "iat claim not found")
	assert.EqualError(t, c.VerifyNotBefore(now, true), "nbf claim not found")
	assert.EqualError(t, c.VerifyAudience([]string{"t2"}), "aud claim not found")
	assert.EqualError(t, c.VerifyIssuer("iss"), "iss claim not found")
	assert.EqualError(t, c.VerifySubject("sub"), "sub claim not found")

	assert.NoError(t, c.VerifyExpiresAt(now, false))
	assert.NoError(t, c.VerifyIssuedAt(now, false))
	assert.NoError(t, c.VerifyNotBefore(now, false))

	c = MapClaims{
		"jti": "123",
		"aud": []string{"t1"},
	}
	assert.Equal(t, `{"aud":["t1"],"jti":"123"}`, c.Marshal())

	err := c.VerifyAudience([]string{"t2"})
	assert.EqualError(t, err, "token missing audience: t2")
	err = c.VerifyIssuer("iss")
	assert.EqualError(t, err, "iss claim not found")
	err = c.VerifyExpiresAt(now, true)
	assert.EqualError(t, err, "exp claim not found")
	err = c.VerifyIssuedAt(now, true)
	assert.EqualError(t, err, "iat claim not found")
	err = c.VerifyNotBefore(now, true)
	assert.EqualError(t, err, "nbf claim not found")

	c2 := MapClaims{
		"jti": "2",
		"iss": "123",
		"sub": "sFX",
		"aud": "t1",
		"nbf": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(time.Hour).Unix(),
	}
	c2c := MapClaims{}
	CopyUserInfoClaims(c2, c2c)
	assert.NotEqual(t, c2, c2c)

	err = c2.VerifySubject("s")
	assert.EqualError(t, err, "invalid subject: sFX, expected: s")
	err = c2.VerifyIssuer("iss")
	assert.EqualError(t, err, "invalid issuer: 123, expected: iss")
	err = c2.VerifyAudience([]string{"t2"})
	assert.EqualError(t, err, "token missing audience: t2")
	err = c2.VerifyIssuedAt(now, true)
	assert.Contains(t, err.Error(), "token issued after now")
	err = c2.VerifyNotBefore(now, true)
	assert.Contains(t, err.Error(), "token not valid yet")

	cfg = VerifyConfig{
		ExpectedIssuer:   "123",
		ExpectedAudience: []string{"t1"},
		ExpectedSubject:  "sFX",
	}
	assert.Error(t, c2.Valid(cfg))
	c2["nbf"] = time.Now().Add(-2 * time.Hour).Unix()
	c2["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	c2["exp"] = time.Now().Add(time.Hour).Unix()
	assert.NoError(t, c2.Valid(cfg))

	c4 := map[string]interface{}{
		"c4":  "444",
		"aud": []string{"t1", "t2"},
		"exp": time.Now().Add(-time.Hour).Unix(),
	}
	err = c.Add(c2, nil)
	require.NoError(t, err)
	assert.Equal(t, "2", c["jti"])

	err = c.Add(nil, c4)
	require.NoError(t, err)
	assert.Equal(t, "444", c["c4"])
	err = c.VerifyExpiresAt(now, true)
	assert.Contains(t, err.Error(), "token expired at:")

	std := Claims{
		IssuedAt: NewNumericDate(time.Now()),
	}
	err = c.Add(std)
	require.NoError(t, err)
	assert.Len(t, c, 8)
	SetClaimsExpiration(c, 60*time.Minute)

	err = c.Add(3)
	assert.EqualError(t, err, "unsupported claims interface")

	c["exp"] = time.Now().Add(time.Hour).Unix()
	c["nbf"] = time.Now().Add(time.Hour).Unix()
	err = c.Valid(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token not valid yet, not before")

	c["nbf"] = time.Now().Add(-2 * time.Hour).Unix()
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	err = c.Valid(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at")

	var std2 Claims
	err = c.To(&std2)
	require.NoError(t, err)
	err = c.Valid(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at")

	c3 := MapClaims{
		"aud": []interface{}{time.Now()},
	}
	assert.EqualError(t, c3.VerifyAudience([]string{"t2"}), "invalid aud claim with unsupported value")
}

func TestClaims_String(t *testing.T) {
	c := func(o MapClaims, k, exp string) {
		act := o.String(k)
		assert.Equal(t, act, exp)
	}

	stru := struct {
		Foo string
		B   bool
		I   int
	}{Foo: "foo", B: true, I: -1}

	o := MapClaims{
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
	c := func(o MapClaims, k string, exp int) {
		act := o.Int(k)
		assert.Equal(t, act, exp)
	}

	o := MapClaims{
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
	c := func(o MapClaims, k string, exp bool) {
		act := o.Bool(k)
		assert.Equal(t, act, exp)
	}

	o := MapClaims{
		"nil":    nil,
		"struct": struct{}{},
		"true":   true,
		"false":  false,
		"strue":  "true",
	}
	c(o, "nil", false)
	c(o, "struct", false)
	c(o, "true", true)
	c(o, "strue", true)
	c(o, "false", false)
}

func TestCreateClaims(t *testing.T) {
	cl := CreateClaims("123", "subj", "issuer", []string{"aud"}, 60*time.Minute, nil)
	assert.NotNil(t, cl.Time("iat"))
	assert.NotNil(t, cl.Time("nbf"))
	assert.NotNil(t, cl.Time("exp"))
}

func TestClaims_Time(t *testing.T) {
	c := func(o MapClaims, k string, exp *time.Time) {
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

	o := MapClaims{
		"t1":      "2007-02-03T15:05:06.123-0701",
		"t2":      t2,
		"t3":      &t2,
		"err":     "11111111111111111111111111111",
		"struct":  struct{}{},
		"tnil":    1,
		"tnil2":   "notime",
		"unix":    1645187555,
		"float64": float64(1645187555),
		"unixs":   "1645187555",
		"json":    json.Number("1645187555"),
		"uint64":  uint64(1645187555),
		"int64":   int64(1645187555),
	}
	c(o, "t1", &t2)
	c(o, "t2", &t2)
	c(o, "t3", &t2)
	c(o, "err", nil)
	c(o, "tnil2", nil)
	c(o, "struct", nil)
	c(o, "unix", &t3)
	c(o, "unixs", &t3)
	c(o, "float64", &t3)
	c(o, "uint64", &t3)
	c(o, "int64", &t3)
	c(o, "json", &t3)
}

func TestExpired(t *testing.T) {
	auth := `eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Il9TRVdHR0hLVGY2YmFvYWRZdEMycmdBVGJZUGh6Yjd1eWt0c3FIeHZ4YmciLCJ5IjoieExfMFktdXFsU0lsZm1Md3NwbXpiSTJmRWxYcF9YS0Q1Tm1xd2c5aXZFUSJ9LCJ0eXAiOiJKV1QifQ.eyJjbmYiOnsiamt0IjoidTJBa1VNQjFzaHBfYTVtSldFODFrMFdGSEhGLVlJNTJWajByQUl5dmdHRSJ9LCJlbWFpbCI6ImRlbmlzQGVrc3BhbmQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImV4cCI6MTY0NzExMDU3OCwiaWF0IjoxNjQ3MTA2OTc5LCJuYW1lIjoiRGVuaXMgSXNzb3Vwb3YiLCJuYmYiOjE2NDcxMDY4NTksInByb3ZpZGVyIjoiZ29vZ2xlIiwic3ViIjoiMTE1MTgyMzI4NjQzNjY2MDAyMDExIn0.dp42oVGjbAoPb8WiRqWLHU9p_sW0kgjK0NktfunIbm_FJAGdoEsxkeigs3wvWdCNxXrgAuujK9jJhfBwvrjC7g`

	parser := TokenParser{
		UseJSONNumber: true,
	}

	claims := MapClaims{}
	token, _, err := parser.ParseUnverified(auth, claims)
	require.NoError(t, err)
	assert.False(t, token.Valid)
	err = claims.VerifyExpiresAt(time.Now(), true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token expired at:")
}

func TestNil(t *testing.T) {
	var c MapClaims
	assert.Empty(t, c.String("123"))
	assert.Equal(t, 0, c.Int("123"))
	assert.Nil(t, c.Time("123"))
	assert.False(t, c.Bool("123"))
}
