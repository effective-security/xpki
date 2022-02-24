package jwt

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/x/slices"
	"github.com/pkg/errors"
)

var (
	// TimeNowFn to override in unit tests
	TimeNowFn = time.Now

	// DefaultTimeSkew is an interval for allowed time skew
	DefaultTimeSkew = 5 * time.Minute
)

// Claims provides generic claims on map
type Claims map[string]interface{}

// Add new claims to the map
func (c Claims) Add(val ...interface{}) error {
	for _, i := range val {
		if i == nil {
			continue
		}
		switch m := i.(type) {
		case map[string]interface{}:
			c.merge(m)
		case Claims:
			c.merge(m)
		default:
			if reflect.Indirect(reflect.ValueOf(i)).Kind() == reflect.Struct {
				m, err := normalize(i)
				if err != nil {
					return errors.WithStack(err)
				}
				c.merge(m)
			} else {
				return errors.Errorf("unsupported claims interface")
			}
		}
	}
	return nil
}

// To converts the claims to the value pointed to by v.
func (c Claims) To(val interface{}) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return errors.WithStack(err)
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	if err := d.Decode(val); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// Marshal returns JSON encoded string
func (c Claims) Marshal() string {
	raw, _ := json.Marshal(c)
	return string(raw)
}

func (c Claims) merge(m map[string]interface{}) {
	for k, v := range m {
		c[k] = v
	}
}

func normalize(i interface{}) (map[string]interface{}, error) {
	m := make(map[string]interface{})

	raw, err := json.Marshal(i)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()

	if err := d.Decode(&m); err != nil {
		return nil, errors.WithStack(err)
	}

	return m, nil
}

// String will return the named claim as a string,
// if the underlying type is not a string,
// it will try and co-oerce it to a string.
func (c Claims) String(k string) string {
	v := c[k]
	if v == nil {
		return ""
	}
	switch tv := v.(type) {
	case string:
		return tv
	default:
		return xlog.String(v)
	}
}

// Bool will return the named claim as Bool
func (c Claims) Bool(k string) bool {
	v := c[k]
	if v == nil {
		return false
	}
	switch tv := v.(type) {
	case bool:
		return tv
	default:
		return false
	}
}

// Time will return the named claim as Time
func (c Claims) Time(k string) *time.Time {
	v := c[k]
	if v == nil {
		return nil
	}
	switch tv := v.(type) {
	case time.Time:
		return &tv
	case *time.Time:
		return tv
	case int64:
		t := time.Unix(tv, 0)
		return &t
	case uint64:
		t := time.Unix(int64(tv), 0)
		return &t
	case int:
		t := time.Unix(int64(tv), 0)
		return &t
	case string:
		if len(tv) > 20 {
			t, err := time.Parse("2006-01-02T15:04:05.000-0700", tv)
			if err != nil {
				return nil
			}
			return &t
		}
		unix, err := strconv.ParseInt(tv, 10, 64)
		if err != nil {
			return nil
		}
		t := time.Unix(unix, 0)
		return &t
	default:
		return nil
	}
}

// Int will return the named claim as an int
func (c Claims) Int(k string) int {
	v := c[k]
	if v == nil {
		return 0
	}
	switch tv := v.(type) {
	case int:
		return tv
	case int32:
		return int(tv)
	case int64:
		return int(tv)
	case uint:
		return int(tv)
	case uint32:
		return int(tv)
	case uint64:
		return int(tv)
	case string:
		i, err := strconv.Atoi(tv)
		if err != nil {
			return 0
		}
		return i
	default:
		return 0
	}
}

// VerifyAudience compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c Claims) VerifyAudience(cmp []string, req bool) error {
	var aud []string
	switch v := c["aud"].(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return errors.Errorf("invalid aud claim with unsupported value")
			}
			aud = append(aud, vs)
		}
	}

	if len(aud) == 0 && req {
		return errors.Errorf("aud claim not found")
	}

	for _, a := range cmp {
		if !slices.ContainsString(aud, a) {
			return errors.Errorf("token missing audience: %s", a)
		}
	}

	return nil
}

// VerifyExpiresAt returns true issued at is valid.
func (c Claims) VerifyExpiresAt(now time.Time, req bool) error {
	exp := c.Time("exp")
	if exp == nil {
		if req {
			return errors.Errorf("exp claim not found")
		}
		return nil
	}
	if now.After(*exp) {
		return errors.Errorf("token expired at: %s, now: %s",
			exp.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// VerifyIssuedAt verifies the iat claim.
func (c Claims) VerifyIssuedAt(now time.Time, req bool) error {
	iat := c.Time("iat")
	if iat == nil {
		if req {
			return errors.Errorf("iat claim not found")
		}
		return nil
	}
	if iat.After(now) {
		return errors.Errorf("token issued after now: %s, now: %s",
			iat.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// VerifyNotBefore verifies the nbf claim.
func (c Claims) VerifyNotBefore(now time.Time, req bool) error {
	nbf := c.Time("nbf")
	if nbf == nil {
		if req {
			return errors.Errorf("nbf claim not found")
		}
		return nil
	}
	if nbf.After(now) {
		return errors.Errorf("token not valid yet, not before: %s, now: %s",
			nbf.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// VerifyIssuer compares the iss claim against cmp.
// If required is false, this method will return nil if the value matches or is unset
func (c Claims) VerifyIssuer(cmp string, req bool) error {
	iss := c.String("iss")
	if iss == "" && req {
		return errors.Errorf("iss claim not found")
	}
	if !strings.EqualFold(iss, cmp) {
		return errors.Errorf("invalid issuer: %s, expected: %s", iss, cmp)
	}
	return nil
}

// Valid returns error if the standard claims are invalid
func (c Claims) Valid() error {
	now := TimeNowFn()

	err := c.VerifyExpiresAt(now.Add(-DefaultTimeSkew), false)
	if err != nil {
		return errors.WithStack(err)
	}

	err = c.VerifyIssuedAt(now.Add(DefaultTimeSkew), false)
	if err != nil {
		return errors.WithStack(err)
	}

	err = c.VerifyNotBefore(now.Add(DefaultTimeSkew), false)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}
