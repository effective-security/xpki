package jwt

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"github.com/effective-security/xlog"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

// Claims provides generic claims on map
type Claims jwt.MapClaims

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
		case jwt.MapClaims:
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

// Valid returns error if the standard claims are invalid
func (c Claims) Valid() error {
	return jwt.MapClaims(c).Valid()
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
