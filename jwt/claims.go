package jwt

import (
	"bytes"
	"encoding/json"
	"reflect"

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
