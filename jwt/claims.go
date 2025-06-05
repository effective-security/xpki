package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/slices"
	"github.com/effective-security/xlog"
)

var (
	// TimeNowFn to override in unit tests
	TimeNowFn = time.Now

	// DefaultTimeSkew is an interval for allowed time skew
	DefaultTimeSkew = 5 * time.Minute
)

// Cnf is DPoP specific claim for JWT Key ID
type Cnf struct {
	Jkt string `json:"jkt,omitempty"`
}

// Claims represents public claim values (as specified in RFC 7519).
type Claims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  Audience     `json:"aud,omitempty"`
	Expiry    *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`

	// DPoP specific claims
	Cnf        *Cnf   `json:"cnf,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	HTTPMethod string `json:"htm,omitempty"`
	HTTPUri    string `json:"htu,omitempty"`

	// Custom most common claims
	Name          string `json:"name,omitempty"`
	Profile       string `json:"profile ,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified ,omitempty"`
	Phone         string `json:"phone_number,omitempty"`
	PhoneVerified bool   `json:"phone_number_verified ,omitempty"`
	// Role in the service
	Role   string `json:"role,omitempty"`
	Tenant string `json:"tenant,omitempty"`
	Org    string `json:"org,omitempty"`
	// map of Org:Role
	Orgs    map[string]string `json:"orgs,omitempty"`
	OrgRole string            `json:"org_role,omitempty"`
	Scope   Audience          `json:"scope,omitempty"`
}

// Marshal returns JSON encoded string
func (c *Claims) Marshal() string {
	raw, _ := json.Marshal(c)
	return string(raw)
}

// VerifyAudience compares the aud claim against expected.
func (c *Claims) VerifyAudience(expected []string) error {
	if len(expected) == 0 {
		return nil
	}
	if len(c.Audience) == 0 {
		return errors.Errorf("aud claim not found")
	}

	for _, a := range expected {
		if !c.Audience.Contains(a) {
			return errors.Errorf("token missing audience: %s", a)
		}
	}

	return nil
}

// VerifyExpiresAt returns true issued at is valid.
func (c *Claims) VerifyExpiresAt(now time.Time, req bool) error {
	if c.Expiry == nil {
		if req {
			return errors.Errorf("exp claim not found")
		}
		return nil
	}
	exp := c.Expiry.Time()
	if now.After(exp) {
		return errors.Errorf("token expired at: %s, now: %s",
			exp.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// VerifyIssuedAt verifies the iat claim.
func (c *Claims) VerifyIssuedAt(now time.Time, req bool) error {
	if c.IssuedAt == nil {
		if req {
			return errors.Errorf("iat claim not found")
		}
		return nil
	}
	iat := c.IssuedAt.Time()
	if iat.After(now) {
		return errors.Errorf("token issued after now: %s, now: %s",
			iat.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// VerifyNotBefore verifies the nbf claim.
func (c *Claims) VerifyNotBefore(now time.Time, req bool) error {
	if c.NotBefore == nil {
		if req {
			return errors.Errorf("nbf claim not found")
		}
		return nil
	}
	nbf := c.NotBefore.Time()
	if nbf.After(now) {
		return errors.Errorf("token not valid yet, not before: %s, now: %s",
			nbf.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// VerifyIssuer compares the iss claim against expected.
func (c *Claims) VerifyIssuer(expected string) error {
	if expected == "" {
		return nil
	}
	if c.Issuer == "" {
		return errors.Errorf("iss claim not found")
	}
	if !strings.EqualFold(c.Issuer, expected) {
		return errors.Errorf("invalid issuer: %s, expected: %s", c.Issuer, expected)
	}
	return nil
}

// VerifySubject compares the sub claim against expected.
func (c *Claims) VerifySubject(expected string) error {
	if expected == "" {
		return nil
	}
	if c.Subject == "" {
		return errors.Errorf("sub claim not found")
	}
	if !strings.EqualFold(c.Subject, expected) {
		return errors.Errorf("invalid subject: %s, expected: %s", c.Subject, expected)
	}
	return nil
}

// Valid returns error if the standard claims are invalid
func (c *Claims) Valid(cfg *VerifyConfig) error {
	now := TimeNowFn()

	err := c.VerifyExpiresAt(now, false)
	if err != nil {
		return err
	}

	err = c.VerifyIssuedAt(now.Add(DefaultTimeSkew), false)
	if err != nil {
		return err
	}

	err = c.VerifyNotBefore(now.Add(DefaultTimeSkew), false)
	if err != nil {
		return err
	}

	if cfg != nil {
		err = c.VerifyIssuer(cfg.ExpectedIssuer)
		if err != nil {
			return err
		}

		err = c.VerifySubject(cfg.ExpectedSubject)
		if err != nil {
			return err
		}

		err = c.VerifyAudience(cfg.ExpectedAudience)
		if err != nil {
			return err
		}
	}
	return nil
}

// MapClaims provides generic claims on map
type MapClaims map[string]any

// Add new claims to the map
func (c MapClaims) Add(val ...any) error {
	for _, i := range val {
		if i == nil {
			continue
		}
		switch m := i.(type) {
		case map[string]string:
			for k, v := range m {
				c[k] = v
			}
		case map[string]any:
			c.merge(m)
		case MapClaims:
			c.merge(m)
		default:
			if reflect.Indirect(reflect.ValueOf(i)).Kind() == reflect.Struct {
				m, err := normalize(i)
				if err != nil {
					return err
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
func (c MapClaims) To(val any) error {
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
func (c MapClaims) Marshal() string {
	raw, _ := json.Marshal(c)
	return string(raw)
}

func (c MapClaims) merge(m map[string]any) {
	for k, v := range m {
		c[k] = v
	}
}

func normalize(i any) (map[string]any, error) {
	m := make(map[string]any)

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

// CNF returns DPoP cnf claim
func (c MapClaims) CNF() *Cnf {
	v := c["cnf"]
	if v == nil {
		return nil
	}
	switch tv := v.(type) {
	case *Cnf:
		return tv
	case Cnf:
		return &tv
	case map[string]string:
		return &Cnf{
			Jkt: tv["jkt"],
		}
	case map[string]any:
		if jkt, ok := tv["jkt"].(string); ok {
			return &Cnf{
				Jkt: jkt,
			}
		}
	}
	return nil
}

// StringsMap will return the named claim as a map[string]string,
func (c MapClaims) StringsMap(k string) map[string]string {
	if c == nil {
		return nil
	}
	v := c[k]
	if v == nil {
		return nil
	}
	switch tv := v.(type) {
	case map[string]string:
		return tv
	case map[string]any:
		res := map[string]string{}
		for k, v := range tv {
			res[k] = fmt.Sprint(v)
		}
		return res
	}
	return nil
}

// Strings will return the named claim as a []string
func (c MapClaims) Strings(k string) []string {
	if c == nil {
		return nil
	}
	v := c[k]
	if v == nil {
		return nil
	}
	switch tv := v.(type) {
	case []any:
		var res []string
		for _, v := range tv {
			if vs, ok := v.(string); ok {
				res = append(res, vs)
			} else {
				res = append(res, fmt.Sprint(v))
			}
		}
		return res
	case []string:
		return tv
	case string:
		return []string{tv}
	}
	return nil
}

// String will return the named claim as a string,
// if the underlying type is not a string,
// it will try and co-oerce it to a string.
func (c MapClaims) String(k string) string {
	if c == nil {
		return ""
	}
	v := c[k]
	if v == nil {
		return ""
	}
	switch tv := v.(type) {
	case string:
		return tv
	case uint64:
		return strconv.FormatUint(tv, 10)
	case int64:
		return strconv.FormatInt(tv, 10)
	case json.Number:
		return tv.String()
	case bool:
		if tv {
			return "true"
		}
		return "false"
	default:
		logger.KV(xlog.DEBUG, "reason", "unsupported", "val", k, "type", fmt.Sprintf("%T", tv))
		return xlog.EscapedString(v)
	}
}

// Bool will return the named claim as Bool
func (c MapClaims) Bool(k string) bool {
	if c == nil {
		return false
	}
	v := c[k]
	if v == nil {
		return false
	}
	switch tv := v.(type) {
	case bool:
		return tv
	case string:
		return tv == "true"
	default:
		logger.KV(xlog.DEBUG, "reason", "unsupported", "val", k, "type", fmt.Sprintf("%T", tv))
		return false
	}
}

// TimeVal will return the named claim as Time value
func (c MapClaims) TimeVal(k string) time.Time {
	p := c.Time(k)
	if p != nil {
		return *p
	}
	return time.Time{}
}

// Time will return the named claim as Time pointer
func (c MapClaims) Time(k string) *time.Time {
	if c == nil {
		return nil
	}
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
	case float64:
		t := time.Unix(int64(tv), 0)
		return &t
	case int:
		t := time.Unix(int64(tv), 0)
		return &t
	case json.Number:
		unix, err := tv.Int64()
		if err != nil {
			return nil
		}
		t := time.Unix(unix, 0)
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
			logger.KV(xlog.DEBUG, "val", k, "type", fmt.Sprintf("%T", tv), "err", err.Error())
			return nil
		}
		t := time.Unix(unix, 0)
		return &t
	default:
		logger.KV(xlog.DEBUG, "reason", "unsupported", "val", k, "type", fmt.Sprintf("%T", tv))
		return nil
	}
}

// Int will return the named claim as an int
func (c MapClaims) Int(k string) int {
	if c == nil {
		return 0
	}
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
	case json.Number:
		i, _ := tv.Int64()
		return int(i)
	case string:
		i, err := strconv.Atoi(tv)
		if err != nil {
			logger.KV(xlog.DEBUG, "val", k, "type", fmt.Sprintf("%T", tv), "err", err.Error())
			return 0
		}
		return i
	default:
		logger.KV(xlog.DEBUG, "reason", "unsupported", "val", k, "type", fmt.Sprintf("%T", tv))
		return 0
	}
}

// UInt64 will return the named claim as an uint64
func (c MapClaims) UInt64(k string) uint64 {
	if c == nil {
		return 0
	}
	v := c[k]
	if v == nil {
		return 0
	}
	switch tv := v.(type) {
	case int:
		return uint64(tv)
	case int32:
		return uint64(tv)
	case int64:
		return uint64(tv)
	case uint:
		return uint64(tv)
	case uint32:
		return uint64(tv)
	case uint64:
		return uint64(tv)
	case json.Number:
		i, _ := tv.Int64()
		return uint64(i)
	case string:
		i64, err := strconv.ParseUint(tv, 10, 64)
		if err != nil {
			logger.KV(xlog.DEBUG, "val", k, "type", fmt.Sprintf("%T", tv), "err", err.Error())
			return 0
		}
		return i64
	default:
		logger.KV(xlog.DEBUG, "reason", "unsupported", "val", k, "type", fmt.Sprintf("%T", tv))
		return 0
	}
}

// Int64 will return the named claim as an int64
func (c MapClaims) Int64(k string) int64 {
	if c == nil {
		return 0
	}
	v := c[k]
	if v == nil {
		return 0
	}
	switch tv := v.(type) {
	case int:
		return int64(tv)
	case int32:
		return int64(tv)
	case int64:
		return int64(tv)
	case uint:
		return int64(tv)
	case uint32:
		return int64(tv)
	case uint64:
		return int64(tv)
	case string:
		i64, err := strconv.ParseInt(tv, 10, 64)
		if err != nil {
			logger.KV(xlog.DEBUG, "val", k, "type", fmt.Sprintf("%T", tv), "err", err.Error())
			return 0
		}
		return i64
	default:
		logger.KV(xlog.DEBUG, "reason", "unsupported", "val", k, "type", fmt.Sprintf("%T", tv))
		return 0
	}
}

// VerifyAudience compares the aud claim against expected.
func (c MapClaims) VerifyAudience(expected []string) error {
	if len(expected) == 0 {
		return nil
	}
	var aud []string
	switch v := c["aud"].(type) {
	case string:
		aud = append(aud, v)
	case []string:
		aud = v
	case []any:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return errors.Errorf("invalid aud claim with unsupported value")
			}
			aud = append(aud, vs)
		}
	}

	if len(aud) == 0 {
		return errors.Errorf("aud claim not found")
	}

	for _, a := range expected {
		if !slices.ContainsString(aud, a) {
			return errors.Errorf("token missing audience: %s", a)
		}
	}

	return nil
}

// VerifyExpiresAt returns true issued at is valid.
func (c MapClaims) VerifyExpiresAt(now time.Time, req bool) error {
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
func (c MapClaims) VerifyIssuedAt(now time.Time, req bool) error {
	iat := c.Time("iat")
	if iat == nil {
		if req {
			return errors.Errorf("iat claim not found")
		}
		return nil
	}
	if iat.After(now) {
		return errors.Errorf("token issued at %s, after now: %s",
			iat.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// VerifyNotBefore verifies the nbf claim.
func (c MapClaims) VerifyNotBefore(now time.Time, req bool) error {
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

// VerifyIssuer compares the iss claim against expected.
func (c MapClaims) VerifyIssuer(expected string) error {
	if expected == "" {
		return nil
	}
	iss := c.String("iss")
	if iss == "" {
		return errors.Errorf("iss claim not found")
	}
	if !strings.EqualFold(iss, expected) {
		return errors.Errorf("invalid issuer: %s, expected: %s", iss, expected)
	}
	return nil
}

// VerifySubject compares the sub claim against expected.
func (c MapClaims) VerifySubject(expected string) error {
	if expected == "" {
		return nil
	}
	sub := c.String("sub")
	if sub == "" {
		return errors.Errorf("sub claim not found")
	}
	if !strings.EqualFold(sub, expected) {
		return errors.Errorf("invalid subject: %s, expected: %s", sub, expected)
	}
	return nil
}

// Valid returns error if the standard claims are invalid
func (c MapClaims) Valid(cfg *VerifyConfig) error {
	now := TimeNowFn()

	err := c.VerifyExpiresAt(now, false)
	if err != nil {
		return err
	}

	err = c.VerifyIssuedAt(now.Add(DefaultTimeSkew), false)
	if err != nil {
		return err
	}

	err = c.VerifyNotBefore(now.Add(DefaultTimeSkew), false)
	if err != nil {
		return err
	}

	if cfg != nil {
		err = c.VerifyIssuer(cfg.ExpectedIssuer)
		if err != nil {
			return err
		}

		err = c.VerifySubject(cfg.ExpectedSubject)
		if err != nil {
			return err
		}

		err = c.VerifyAudience(cfg.ExpectedAudience)
		if err != nil {
			return err
		}
	}
	return nil
}

// NumericDate represents date and time as the number of seconds since the
// epoch, ignoring leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
// See RFC7519 Section 2: https://tools.ietf.org/html/rfc7519#section-2
type NumericDate int64

// NewNumericDate constructs NumericDate from time.Time value.
func NewNumericDate(t time.Time) *NumericDate {
	if t.IsZero() {
		return nil
	}

	// While RFC 7519 technically states that NumericDate values may be
	// non-integer values, we don't bother serializing timestamps in
	// claims with sub-second accurancy and just round to the nearest
	// second instead. Not convined sub-second accuracy is useful here.
	out := NumericDate(t.Unix())
	return &out
}

// MarshalJSON serializes the given NumericDate into its JSON representation.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(n), 10)), nil
}

// UnmarshalJSON reads a date from its JSON representation.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")

	f, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return errors.Errorf("expected number value to unmarshal NumericDate: %s", s)
	}

	*n = NumericDate(f)
	return nil
}

// Time returns time.Time representation of NumericDate.
func (n *NumericDate) Time() time.Time {
	if n == nil {
		return time.Time{}
	}
	return time.Unix(int64(*n), 0)
}

// Audience represents the recipients that the token is intended for.
type Audience []string

// UnmarshalJSON reads an audience from its JSON representation.
func (s *Audience) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return errors.WithStack(err)
	}

	switch v := v.(type) {
	case string:
		*s = []string{v}
	case []any:
		a := make([]string, len(v))
		for i, e := range v {
			s, ok := e.(string)
			if !ok {
				return errors.Errorf("audience: expected string or array value")
			}
			a[i] = s
		}
		*s = a
	default:
		return errors.Errorf("audience: unsupported type: '%T'", v)
	}

	return nil
}

// Contains returns true if audience contains expected value
func (s Audience) Contains(expected string) bool {
	return slices.ContainsString(s, expected)
}

var userInfoClaims = []string{
	"sub", "email", "email_verified", "name", "family_name", "given_name", "locale", "picture", "nonce",
}

// CopyUserInfoClaims from source to destination
func CopyUserInfoClaims(src, dst MapClaims) {
	for _, c := range userInfoClaims {
		if v := src[c]; v != nil {
			dst[c] = v
		}
	}
}

// SetClaimsExpiration sets expiration claims
func SetClaimsExpiration(claims MapClaims, expiry time.Duration) {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)
	notBefore := now.Add(DefaultNotBefore)

	claims["iat"] = now.Unix()
	claims["nbf"] = notBefore.Unix()
	claims["exp"] = expiresAt.Unix()
}

// CreateClaims returns claims
func CreateClaims(jti, subject, issuer string, audience []string, expiry time.Duration, extraClaims MapClaims) MapClaims {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)
	notBefore := now.Add(DefaultNotBefore)

	claims := &Claims{
		ID:        jti,
		Expiry:    NewNumericDate(expiresAt),
		IssuedAt:  NewNumericDate(now),
		NotBefore: NewNumericDate(notBefore),
		Issuer:    issuer,
		Audience:  audience,
		Subject:   subject,
	}
	c := MapClaims{}
	_ = c.Add(claims, extraClaims)
	return c
}
