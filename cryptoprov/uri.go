package cryptoprov

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
)

// PrivateKeyURI holds PKCS#11 private key information.
//
// A token may be identified either by serial number or label.  If
// both are specified then the first match wins.
type PrivateKeyURI interface {
	// Token manufacturer
	Manufacturer() string

	// Model manufacturer
	Model() string

	// Token serial number
	TokenSerial() string

	// Token label
	TokenLabel() string

	// Key ID
	ID() string
}

type keyURI struct {
	manufacturer string
	model        string
	tokenSerial  string
	tokenLabel   string
	id           string
}

// Token manufacturer
func (k *keyURI) Manufacturer() string {
	return k.manufacturer
}

// Model manufacturer
func (k *keyURI) Model() string {
	return k.model
}

// Token serial number
func (k *keyURI) TokenSerial() string {
	return k.tokenSerial
}

// Token label
func (k *keyURI) TokenLabel() string {
	return k.tokenLabel
}

// Key ID
func (k *keyURI) ID() string {
	return k.id
}

const pkcs11Scheme = "pkcs11:"

// Attribute names of RFC 7512 §2.3.
const (
	attrManufacturer = "manufacturer"
	attrModel        = "model"
	attrToken        = "token"
	attrSerial       = "serial"
	attrID           = "id"
	attrType         = "type"
	attrModuleName   = "module-name"
	attrModulePath   = "module-path"
	attrPinSource    = "pin-source"
	attrPinValue     = "pin-value"
)

// queryAttributes are the RFC 7512 §2.3 query attributes. For compatibility
// with the URIs this package accepted before XPKI-027 they are also accepted
// in the path, but never in both places.
var queryAttributes = []string{attrPinSource, attrPinValue, attrModuleName, attrModulePath}

// attrNameRE is pk11-v-attr-nm-char of RFC 7512 §2.3; the standard names
// match it too.
var attrNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// pathPinValueRE and queryPinValueRE match a pin-value attribute in the
// path and in the query component, for redaction in diagnostics. A path
// value ends at ";" and may contain "&"; a query value ends at "&" and may
// contain ";" (RFC 7512 §2.3), so each component has its own delimiter.
var (
	pathPinValueRE  = regexp.MustCompile(`(^|[:;])pin-value=[^;]*`)
	queryPinValueRE = regexp.MustCompile(`(^|&)pin-value=[^&]*`)
)

// pkcs11URI is a parsed RFC 7512 URI: the percent-decoded path attributes
// and the four standard query attributes, wherever they were placed.
type pkcs11URI struct {
	path  map[string]string
	query map[string]string
}

// attr returns the path attribute name, or "" when it is absent. An
// attribute given with an empty value counts as absent.
func (u *pkcs11URI) attr(name string) string {
	return u.path[name]
}

// qattr returns the query attribute name, or "" when it is absent.
func (u *pkcs11URI) qattr(name string) string {
	return u.query[name]
}

// redactURI returns uri with the value of every pin-value attribute
// replaced, for error messages and logs, in the path and in the query
// component according to its delimiters.
func redactURI(uri string) string {
	path, query, hasQuery := strings.Cut(uri, "?")
	path = pathPinValueRE.ReplaceAllString(path, "${1}pin-value=***")
	if !hasQuery {
		return path
	}
	return path + "?" + queryPinValueRE.ReplaceAllString(query, "${1}pin-value=***")
}

// redactAttribute returns one name=value segment with the value replaced
// when it is a pin-value, whatever delimiters the value contains.
func redactAttribute(segment string) string {
	if strings.HasPrefix(segment, attrPinValue+"=") {
		return attrPinValue + "=***"
	}
	return segment
}

func invalidURI(uri, format string, args ...any) error {
	return errors.Wrapf(ErrInvalidURI, "%s in %q", fmt.Sprintf(format, args...), redactURI(uri))
}

// uriError is an ErrInvalidURI that keeps its cause, such as the
// *fs.PathError of an unreadable pin-source file, visible to errors.Is and
// errors.As.
type uriError struct {
	msg   string
	cause error
}

func (e *uriError) Error() string   { return e.msg }
func (e *uriError) Unwrap() []error { return []error{ErrInvalidURI, e.cause} }

// invalidURICause is invalidURI with cause as the underlying error.
func invalidURICause(uri string, cause error, format string, args ...any) error {
	return &uriError{
		msg:   fmt.Sprintf("%s: %v in %q: %v", fmt.Sprintf(format, args...), cause, redactURI(uri), ErrInvalidURI),
		cause: cause,
	}
}

// parsePKCS11URI parses an RFC 7512 PKCS #11 URI:
//
//	pkcs11:path-attr;path-attr?query-attr&query-attr
//
// Path attributes are separated by ";", query attributes by "&", every
// attribute is name=value and values are percent-decoded ("+" stays a
// literal plus). Surrounding whitespace of the URI and empty segments (a
// trailing or doubled separator) are ignored. Unknown and
// vendor attributes are ignored. It is an error when an attribute name
// repeats in the path, when one of pin-source, pin-value, module-name and
// module-path repeats in the query or is given both in the path and in the
// query, when both pin-source and pin-value are present (RFC 7512 §2.4),
// when module-path is relative, or when a value has a bad percent escape.
func parsePKCS11URI(uri string) (*pkcs11URI, error) {
	s := strings.TrimSpace(uri)
	if len(s) < len(pkcs11Scheme) || !strings.EqualFold(s[:len(pkcs11Scheme)], pkcs11Scheme) {
		return nil, invalidURI(uri, "scheme is not pkcs11")
	}
	s = s[len(pkcs11Scheme):]

	rawPath, rawQuery, hasQuery := strings.Cut(s, "?")

	u := &pkcs11URI{
		path:  map[string]string{},
		query: map[string]string{},
	}

	if rawPath != "" {
		for _, segment := range strings.Split(rawPath, ";") {
			if segment == "" {
				// a trailing or doubled separator, accepted before XPKI-027
				continue
			}
			name, value, err := parseAttribute(segment)
			if err != nil {
				return nil, invalidURI(uri, "path attribute %q: %v", redactAttribute(segment), err)
			}
			if _, dup := u.path[name]; dup {
				return nil, invalidURI(uri, "duplicate path attribute %q", name)
			}
			u.path[name] = value
		}
	}

	if hasQuery && rawQuery != "" {
		for _, segment := range strings.Split(rawQuery, "&") {
			if segment == "" {
				continue
			}
			name, value, err := parseAttribute(segment)
			if err != nil {
				return nil, invalidURI(uri, "query attribute %q: %v", redactAttribute(segment), err)
			}
			if !slices.Contains(queryAttributes, name) {
				// vendor query attributes are ignored
				continue
			}
			if _, dup := u.query[name]; dup {
				return nil, invalidURI(uri, "duplicate query attribute %q", name)
			}
			u.query[name] = value
		}
	}

	// legacy placement: the query attributes were accepted in the path
	for _, name := range queryAttributes {
		value, inPath := u.path[name]
		if !inPath {
			continue
		}
		if _, inQuery := u.query[name]; inQuery {
			return nil, invalidURI(uri, "attribute %q in both path and query", name)
		}
		u.query[name] = value
		delete(u.path, name)
	}

	_, hasPinSource := u.query[attrPinSource]
	_, hasPinValue := u.query[attrPinValue]
	if hasPinSource && hasPinValue {
		return nil, invalidURI(uri, "both pin-source and pin-value are present")
	}
	if p := u.query[attrModulePath]; p != "" && !filepath.IsAbs(p) {
		return nil, invalidURI(uri, "module-path %q is not absolute", p)
	}

	return u, nil
}

// parseAttribute splits one name=value attribute and percent-decodes the
// value.
func parseAttribute(segment string) (name, value string, err error) {
	name, rawValue, ok := strings.Cut(segment, "=")
	if !ok {
		return "", "", errors.New("missing '='")
	}
	if !attrNameRE.MatchString(name) {
		return "", "", errors.New("invalid attribute name")
	}
	value, err = url.PathUnescape(rawValue)
	if err != nil {
		return "", "", errors.New("invalid percent-encoding")
	}
	return name, value, nil
}

// trimTokenField removes the padding a PKCS #11 token reports in its
// manufacturer and model fields.
func trimTokenField(s string) string {
	return strings.TrimSpace(strings.TrimRight(s, "\x00"))
}

// ParseTokenURI parses a PKCS #11 URI (RFC 7512) into a token
// configuration. The path attributes manufacturer, model, token and serial
// select the token; the query attributes module-name, module-path,
// pin-value and pin-source (a file: URI whose content, trimmed, is the PIN)
// set the library and the PIN. module-path overrides module-name when both
// are present. The query attributes are also accepted in the path, as this
// package did before XPKI-027, but not in both places, and a URI with both
// pin-source and pin-value is refused (RFC 7512 §2.4). Manufacturer and
// model are trimmed. Errors never contain a pin-value.
func ParseTokenURI(uri string) (TokenConfig, error) {
	u, err := parsePKCS11URI(uri)
	if err != nil {
		return nil, err
	}

	c := &tokenConfig{
		Man:    trimTokenField(u.attr(attrManufacturer)),
		Mod:    trimTokenField(u.attr(attrModel)),
		Label:  u.attr(attrToken),
		Serial: u.attr(attrSerial),
		Dir:    u.qattr(attrModuleName),
		Pwd:    u.qattr(attrPinValue),
	}
	if p := u.qattr(attrModulePath); p != "" {
		c.Dir = p
	}

	if pinSourceURI := u.qattr(attrPinSource); pinSourceURI != "" {
		pin, err := readPinSource(pinSourceURI)
		if err != nil {
			return nil, invalidURICause(uri, err, "pin-source")
		}
		c.Pwd = pin
	}

	return c, nil
}

// readPinSource reads the PIN from a file: URI.
func readPinSource(source string) (string, error) {
	pinURI, err := url.Parse(source)
	if err != nil {
		return "", errors.New("not a URI")
	}
	if pinURI.Opaque != "" && pinURI.Path == "" {
		pinURI.Path = pinURI.Opaque
	}
	if pinURI.Scheme != "file" || pinURI.Path == "" {
		return "", errors.New("only file: URIs are supported")
	}
	pin, err := os.ReadFile(pinURI.Path)
	if err != nil {
		// the *fs.PathError stays inspectable with errors.Is/As
		return "", errors.WithMessagef(err, "read %s", pinURI.Path)
	}
	return strings.TrimSpace(string(pin)), nil
}

// ParsePrivateKeyURI parses a PKCS #11 URI (RFC 7512) into a key
// configuration. The URI must have type=private, serial and id (the id is
// percent-decoded and may hold binary data). Query attributes are validated
// like ParseTokenURI does but not returned.
func ParsePrivateKeyURI(uri string) (PrivateKeyURI, error) {
	u, err := parsePKCS11URI(uri)
	if err != nil {
		return nil, err
	}

	c := &keyURI{
		manufacturer: trimTokenField(u.attr(attrManufacturer)),
		model:        trimTokenField(u.attr(attrModel)),
		tokenLabel:   u.attr(attrToken),
		tokenSerial:  u.attr(attrSerial),
		id:           u.attr(attrID),
	}
	if u.attr(attrType) != "private" || c.tokenSerial == "" || c.id == "" {
		return nil, errors.Wrapf(ErrInvalidPrivateKeyURI, "type=private, serial and id are required in %q", redactURI(uri))
	}

	return c, nil
}
