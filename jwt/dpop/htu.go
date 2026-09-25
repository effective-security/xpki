package dpop

import (
	"cmp"
	"net/http"
	"net/url"
	"strings"

	"github.com/cockroachdb/errors"
)

const (
	schemeHTTPS      = "https"
	schemeHTTP       = "http"
	defaultPortHTTPS = "443"
	defaultPortHTTP  = "80"
	hexUpper         = "0123456789ABCDEF"
)

// requestURI returns the URI a proof for req is expected to name in htu. The
// scheme and host come from cfg.ExternalURL when it is set; otherwise from
// the request URL, then req.Host, with https assumed for an empty scheme
// (server-side requests behind a TLS-terminating proxy). Query and fragment
// are dropped.
func requestURI(cfg VerifyConfig, req *http.Request) (string, error) {
	u := req.URL
	scheme := cmp.Or(u.Scheme, schemeHTTPS)
	host := cmp.Or(u.Host, req.Host)
	if cfg.ExternalURL != "" {
		ext, err := parseExternalURL(cfg.ExternalURL)
		if err != nil {
			return "", err
		}
		scheme, host = ext.Scheme, ext.Host
	}
	coreURL := url.URL{
		Scheme:  scheme,
		Host:    host,
		Path:    u.Path,
		RawPath: u.RawPath,
	}
	return coreURL.String(), nil
}

// parseExternalURL validates VerifyConfig.ExternalURL: an absolute http or
// https origin without a path, query or fragment.
func parseExternalURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.Wrapf(err, "dpop: invalid ExternalURL %q", s)
	}
	if u.Host == "" || u.User != nil ||
		(u.Scheme != schemeHTTPS && u.Scheme != schemeHTTP) ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.Errorf("dpop: invalid ExternalURL %q: expected scheme://host[:port]", s)
	}
	return u, nil
}

// normalizeHTU returns the comparison form of an htu value or request URI
// (RFC 9449 §4.3 with RFC 3986 §6.2.2 and §6.2.3 normalization): scheme and
// host lowercased, the scheme's default port removed, percent-encoding
// normalized, and an empty path replaced by "/". Path case and dot segments
// are preserved; query and fragment are ignored.
func normalizeHTU(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", errors.Wrapf(err, "invalid URI %q", s)
	}
	if u.Scheme == "" || u.Host == "" || u.Opaque != "" || u.User != nil {
		return "", errors.Errorf("invalid URI %q", s)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch port := u.Port(); {
	case port == "" && strings.HasSuffix(host, ":"):
		host = strings.TrimSuffix(host, ":")
	case scheme == schemeHTTPS && port == defaultPortHTTPS,
		scheme == schemeHTTP && port == defaultPortHTTP:
		host = strings.TrimSuffix(host, ":"+port)
	}

	// dot segments are kept: a router that does not clean paths may
	// dispatch /admin/../public differently from /public
	path := normalizePercentEncoding(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// normalizePercentEncoding decodes percent-encoded unreserved characters and
// uppercases the hex digits of the remaining escapes. The input is an escaped
// path as produced by url.URL.EscapedPath, so every '%' starts a valid escape.
func normalizePercentEncoding(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+2 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		c := unhex(s[i+1])<<4 | unhex(s[i+2])
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexUpper[c>>4])
			b.WriteByte(hexUpper[c&0x0f])
		}
		i += 2
	}
	return b.String()
}

// isUnreserved reports whether c is an RFC 3986 unreserved character.
func isUnreserved(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return c == '-' || c == '.' || c == '_' || c == '~'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
