package dpop

import (
	"crypto"
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	hjwt "gopkg.in/square/go-jose.v2/jwt"
)

type signer struct {
	prov jwt.Provider
	tp   string
}

// NewSigner creates a DPoP signer that can generate DPoP headers for a request.
func NewSigner(s crypto.Signer) (Signer, error) {
	ops := jwt.WithHeaders(map[string]interface{}{
		"typ": jwtHeaderTypeDPOP,
	})
	prov, err := jwt.NewFromCryptoSigner(s, ops)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	jk := jose.JSONWebKey{
		Key: s.Public(),
	}
	tb, err := jk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &signer{
		prov: prov,
		tp:   base64.RawURLEncoding.EncodeToString(tb),
	}, nil
}

// JWKThumbprint returns base64 hash of the key
func (p *signer) JWKThumbprint() string {
	return p.tp
}

func (p *signer) ForRequest(r *http.Request, extraClaims interface{}) (string, error) {
	now := TimeNowFn()
	notBefore := now.Add(DefaultNotBefore)
	exp := now.Add(DefaultExpiration)
	claims := &hjwt.Claims{
		ID:        certutil.RandomString(8),
		NotBefore: hjwt.NewNumericDate(notBefore),
		Expiry:    hjwt.NewNumericDate(exp),
		IssuedAt:  hjwt.NewNumericDate(now),
	}

	coreURL := url.URL{
		Scheme: r.URL.Scheme,
		Opaque: r.URL.Opaque,
		Host:   r.URL.Host,
		Path:   r.URL.Path,
	}

	c := jwt.Claims{
		claimNameForHTTPMethod: r.Method,
		claimNameForHTTPURL:    coreURL.String(),
	}
	err := c.Add(claims, extraClaims)
	if err != nil {
		return "", errors.WithStack(err)
	}

	token, _, err := p.prov.SignToken(
		certutil.RandomString(8),
		"",
		nil,
		DefaultExpiration,
		c,
	)
	if err != nil {
		return "", errors.WithStack(err)
	}

	r.Header.Set(HTTPHeader, token)
	return token, nil
}
