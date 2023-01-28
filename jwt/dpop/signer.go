package dpop

import (
	"crypto"
	"net/http"
	"net/url"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt"
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
		return nil, err
	}

	jk := jose.JSONWebKey{
		Key: s.Public(),
	}
	tp, err := Thumbprint(&jk)
	if err != nil {
		return nil, err
	}

	return &signer{
		prov: prov,
		tp:   tp,
	}, nil
}

// JWKThumbprint returns base64 hash of the key
func (p *signer) JWKThumbprint() string {
	return p.tp
}

func ForRequest(p Signer, r *http.Request, extraClaims interface{}) (string, error) {
	token, err := p.Sign(r.Method, r.URL, extraClaims)
	if err != nil {
		return "", err
	}

	r.Header.Set(HTTPHeader, token)
	return token, nil
}

// Sign returns DPoP token
func (p *signer) Sign(method string, u *url.URL, extraClaims interface{}) (string, error) {
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
		Scheme: u.Scheme,
		Host:   u.Host,
		Path:   u.Path,
	}

	c := jwt.MapClaims{
		claimNameForHTTPMethod: method,
		claimNameForHTTPURL:    coreURL.String(),
	}
	err := c.Add(claims, extraClaims)
	if err != nil {
		return "", err
	}

	std := jwt.CreateClaims(
		certutil.RandomString(8),
		"",
		p.prov.Issuer(),
		nil,
		DefaultExpiration,
		c,
	)
	token, err := p.prov.Sign(std)
	if err != nil {
		return "", err
	}

	return token, nil
}
