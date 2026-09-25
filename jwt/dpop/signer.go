package dpop

import (
	"context"
	"crypto"
	"net/http"
	"net/url"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/jwt"
	"github.com/go-jose/go-jose/v4"
	hjwt "github.com/go-jose/go-jose/v4/jwt"
)

// proofIDLength is the jti length: about 131 bits from the 62-character
// alphabet of certutil.RandomString; RFC 9449 §4.2 asks for at least 96 bits
// of pseudorandom data so that replay caches do not see collisions.
const proofIDLength = 22

type signer struct {
	prov jwt.Provider
	tp   string
}

// NewSigner creates a DPoP signer that can generate DPoP headers for a request.
func NewSigner(s crypto.Signer) (Signer, error) {
	ops := jwt.WithHeaders(map[string]any{
		"typ": jwtHeaderTypeDPOP,
	})
	prov, err := jwt.NewProviderFromCryptoSigner(s, ops)
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

// ForRequest creates a DPoP proof for the request method and URL and sets it
// as the DPoP header; the proof is also returned.
func ForRequest(p Signer, r *http.Request, extraClaims any) (string, error) {
	token, err := p.Sign(r.Context(), r.Method, r.URL, extraClaims)
	if err != nil {
		return "", err
	}

	r.Header.Set(HTTPHeader, token)
	return token, nil
}

// Sign returns DPoP token
func (p *signer) Sign(ctx context.Context, method string, u *url.URL, extraClaims any) (string, error) {
	now := TimeNowFn()
	notBefore := now.Add(DefaultNotBefore)
	exp := now.Add(DefaultExpiration)
	jti := certutil.RandomString(proofIDLength)
	claims := &hjwt.Claims{
		ID:        jti,
		NotBefore: hjwt.NewNumericDate(notBefore),
		Expiry:    hjwt.NewNumericDate(exp),
		IssuedAt:  hjwt.NewNumericDate(now),
	}

	// RawPath keeps escapes such as %2F that the decoded Path loses
	coreURL := url.URL{
		Scheme:  u.Scheme,
		Host:    u.Host,
		Path:    u.Path,
		RawPath: u.RawPath,
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
		jti,
		"",
		p.prov.Issuer(),
		nil,
		DefaultExpiration,
		c,
	)
	token, err := p.prov.Sign(ctx, std)
	if err != nil {
		return "", err
	}

	return token, nil
}
