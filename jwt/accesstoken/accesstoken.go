package accesstoken

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
)

// Provider of Access Token
type Provider struct {
	jwt.Provider

	dp         dataprotection.Provider
	revocation jwt.Revocation
}

// New returns new Provider
func New(dp dataprotection.Provider, provider jwt.Provider) jwt.Provider {
	return &Provider{
		dp:       dp,
		Provider: provider,
	}
}

func (p *Provider) SetRevocation(r jwt.Revocation) {
	p.revocation = r
}

func (p *Provider) GetRevocation() jwt.Revocation {
	return p.revocation
}

// Sign returns AccessToken from claims
func (p *Provider) Sign(ctx context.Context, claims jwt.MapClaims) (string, error) {
	js, err := json.Marshal(claims)
	if err != nil {
		return "", errors.WithStack(err)
	}

	protected, err := p.dp.Protect(ctx, js)
	if err != nil {
		return "", err
	}
	return "pat." + base64.RawURLEncoding.EncodeToString(protected), nil
}

// Claims returns claims from the Access Token,
// or nil if `auth` is not Access Token
func (p *Provider) ParseToken(ctx context.Context, token string, cfg *jwt.VerifyConfig) (jwt.MapClaims, error) {
	if !strings.HasPrefix(token, "pat.") {
		if p.Provider == nil {
			// not supported
			return nil, errors.Errorf("token not supported")
		}
		cl, err := p.Provider.ParseToken(ctx, token, cfg)
		if err != nil {
			return nil, err
		}
		return cl, nil
	}

	protected, err := base64.RawURLEncoding.DecodeString(token[4:])
	if err != nil {
		return nil, errors.WithStack(err)
	}
	js, err := p.dp.Unprotect(ctx, protected)
	if err != nil {
		return nil, errors.Errorf("failed to decrypt token")
	}

	d := json.NewDecoder(bytes.NewReader(js))
	d.UseNumber()
	claims := jwt.MapClaims{}
	if err := d.Decode(&claims); err != nil {
		return nil, errors.WithStack(err)
	}

	err = claims.Valid(cfg)
	if err != nil {
		return nil, err
	}

	if p.revocation != nil {
		if err := p.revocation.Validate(ctx, token, claims); err != nil {
			return nil, errors.WithMessagef(err, "invalid token")
		}
	}

	return claims, nil
}

// PublicKey is returned for assymetric signer
func (p *Provider) PublicKey() crypto.PublicKey {
	return p.dp.PublicKey()
}

// Issuer returns name of the issuer
func (p *Provider) Issuer() string {
	if p.Provider == nil {
		// not supported
		return ""
	}
	return p.Provider.Issuer()
}

// TokenExpiry specifies token expiration period
func (p *Provider) TokenExpiry() time.Duration {
	if p.Provider == nil {
		// not supported
		return 0
	}
	return p.Provider.TokenExpiry()
}
