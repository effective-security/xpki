package accesstoken

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"maps"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
)

const (
	// TokenPrefix is the prefix of the opaque access tokens issued by Sign
	TokenPrefix = "pat."

	claimExp = "exp"
	claimIat = "iat"
	claimNbf = "nbf"
)

// timeClaims are the registered claims Sign normalizes to NumericDate
var timeClaims = []string{claimExp, claimIat, claimNbf}

// Provider of Access Token
type Provider struct {
	jwt.Provider

	dp            dataprotection.Provider
	revocation    jwt.Revocation
	tokenExpiry   time.Duration
	allowNoExpiry bool
}

// Option configures a Provider.
type Option func(*Provider)

// WithTokenExpiry sets the lifetime Sign gives a token whose claims have no
// exp. It takes precedence over the inner provider's TokenExpiry. Zero keeps
// the inner provider's value; a negative value makes Sign fail.
func WithTokenExpiry(d time.Duration) Option {
	return func(p *Provider) {
		p.tokenExpiry = d
	}
}

// WithAllowNoExpiry makes ParseToken accept pat. tokens without an exp
// claim, such as tokens issued before Sign added one (XPKI-078). Use it only
// to migrate existing perpetual tokens; revocation is still checked.
func WithAllowNoExpiry() Option {
	return func(p *Provider) {
		p.allowNoExpiry = true
	}
}

// New returns a Provider that issues pat. tokens protected by dp and
// delegates other tokens to the optional inner provider. A nil dp is
// allowed, but then pat. tokens can be neither issued nor parsed.
func New(dp dataprotection.Provider, provider jwt.Provider, opts ...Option) jwt.Provider {
	p := &Provider{
		dp:       dp,
		Provider: provider,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// SetRevocation installs the revocation checker used for pat. tokens,
// and forwards it to the wrapped jwt.Provider so that plain JWTs are
// checked against the same revocation list.
func (p *Provider) SetRevocation(r jwt.Revocation) {
	p.revocation = r
	if p.Provider != nil {
		p.Provider.SetRevocation(r)
	}
}

// GetRevocation returns the revocation checker used for pat. tokens
func (p *Provider) GetRevocation() jwt.Revocation {
	return p.revocation
}

// Sign returns an encrypted pat. token for the claims. Caller-supplied exp,
// iat and nbf are kept and normalized to NumericDate; an unparsable one is an
// error. Without exp, the token expires after TokenExpiry, and iat and nbf
// are added when absent; Sign fails if TokenExpiry is not positive. The
// claims map is not modified.
func (p *Provider) Sign(ctx context.Context, claims jwt.MapClaims) (string, error) {
	if p.dp == nil {
		return "", errors.Errorf("data protection not configured")
	}

	cl := make(jwt.MapClaims, len(claims)+3)
	maps.Copy(cl, claims)

	// time claims are stored as NumericDate: other encodings, such as
	// time.Time, may not parse back and their checks would be skipped
	// (XPKI-109)
	for _, k := range timeClaims {
		if _, ok := cl[k]; !ok {
			continue
		}
		t := cl.Time(k)
		if t == nil {
			return "", errors.Errorf("invalid %s claim", k)
		}
		cl[k] = t.Unix()
	}

	if _, ok := cl[claimExp]; !ok {
		expiry := p.TokenExpiry()
		if expiry <= 0 {
			return "", errors.Errorf("token expiry not configured")
		}
		now := jwt.TimeNowFn().UTC()
		cl[claimExp] = now.Add(expiry).Unix()
		if _, ok := cl[claimIat]; !ok {
			cl[claimIat] = now.Unix()
		}
		if _, ok := cl[claimNbf]; !ok {
			cl[claimNbf] = now.Add(jwt.DefaultNotBefore).Unix()
		}
	}

	js, err := json.Marshal(cl)
	if err != nil {
		return "", errors.WithStack(err)
	}

	protected, err := p.dp.Protect(ctx, js)
	if err != nil {
		return "", err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(protected), nil
}

// ParseToken parses JWT Token with data protection. A pat. token must have an
// exp claim unless WithAllowNoExpiry is set; an unparsable exp is always
// rejected.
func (p *Provider) ParseToken(ctx context.Context, token string, cfg *jwt.VerifyConfig) (jwt.MapClaims, error) {
	if !strings.HasPrefix(token, TokenPrefix) {
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
	if p.dp == nil {
		return nil, errors.Errorf("data protection not configured")
	}

	protected, err := base64.RawURLEncoding.DecodeString(token[len(TokenPrefix):])
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

	if _, ok := claims[claimExp]; ok {
		if claims.Time(claimExp) == nil {
			return nil, errors.Errorf("invalid exp claim")
		}
	} else if !p.allowNoExpiry {
		return nil, errors.Errorf("exp claim not found")
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

// PublicKey returns the public key of an asymmetric data protection
// provider, or nil for a symmetric or nil one.
func (p *Provider) PublicKey() crypto.PublicKey {
	if p.dp == nil {
		return nil
	}
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

// TokenExpiry returns the lifetime Sign gives a token without exp: the
// WithTokenExpiry value if set, else the inner provider's TokenExpiry, else 0.
// A negative WithTokenExpiry value is reported as 0.
func (p *Provider) TokenExpiry() time.Duration {
	if p.tokenExpiry != 0 {
		return max(p.tokenExpiry, 0)
	}
	if p.Provider == nil {
		// not supported
		return 0
	}
	return p.Provider.TokenExpiry()
}
