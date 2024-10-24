package jwt

import (
	"context"
	"crypto"
	"strconv"
	"strings"
	"time"

	"github.com/effective-security/x/configloader"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "jwt")

const (
	// DefaultNotBefore offset for NotBefore
	DefaultNotBefore = -2 * time.Minute
)

// Signer specifies JWT signer interface
type Signer interface {
	// SignClaims returns signed JWT token
	Sign(ctx context.Context, claims MapClaims) (string, error)
	// PublicKey is returned for assymetric signer
	PublicKey() crypto.PublicKey
	// Issuer returns name of the issuer
	Issuer() string
	// TokenExpiry specifies token expiration period
	TokenExpiry() time.Duration
}

// Parser specifies JWT parser interface
type Parser interface {
	// ParseToken returns jwt.StandardClaims
	ParseToken(ctx context.Context, token string, cfg *VerifyConfig) (MapClaims, error)

	GetRevocation() Revocation
	SetRevocation(Revocation)
}

type Revocation interface {
	// Validate validates token claims,
	// it can be used to validate token revocation, etc.
	Validate(ctx context.Context, token string, claims MapClaims) error
	// Revoke revokes token
	Revoke(ctx context.Context, token string, claims MapClaims) error
}

// Provider specifies JWT provider interface
type Provider interface {
	Signer
	Parser
}

// Key for JWT signature
type Key struct {
	// ID of the key
	ID   string `json:"id" yaml:"id"`
	Seed string `json:"seed" yaml:"seed"`
}

// ProviderConfig provides OAuth2 configuration
type ProviderConfig struct {
	// Issuer specifies issuer claim
	Issuer string `json:"issuer" yaml:"issuer"`
	// KeyID specifies ID of the current key
	KeyID string `json:"kid" yaml:"kid"`
	// Keys specifies list of issuer's keys
	Keys []*Key `json:"keys" yaml:"keys"`

	PrivateKey string `json:"private_key" yaml:"private_key"`

	// TokenExpiry specifies token expiration period
	TokenExpiry csr.Duration `json:"token_expiry" yaml:"token_expiry"`
}

// WithHeaders allows to specify extra headers or override defaults
func WithHeaders(headers map[string]any) Option {
	return optionFunc(func(c *provider) {
		for k, v := range headers {
			c.headers[k] = v
		}
	})
}

// provider for JWT
type provider struct {
	issuer      string
	tokenExpiry time.Duration
	kid         string
	keys        map[string][]byte
	signerInfo  *SignerInfo
	verifyKey   crypto.PublicKey
	headers     map[string]any
	parser      TokenParser
	revocation  Revocation
}

// LoadProviderConfig returns provider configuration loaded from a file
func LoadProviderConfig(file string) (*ProviderConfig, error) {
	if file == "" {
		return &ProviderConfig{}, nil
	}

	var config ProviderConfig
	err := configloader.UnmarshalAndExpand(file, &config)
	if err != nil {
		return nil, err
	}

	if config.PrivateKey == "" {
		if config.KeyID == "" {
			return nil, errors.Errorf("missing kid: %q", file)
		}
		if len(config.Keys) == 0 {
			return nil, errors.Errorf("missing keys: %q", file)
		}
	}
	return &config, nil
}

// LoadProvider returns new provider
func LoadProvider(cfgfile string, crypto *cryptoprov.Crypto) (Provider, error) {
	cfg, err := LoadProviderConfig(cfgfile)
	if err != nil {
		return nil, err
	}
	return NewProvider(cfg, crypto)
}

// MustNewProvider returns new provider
func MustNewProvider(cfg *ProviderConfig, crypto *cryptoprov.Crypto, ops ...Option) Provider {
	p, err := NewProvider(cfg, crypto, ops...)
	if err != nil {
		logger.Panicf("unable to create provider: %+v", err)
	}
	return p
}

// NewProvider returns new provider that supports, both Signer and Parser
func NewProvider(cfg *ProviderConfig, crypto *cryptoprov.Crypto, ops ...Option) (Provider, error) {
	p := &provider{
		issuer:      cfg.Issuer,
		kid:         cfg.KeyID,
		tokenExpiry: time.Duration(cfg.TokenExpiry),
		keys:        map[string][]byte{},
		parser: TokenParser{
			UseJSONNumber: true,
		},
	}

	if p.issuer == "" {
		return nil, errors.Errorf("issuer not configured")
	}
	if p.tokenExpiry == 0 {
		p.tokenExpiry = 60 * time.Minute
	}

	if cfg.PrivateKey != "" {
		if crypto == nil {
			return nil, errors.Errorf("Crypto provider not provided to load private key")
		}
		signer, err := crypto.NewSignerFromPEM([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, errors.Wrap(err, "failed to load private key")
		}
		p.signerInfo, err = NewSignerInfo(signer)
		if err != nil {
			return nil, err
		}
		p.verifyKey = signer.Public()
		p.headers = map[string]any{
			"jwk": &jose.JSONWebKey{
				Key: p.verifyKey,
			},
		}
	} else {
		if len(cfg.Keys) == 0 {
			return nil, errors.Errorf("keys not provided")
		}

		for _, key := range cfg.Keys {
			seed, err := configloader.ResolveValue(key.Seed)
			if err != nil {
				return nil, errors.Wrap(err, "failed to load seed")
			}
			p.keys[key.ID] = certutil.SHA256([]byte(seed))
		}

		if p.kid == "" {
			p.kid = cfg.Keys[len(cfg.Keys)-1].ID
		}

		kid, key := p.currentKey()
		p.headers = map[string]any{
			"kid": kid,
		}

		si, err := newSymmetricSigner("HS256", key)
		if err != nil {
			return nil, err
		}
		p.signerInfo, err = NewSignerInfo(si)
		if err != nil {
			return nil, err
		}
	}

	for _, opt := range ops {
		opt.applyOption(p)
	}
	return p, nil
}

// NewProviderFromCryptoSigner returns new from Signer
func NewProviderFromCryptoSigner(signer crypto.Signer, ops ...Option) (Provider, error) {
	p := &provider{
		parser: TokenParser{
			UseJSONNumber: true,
		},
	}
	var err error
	p.signerInfo, err = NewSignerInfo(signer)
	if err != nil {
		return nil, err
	}
	p.verifyKey = signer.Public()
	p.headers = map[string]any{
		"jwk": &jose.JSONWebKey{
			Key: p.verifyKey,
		},
	}
	for _, opt := range ops {
		opt.applyOption(p)
	}
	return p, nil
}

// NewProviderWithSymmetricKey returns new from Signer
func NewProviderWithSymmetricKey(key []byte, ops ...Option) (Provider, error) {
	p := &provider{
		parser: TokenParser{
			UseJSONNumber: true,
		},
	}
	signer, err := newSymmetricSigner("HS256", key)
	if err != nil {
		return nil, err
	}
	p.signerInfo, err = NewSignerInfo(signer)
	if err != nil {
		return nil, err
	}
	for _, opt := range ops {
		opt.applyOption(p)
	}
	return p, nil
}

func (p *provider) SetRevocation(r Revocation) {
	p.revocation = r
}

func (p *provider) GetRevocation() Revocation {
	return p.revocation
}

// PublicKey is returned for assymetric signer
func (p *provider) PublicKey() crypto.PublicKey {
	return p.verifyKey
}

// Issuer returns issuer name
func (p *provider) Issuer() string {
	return p.issuer
}

// TokenExpiry specifies token expiration period
func (p *provider) TokenExpiry() time.Duration {
	return p.tokenExpiry
}

// CurrentKey returns the key currently being used to sign tokens.
func (p *provider) currentKey() (string, []byte) {
	if key, ok := p.keys[p.kid]; ok {
		return p.kid, key
	}
	return "", nil
}

// Sign returns signed JWT token
func (p *provider) Sign(ctx context.Context, claims MapClaims) (string, error) {
	if p.signerInfo == nil {
		return "", errors.Errorf("signer not configured")
	}
	tokenString, err := p.signerInfo.signJWT(claims, p.headers)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// ParseToken returns MapClaims
func (p *provider) ParseToken(ctx context.Context, authorization string, cfg *VerifyConfig) (MapClaims, error) {
	claims := MapClaims{}
	token, err := p.parser.ParseWithClaims(authorization, cfg, claims, func(token *Token) (any, error) {
		logger.KV(xlog.DEBUG,
			"headers", token.Header,
			"claims", token.Claims,
		)
		if strings.HasPrefix(token.SigningMethod, "HS") {
			if kid, ok := token.Header["kid"]; ok {
				var id string
				switch t := kid.(type) {
				case string:
					id = t
				case int:
					id = strconv.Itoa(t)
				}

				if key, ok := p.keys[id]; ok {
					return key, nil
				}
				return nil, errors.Errorf("unexpected kid")
			}
			return nil, errors.Errorf("missing kid")
		}
		if p.signerInfo == nil {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.verifyKey, nil
	})
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to verify token")
	}

	if claims, ok := token.Claims.(MapClaims); ok && token.Valid {
		if p.revocation != nil {
			if err := p.revocation.Validate(ctx, authorization, claims); err != nil {
				return nil, errors.WithMessagef(err, "invalid token")
			}
		}
		return claims, nil
	}

	return nil, errors.Errorf("invalid token")
}

// A Option modifies the default behavior of Provider.
type Option interface {
	applyOption(*provider)
}

type optionFunc func(*provider)

func (f optionFunc) applyOption(opts *provider) { f(opts) }
