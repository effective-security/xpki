package jwt

import (
	"crypto"
	"encoding/json"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/x/fileutil"
	"github.com/effective-security/xpki/x/slices"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"gopkg.in/yaml.v2"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "jwt")

const (
	// DefaultNotBefore offset for NotBefore
	DefaultNotBefore = -2 * time.Minute
)

// VerifyConfig expreses the possible options for validating a JWT
type VerifyConfig struct {
	// ExpectedSubject validates the sub claim of a JWT matches this value
	ExpectedSubject string
	// ExpectedAudience validates that the aud claim of a JWT contains this value
	ExpectedAudience string
}

// Signer specifies JWT signer interface
type Signer interface {
	// SignToken returns signed JWT token
	SignToken(id, subject string, audience []string, expiry time.Duration, extraClaims Claims) (string, Claims, error)
	// PublicKey is returned for assymetric signer
	PublicKey() crypto.PublicKey
}

// Parser specifies JWT parser interface
type Parser interface {
	// ParseToken returns jwt.StandardClaims
	ParseToken(authorization string, cfg *VerifyConfig) (Claims, error)
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

// Config provides OAuth2 configuration
type Config struct {
	// Issuer specifies issuer claim
	Issuer string `json:"issuer" yaml:"issuer"`
	// KeyID specifies ID of the current key
	KeyID string `json:"kid" yaml:"kid"`
	// Keys specifies list of issuer's keys
	Keys []*Key `json:"keys" yaml:"keys"`

	PrivateKey string `json:"private_key" yaml:"private_key"`
}

// WithHeaders allows to specify extra headers or override defaults
func WithHeaders(headers map[string]interface{}) Option {
	return optionFunc(func(c *provider) {
		for k, v := range headers {
			c.headers[k] = v
		}
	})
}

// provider for JWT
type provider struct {
	issuer     string
	kid        string
	keys       map[string][]byte
	signerInfo *SignerInfo
	verifyKey  crypto.PublicKey
	headers    map[string]interface{}
	parser     TokenParser
}

// LoadConfig returns configuration loaded from a file
func LoadConfig(file string) (*Config, error) {
	if file == "" {
		return &Config{}, nil
	}

	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var config Config
	if strings.HasSuffix(file, ".json") {
		err = json.Unmarshal(raw, &config)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to unmarshal JSON: %q", file)
		}
	} else {
		err = yaml.Unmarshal(raw, &config)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to unmarshal YAML: %q", file)
		}
	}

	if config.PrivateKey != "" {
		config.PrivateKey, err = fileutil.LoadConfigWithSchema(config.PrivateKey)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to resole private key")
		}
	} else {
		if config.KeyID == "" {
			return nil, errors.Errorf("missing kid: %q", file)
		}
		if len(config.Keys) == 0 {
			return nil, errors.Errorf("missing keys: %q", file)
		}
	}
	return &config, nil
}

// Load returns new provider
func Load(cfgfile string, crypto *cryptoprov.Crypto) (Provider, error) {
	cfg, err := LoadConfig(cfgfile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return New(cfg, crypto)
}

// MustNew returns new provider
func MustNew(cfg *Config, crypto *cryptoprov.Crypto, ops ...Option) Provider {
	p, err := New(cfg, crypto, ops...)
	if err != nil {
		logger.Panicf("unable to create provider: %+v", err)
	}
	return p
}

// New returns new provider that supports, both Signer and Parser
func New(cfg *Config, crypto *cryptoprov.Crypto, ops ...Option) (Provider, error) {
	p := &provider{
		issuer: cfg.Issuer,
		kid:    cfg.KeyID,
		keys:   map[string][]byte{},
		parser: TokenParser{
			UseJSONNumber: true,
		},
	}

	if p.issuer == "" {
		return nil, errors.Errorf("issuer not configured")
	}

	if cfg.PrivateKey != "" {
		if crypto == nil {
			return nil, errors.Errorf("Crypto provider not provided to load private key")
		}
		signer, err := crypto.NewSignerFromPEM([]byte(cfg.PrivateKey))
		if err != nil {
			return nil, errors.Errorf("failed to load private key: " + err.Error())
		}
		p.signerInfo, err = NewSignerInfo(signer)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		p.verifyKey = signer.Public()
		p.headers = map[string]interface{}{
			"jwk": &jose.JSONWebKey{
				Key: p.verifyKey,
			},
		}
	} else {
		if len(cfg.Keys) == 0 {
			return nil, errors.Errorf("keys not provided")
		}

		for _, key := range cfg.Keys {
			seed, err := fileutil.LoadConfigWithSchema(key.Seed)
			if err != nil {
				return nil, errors.Errorf("failed to load seed: " + err.Error())
			}
			p.keys[key.ID] = certutil.SHA256([]byte(seed))
		}

		if p.kid == "" {
			p.kid = cfg.Keys[len(cfg.Keys)-1].ID
		}

		kid, key := p.currentKey()
		p.headers = map[string]interface{}{
			"kid": kid,
		}

		si, err := newSymmetricSigner("HS256", key)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		p.signerInfo, err = NewSignerInfo(si)
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}

	for _, opt := range ops {
		opt.applyOption(p)
	}
	return p, nil
}

// NewFromCryptoSigner returns new from Signer
func NewFromCryptoSigner(signer crypto.Signer, ops ...Option) (Provider, error) {
	p := &provider{
		parser: TokenParser{
			UseJSONNumber: true,
		},
	}
	var err error
	p.signerInfo, err = NewSignerInfo(signer)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	p.verifyKey = signer.Public()
	p.headers = map[string]interface{}{
		"jwk": &jose.JSONWebKey{
			Key: p.verifyKey,
		},
	}
	for _, opt := range ops {
		opt.applyOption(p)
	}
	return p, nil
}

// PublicKey is returned for assymetric signer
func (p *provider) PublicKey() crypto.PublicKey {
	return p.verifyKey
}

// CurrentKey returns the key currently being used to sign tokens.
func (p *provider) currentKey() (string, []byte) {
	if key, ok := p.keys[p.kid]; ok {
		return p.kid, key
	}
	return "", nil
}

// SignToken returns signed JWT token with custom claims
func (p *provider) SignToken(jti, subject string, audience []string, expiry time.Duration, extraClaims Claims) (string, Claims, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)
	notBefore := now.Add(DefaultNotBefore)

	claims := &jwt.Claims{
		ID:        jti,
		Expiry:    jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(notBefore),
		Issuer:    p.issuer,
		Audience:  audience,
		Subject:   subject,
	}
	c := Claims{}
	c.Add(claims, extraClaims)

	tokenString, err := p.signerInfo.signJWT(c, p.headers)
	if err != nil {
		return "", nil, errors.WithStack(err)
	}
	return tokenString, c, nil
}

// ParseToken returns jwt.StandardClaims
func (p *provider) ParseToken(authorization string, cfg *VerifyConfig) (Claims, error) {
	claims := Claims{}
	token, err := p.parser.ParseWithClaims(authorization, claims, func(token *Token) (interface{}, error) {
		logger.KV(xlog.TRACE, "alg", token.Header["alg"])
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
		return nil, errors.WithMessagef(err, "failed to verify token")
	}

	if claims, ok := token.Claims.(Claims); ok && token.Valid {
		var std jwt.Claims
		err = Claims(claims).To(&std)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to parse claims")
		}

		if std.Issuer != p.issuer {
			return nil, errors.Errorf("invalid issuer: %s", std.Issuer)
		}
		if cfg.ExpectedSubject != "" && std.Subject != cfg.ExpectedSubject {
			return nil, errors.Errorf("invalid subject: %s", std.Subject)
		}

		if cfg.ExpectedAudience != "" && !slices.ContainsString(std.Audience, cfg.ExpectedAudience) {
			return nil, errors.Errorf("invalid audience: %s", std.Audience)
		}
		return Claims(claims), nil
	}

	return nil, errors.Errorf("invalid token")
}

// A Option modifies the default behavior of Provider.
type Option interface {
	applyOption(*provider)
}

type optionFunc func(*provider)

func (f optionFunc) applyOption(opts *provider) { f(opts) }
