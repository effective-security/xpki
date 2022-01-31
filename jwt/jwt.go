package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/x/fileutil"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "jwt")

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
	SignToken(id, subject, audience string, expiry time.Duration) (string, Claims, error)
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

// provider for JWT
type provider struct {
	issuer        string
	kid           string
	keys          map[string][]byte
	signingMethod jwt.SigningMethod
	signer        crypto.Signer
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
func MustNew(cfg *Config, crypto *cryptoprov.Crypto) Provider {
	p, err := New(cfg, crypto)
	if err != nil {
		logger.Panicf("unable to create provider: %+v", err)
	}
	return p
}

// New returns new provider
func New(cfg *Config, crypto *cryptoprov.Crypto) (Provider, error) {
	p := &provider{
		issuer: cfg.Issuer,
		kid:    cfg.KeyID,
		keys:   map[string][]byte{},
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
		p.signer = signer
		p.signingMethod, err = getSigningMethod(signer.Public())
		if err != nil {
			return nil, errors.WithStack(err)
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
		p.signingMethod = jwt.SigningMethodHS256
	}
	return p, nil
}

// CurrentKey returns the key currently being used to sign tokens.
func (p *provider) currentKey() (string, []byte) {
	if key, ok := p.keys[p.kid]; ok {
		return p.kid, key
	}
	return "", nil
}

// SignToken returns signed JWT token with custom claims
func (p *provider) SignToken(id, subject, audience string, expiry time.Duration) (string, Claims, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)
	claims := &jwt.StandardClaims{
		Id:        id,
		ExpiresAt: expiresAt.Unix(),
		Issuer:    p.issuer,
		IssuedAt:  now.Unix(),
		Audience:  audience,
		Subject:   subject,
	}

	var key interface{}

	token := jwt.NewWithClaims(p.signingMethod, claims)
	if p.signer != nil {
		key = p.signer
	} else {
		var kid string
		kid, key = p.currentKey()
		token.Header["kid"] = kid
	}

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", nil, errors.WithMessagef(err, "failed to sign token")
	}

	c := Claims{}
	c.Add(claims)
	return tokenString, c, nil
}

func getSigningMethod(pub crypto.PublicKey) (jwt.SigningMethod, error) {
	switch typ := pub.(type) {
	case *rsa.PublicKey:
		keySize := typ.N.BitLen()
		switch {
		case keySize >= 4096:
			return jwt.SigningMethodRS512, nil
		case keySize >= 3072:
			return jwt.SigningMethodRS384, nil
		default:
			return jwt.SigningMethodRS256, nil
		}
	case *ecdsa.PublicKey:
		switch typ.Curve {
		case elliptic.P521():
			return jwt.SigningMethodES512, nil
		case elliptic.P384():
			return jwt.SigningMethodES384, nil
		default:
			return jwt.SigningMethodES256, nil
		}
	default:
		return nil, errors.Errorf("public key not supported: %T", typ)
	}
}

// ParseToken returns jwt.StandardClaims
func (p *provider) ParseToken(authorization string, cfg *VerifyConfig) (Claims, error) {
	claims := jwt.MapClaims{}

	parser := new(jwt.Parser)
	parser.UseJSONNumber = true
	token, err := parser.ParseWithClaims(authorization, claims, func(token *jwt.Token) (interface{}, error) {
		logger.KV(xlog.TRACE, "alg", token.Header["alg"])

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
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
		if p.signer == nil {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.signer.Public(), nil
	})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to verify token")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var std jwt.StandardClaims
		Claims(claims).To(&std)

		if std.Issuer != p.issuer {
			return nil, errors.Errorf("invalid issuer: %s", std.Issuer)
		}
		if cfg.ExpectedAudience != "" && std.Audience != cfg.ExpectedAudience {
			return nil, errors.Errorf("invalid audience: %s", std.Audience)
		}
		if cfg.ExpectedSubject != "" && std.Subject != cfg.ExpectedSubject {
			return nil, errors.Errorf("invalid subject: %s", std.Subject)
		}

		return Claims(claims), nil
	}

	return nil, errors.Errorf("invalid token")
}
