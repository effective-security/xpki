package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/configloader"
	"github.com/effective-security/xlog"
	jose "github.com/go-jose/go-jose/v3"
)

// ParserConfig provides JWT parser configuration
type ParserConfig struct {
	// Issuer specifies issuer claim
	Issuer   string              `json:"issuer" yaml:"issuer"`
	JWKSURI  string              `json:"jwks_uri" yaml:"jwks_uri"`
	JWKeySet *jose.JSONWebKeySet `json:"jwks" yaml:"jwks"`
}

// Keyfunc is a callback function to supply the key for verification.
// The function receives the parsed, but unverified Token.
// This allows you to use properties in the Header of the token (such as `kid`)
// to identify which key to use.
type Keyfunc func(*Token) (any, error)

// TokenParser config
type TokenParser struct {
	ValidMethods         []string // If populated, only these methods will be considered valid
	UseJSONNumber        bool     // Use JSON Number format in JSON decoder
	SkipClaimsValidation bool     // Skip claims validation during token parsing
}

// Parse parses and validates JWT, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil
func (p *TokenParser) Parse(tokenString string, cfg *VerifyConfig, keyFunc Keyfunc) (*Token, error) {
	return p.ParseWithClaims(tokenString, cfg, MapClaims{}, keyFunc)
}

// ParseWithClaims parses token with a specified Claims
func (p *TokenParser) ParseWithClaims(tokenString string, cfg *VerifyConfig, claims MapClaims, keyFunc Keyfunc) (*Token, error) {
	token, parts, err := p.ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, err
	}

	// Verify signing method is in the required set
	if p.ValidMethods != nil {
		var signingMethodValid = false
		for _, m := range p.ValidMethods {
			if m == token.SigningMethod {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			// signing method is not in the listed set
			return nil, errors.Errorf("unsupported signing method: %s", token.SigningMethod)
		}
	}

	// Lookup key
	var key any
	if key, err = keyFunc(token); err != nil {
		return nil, err
	}

	// Validate Claims
	if !p.SkipClaimsValidation {
		if err := token.Claims.Valid(cfg); err != nil {
			return nil, err
		}
	}

	// Perform signature validation
	token.Signature = parts[2]
	if err = VerifySignature(token.SigningMethod, strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		return nil, err
	}

	token.Valid = true
	return token, nil
}

// ParseUnverified parses the token but doesn't validate the signature. It's only
// ever useful in cases where you know the signature is valid (because it has
// been checked previously in the stack) and you want to extract values from
// it.
// WARNING: Don't use this method unless you know what you're doing
func (p *TokenParser) ParseUnverified(tokenString string, claims MapClaims) (token *Token, parts []string, err error) {
	parts = strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, parts, errors.Errorf("malformed token")
	}

	token = &Token{
		Raw: tokenString,
	}

	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		return nil, nil, errors.WithMessage(err, "failed to decode token")
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return nil, nil, errors.WithMessage(err, "failed to unmarshal header")
	}

	// parse Claims
	var claimBytes []byte
	token.Claims = claims

	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return nil, nil, errors.WithMessage(err, "failed to decode token")
	}
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	if p.UseJSONNumber {
		dec.UseNumber()
	}
	// JSON Decode.  Special case for map type to avoid weird pointer behavior
	if c, ok := token.Claims.(MapClaims); ok {
		err = dec.Decode(&c)
	} else {
		err = dec.Decode(&claims)
	}
	// Handle decode error
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to decode token")
	}

	// Lookup signature method
	if method, ok := token.Header["alg"].(string); ok {
		token.SigningMethod = method
	} else {
		return nil, nil, errors.WithMessage(err, "invalid token: no alg specified")
	}

	return token, parts, nil
}

// parser for JWT
type parser struct {
	issuer     string
	parser     TokenParser
	verifier   KeySet
	revocation Revocation
}

// LoadParserConfig returns parser configuration loaded from a file
func LoadParserConfig(file string) (*ParserConfig, error) {
	if file == "" {
		return &ParserConfig{}, nil
	}

	var config ParserConfig
	err := configloader.UnmarshalAndExpand(file, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// NewParser returns Parser
func NewParser(cfg *ParserConfig) (Parser, error) {
	p := &parser{
		issuer: cfg.Issuer,
		parser: TokenParser{
			UseJSONNumber: true,
		},
	}

	if cfg.JWKeySet != nil {
		p.verifier = &StaticKeySet{KeySet: cfg.JWKeySet.Keys}
	} else if cfg.JWKSURI != "" {
		p.verifier = NewRemoteKeySet(context.Background(), cfg.JWKSURI)
	}
	return p, nil
}

func (p *parser) SetRevocation(r Revocation) {
	p.revocation = r
}

func (p *parser) GetRevocation() Revocation {
	return p.revocation
}

// ParseToken returns MapClaims
func (p *parser) ParseToken(ctx context.Context, authorization string, cfg *VerifyConfig) (MapClaims, error) {
	if p.verifier == nil {
		return nil, errors.Errorf("verifier not configured")
	}
	claims := MapClaims{}
	token, err := p.parser.ParseWithClaims(authorization, cfg, claims, func(token *Token) (any, error) {
		logger.KV(xlog.DEBUG,
			"headers", token.Header,
			"claims", token.Claims,
		)
		if strings.HasPrefix(token.SigningMethod, "HS") {
			return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		keyID := ""
		if kid, ok := token.Header["kid"]; ok {
			keyID = kid.(string)
		}

		return p.verifier.GetKey(ctx, keyID)
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
