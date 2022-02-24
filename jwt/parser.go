package jwt

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/pkg/errors"
)

// Keyfunc is a callback function to supply the key for verification.
// The function receives the parsed, but unverified Token.
// This allows you to use properties in the Header of the token (such as `kid`)
// to identify which key to use.
type Keyfunc func(*Token) (interface{}, error)

// TokenParser config
type TokenParser struct {
	ValidMethods         []string // If populated, only these methods will be considered valid
	UseJSONNumber        bool     // Use JSON Number format in JSON decoder
	SkipClaimsValidation bool     // Skip claims validation during token parsing
}

// Parse parses and validates JWT, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
// If everything is kosher, err will be nil
func (p *TokenParser) Parse(tokenString string, keyFunc Keyfunc) (*Token, error) {
	return p.ParseWithClaims(tokenString, Claims{}, keyFunc)
}

// ParseWithClaims parses token with a specified Claims
func (p *TokenParser) ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error) {
	token, parts, err := p.ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, errors.WithStack(err)
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
	var key interface{}
	if key, err = keyFunc(token); err != nil {
		return nil, errors.WithStack(err)
	}

	// Validate Claims
	if !p.SkipClaimsValidation {
		if err := token.Claims.Valid(); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	// Perform signature validation
	token.Signature = parts[2]
	if err = VerifySignature(token.SigningMethod, strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		return nil, errors.WithStack(err)
	}

	token.Valid = true
	return token, nil
}

// ParseUnverified parses the token but doesn't validate the signature. It's only
// ever useful in cases where you know the signature is valid (because it has
// been checked previously in the stack) and you want to extract values from
// it.
// WARNING: Don't use this method unless you know what you're doing
func (p *TokenParser) ParseUnverified(tokenString string, claims Claims) (token *Token, parts []string, err error) {
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
	if c, ok := token.Claims.(Claims); ok {
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
