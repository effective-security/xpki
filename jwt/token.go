package jwt

import "encoding/base64"

// ValidClaims interface for Claims validation
type ValidClaims interface {
	Valid(cfg *VerifyConfig) error
}

// VerifyConfig expreses the possible options for validating a JWT
type VerifyConfig struct {
	// ExpectedIssuer validates the iss claim of a JWT matches this value
	ExpectedIssuer string
	// ExpectedSubject validates the sub claim of a JWT matches this value
	ExpectedSubject string
	// ExpectedAudience validates that the aud claim of a JWT contains this value
	ExpectedAudience []string
	// ExpectedNonce validates that the nonce claim of a JWT contains this value
	//ExpectedNonce string
}

// Token for JWT
type Token struct {
	Raw           string         // The raw token.  Populated when you Parse a token
	SigningMethod string         // The signing method used or to be used
	Header        map[string]any // The first segment of the token
	Claims        ValidClaims    // The second segment of the token
	Signature     string         // The third segment of the token.  Populated when you Parse a token
	Valid         bool           // Is the token valid?  Populated when you Parse/Verify a token
}

// DecodeSegment JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

// EncodeSegment returns JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}
