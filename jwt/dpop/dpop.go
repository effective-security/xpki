package dpop

import (
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	// HTTPHeader header name for DPoP
	HTTPHeader = "DPoP"
	// ContentType value
	ContentType = "application/dpop+jwt"
)

const (
	// DefaultExpiration for the proof
	DefaultExpiration = time.Minute * 10
	// DefaultNotBefore offset for NotBefore
	DefaultNotBefore = -10 * time.Minute
)

// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-04
const (
	// CnfThumbprint is the claim name for JKT thumbptint
	CnfThumbprint          = "jkt"
	claimNameForHTTPMethod = "htm"
	claimNameForHTTPURL    = "htu"
	// 10.2.  JSON Web Signature and Encryption Type Values Registration
	jwtHeaderTypeDPOP = `dpop+jwt`
)

// Signer specifies an interface to sign HTTP requests with DPoP
type Signer interface {
	// ForRequest annotates an HTTP Request with a DPoP header.
	ForRequest(r *http.Request, extraClaims interface{}) (string, error)
	// JWKThumbprint returns base64 hash of the key
	JWKThumbprint() string
}

// Claims are common claims in the DPoP proof JWT.
type Claims struct {
	jwt.Claims
	Nonce      string `json:"nonce,omitempty"`
	HTTPMethod string `json:"htm,omitempty"`
	HTTPUri    string `json:"htu,omitempty"`
}

// TimeNowFn to override in unit tests
var TimeNowFn = time.Now
