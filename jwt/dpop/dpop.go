package dpop

import (
	"context"
	"net/url"
	"time"

	"github.com/effective-security/xlog"
	"github.com/pkg/errors"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki/jwt", "dpop")

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
	// Sign returns DPoP token
	Sign(ctx context.Context, method string, u *url.URL, extraClaims interface{}) (string, error)
	// JWKThumbprint returns base64 hash of the key
	JWKThumbprint() string
}

// TimeNowFn to override in unit tests
var TimeNowFn = time.Now

// SetCnfClaim sets DPoP `cnf` claim
func SetCnfClaim(claims map[string]interface{}, thumprint string) {
	claims["cnf"] = map[string]interface{}{
		CnfThumbprint: thumprint,
	}
}

// GetCnfClaim gets DPoP `cnf` claim
func GetCnfClaim(claims map[string]interface{}) (string, error) {
	cnf := claims["cnf"]
	if cnf == nil {
		return "", nil
	}
	m, ok := cnf.(map[string]interface{})
	if !ok {
		return "", errors.Errorf("dpop: invalid cnf claim")
	}
	tb, ok := m[CnfThumbprint].(string)
	if !ok {
		return "", errors.Errorf("dpop: invalid cnf claim")
	}
	return tb, nil
}
