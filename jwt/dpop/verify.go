package dpop

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/effective-security/xlog"
	jwtgo "github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/x/slices"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/pkg/errors"
)

// VerifyConfig expreses the possible options for validating a JWT
type VerifyConfig struct {
	// ExpectedIssuer validates the iss claim of a JWT matches this value
	ExpectedIssuer string
	// ExpectedSubject validates the sub claim of a JWT matches this value
	ExpectedSubject string
	// ExpectedAudience validates that the aud claim of a JWT contains this value
	ExpectedAudience string
	// ExpectedNonce validates that the nonce claim of a JWT contains this value
	ExpectedNonce string
	// EnableQuery speciies to get `dpop` header from the QueryString
	EnableQuery bool
}

/*
https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-04#ref-IANA.MediaType.StructuredSuffix

	4.3.  Checking DPoP Proofs

	To check if a string that was received as part of an HTTP Request is
	a valid DPoP proof, the receiving server MUST ensure that

	1.   that there is not more than one DPoP header in the request,

	2.   the string value of the header field is a well-formed JWT,

	3.   all required claims per Section 4.2 are contained in the JWT,

	4.   the typ field in the header has the value dpop+jwt,

	5.   the algorithm in the header of the JWT indicates an asymmetric
		digital signature algorithm, is not none, is supported by the
		application, and is deemed secure,

	6.   the JWT signature verifies with the public key contained in the
		jwk header of the JWT,

	7.   the htm claim matches the HTTP method value of the HTTP request
		in which the JWT was received,

	8.   the htu claim matches the HTTPS URI value for the HTTP request
		in which the JWT was received, ignoring any query and fragment
		parts,

	9.   if the server provided a nonce value to the client, the nonce
		claim matches the server-provided nonce value,

	10.  the token was issued within an acceptable timeframe and, within
		a reasonable consideration of accuracy and resource utilization,
		a proof JWT with the same jti value has not previously been
		received at the same resource during that time period (see
		Section 10.1).

	11.  when presented to a protected resource in conjunction with an
		access token, ensure that the value of the ath claim equals the
		hash of the access token that has been presented alongside the
		DPoP proof.
*/

// Result is returned from VerifyClaims
type Result struct {
	Claims     *jwtgo.Claims
	Key        *jose.JSONWebKey
	Thumbprint string
}

var parser = jwtgo.TokenParser{
	UseJSONNumber: true,
}

// VerifyRequestClaims returns DPoP claims, raw claims, key; or error
func VerifyRequestClaims(cfg VerifyConfig, req *http.Request) (*Result, error) {
	phdr := req.Header.Get(HTTPHeader)
	if phdr == "" && cfg.EnableQuery {
		phdr = queryString(req.URL, "dpop")
	}
	if phdr == "" {
		return nil, errors.New("dpop: HTTP Header not present in request")
	}

	u := req.URL
	coreURL := url.URL{
		Scheme: slices.StringsCoalesce(u.Scheme, "https"),
		Host:   slices.StringsCoalesce(u.Host, req.Host),
		Path:   u.Path,
	}

	return VerifyClaims(cfg, phdr, req.Method, coreURL.String())
}

// VerifyClaims returns DPoP claims, raw claims, key; or error
func VerifyClaims(cfg VerifyConfig, phdr, httpMethod, httpURI string) (*Result, error) {
	pjwt, err := jwt.ParseSigned(phdr)
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: failed to parse header")
	}

	if len(pjwt.Headers) != 1 {
		return nil, errors.New("dpop: token contains multiple headers")
	}

	pjwtTyp, ok := pjwt.Headers[0].ExtraHeaders["typ"]
	if !ok {
		return nil, errors.New("dpop: typ field not found in header")
	}

	if pjwtTyp != jwtHeaderTypeDPOP {
		return nil, errors.New("dpop: invalid typ header")
	}

	pjwk := pjwt.Headers[0].JSONWebKey
	if pjwk == nil {
		return nil, errors.New("dpop: jwk field not found in header")
	}
	if !pjwk.IsPublic() {
		return nil, errors.New("dpop: jwk field in header must be public key")
	}

	algo := jose.SignatureAlgorithm(pjwt.Headers[0].Algorithm)
	if !supportedSignatureAlgorithm[algo] {
		return nil, errors.Errorf("dpop: alg not allowed: %s", algo)
	}

	claims := &jwtgo.Claims{}
	err = pjwt.UnsafeClaimsWithoutVerification(claims)
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: claims not found in DPoP header")
	}
	if claims.ID == "" {
		return nil, errors.New("dpop: claim not found: jti")
	}
	if claims.HTTPMethod == "" {
		return nil, errors.New("dpop: claim not found: http_method")
	}
	if claims.HTTPUri == "" {
		return nil, errors.New("dpop: claim not found: http_uri")
	}
	if claims.IssuedAt == nil {
		return nil, errors.New("dpop: claim not found: iat")
	}

	if !strings.EqualFold(claims.HTTPMethod, httpMethod) {
		return nil, errors.Errorf("dpop: claim mismatch: http_method: %q, actual: %q",
			claims.HTTPMethod, httpMethod)
	}

	if !strings.EqualFold(claims.HTTPUri, httpURI) {
		return nil, errors.Errorf("dpop: claim mismatch: http_uri: %q, actual: %q",
			claims.HTTPUri, httpURI)
	}

	now := TimeNowFn()
	iat := claims.IssuedAt.Time()
	if now.Sub(iat) > DefaultExpiration {
		return nil, errors.Errorf("dpop: iat claim expired: %s", iat.String())
	}

	jwtgo.TimeNowFn = TimeNowFn
	_, err = parser.Parse(phdr, nil, func(token *jwtgo.Token) (interface{}, error) {
		return pjwk.Public().Key, nil
	})
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: failed to verify token")
	}
	if cfg.ExpectedIssuer != "" && claims.Issuer != cfg.ExpectedIssuer {
		return nil, errors.Errorf("dpop: invalid issuer: '%s'", claims.Issuer)
	}
	if cfg.ExpectedSubject != "" && claims.Subject != cfg.ExpectedSubject {
		return nil, errors.Errorf("dpop: invalid subject: '%s'", claims.Subject)
	}
	if cfg.ExpectedAudience != "" && !claims.Audience.Contains(cfg.ExpectedAudience) {
		return nil, errors.Errorf("dpop: invalid audience: %v", claims.Audience)
	}
	if cfg.ExpectedNonce != "" && claims.Nonce != cfg.ExpectedNonce {
		return nil, errors.Errorf("dpop: invalid nonce: '%s'", claims.Nonce)
	}
	tb, err := Thumbprint(pjwk)
	if err != nil {
		return nil, err
	}

	res := &Result{
		Claims:     claims,
		Key:        pjwk,
		Thumbprint: tb,
	}

	logger.KV(xlog.TRACE,
		"key", res.Thumbprint,
		"claims", claims,
	)

	return res, nil
}

var supportedSignatureAlgorithm = map[jose.SignatureAlgorithm]bool{
	jose.RS256: true, // RSASSA-PKCS-v1.5 using SHA-256
	jose.RS384: true, // RSASSA-PKCS-v1.5 using SHA-384
	jose.RS512: true, // RSASSA-PKCS-v1.5 using SHA-512
	jose.ES256: true, // ECDSA using P-256 and SHA-256
	jose.ES384: true, // ECDSA using P-384 and SHA-384
	jose.ES512: true, // ECDSA using P-521 and SHA-512
	jose.PS256: true, // RSASSA-PSS using SHA256 and MGF1-SHA256
	jose.PS384: true, // RSASSA-PSS using SHA384 and MGF1-SHA384
	jose.PS512: true, // RSASSA-PSS using SHA512 and MGF1-SHA512
	jose.EdDSA: true, // EdDSA using Ed25519
}

// queryString returns Query parameter
func queryString(u *url.URL, name string) string {
	vals, ok := u.Query()[name]
	if !ok || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// TokenInfo is returned from GetTokenInfo
type TokenInfo struct {
	Token       *jwt.JSONWebToken
	Claims      jwtgo.Claims
	Key         *jose.JSONWebKey
	Thumbprint  string
	CnfJkt      string
	IsPublicKey bool
	IsFresh     bool
}

// GetTokenInfo returns token info, if it's JWT or nil otherwise
func GetTokenInfo(t string) *TokenInfo {
	pjwt, err := jwt.ParseSigned(t)
	if err != nil {
		return nil
	}

	res := &TokenInfo{
		Token: pjwt,
	}

	err = pjwt.UnsafeClaimsWithoutVerification(&res.Claims)
	if err == nil {
		now := TimeNowFn()
		iat := res.Claims.IssuedAt.Time()
		res.IsFresh = now.Sub(iat) < DefaultExpiration
		if res.Claims.Cnf != nil {
			res.CnfJkt = res.Claims.Cnf.Jkt
		}
	}

	pjwk := pjwt.Headers[0].JSONWebKey
	if pjwk != nil {
		res.IsPublicKey = pjwk.IsPublic()
		res.Thumbprint, _ = Thumbprint(pjwk)
	}

	return res
}
