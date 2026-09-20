package dpop

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"cmp"

	"github.com/cockroachdb/errors"
	jwtgo "github.com/effective-security/xpki/jwt"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// VerifyConfig expresses the possible options for validating a JWT
type VerifyConfig struct {
	// ExpectedIssuer validates the iss claim of a JWT matches this value
	ExpectedIssuer string
	// ExpectedSubject validates the sub claim of a JWT matches this value
	ExpectedSubject string
	// ExpectedAudience validates that the aud claim of a JWT contains this value
	ExpectedAudience string
	// ExpectedNonce validates that the nonce claim of a JWT contains this value
	ExpectedNonce string
	// EnableQuery specifies to get `dpop` header from the QueryString
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

// parser verifies the proof signature only; temporal claims are checked in
// VerifyClaims against a single per-call clock (TimeNowFn) so that the
// freshness check and the exp/nbf checks cannot disagree.
var parser = jwtgo.TokenParser{
	UseJSONNumber:        true,
	SkipClaimsValidation: true,
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
		Scheme: cmp.Or(u.Scheme, "https"),
		Host:   cmp.Or(u.Host, req.Host),
		Path:   u.Path,
	}

	return VerifyClaims(cfg, phdr, req.Method, coreURL.String())
}

// VerifyClaims returns DPoP claims, raw claims, key; or error
func VerifyClaims(cfg VerifyConfig, phdr, httpMethod, httpURI string) (*Result, error) {
	headers, err := proofHeaders(phdr)
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: failed to parse header")
	}
	pjwk, err := checkProofHeaders(headers)
	if err != nil {
		return nil, err
	}

	pjwt, err := jwt.ParseSigned(phdr, supportedSignatureAlgorithms)
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: failed to parse header")
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
	if iat.After(now.Add(jwtgo.DefaultTimeSkew)) {
		return nil, errors.Errorf("dpop: iat claim is in the future: %s", iat.String())
	}
	if claims.Expiry != nil && now.After(claims.Expiry.Time()) {
		return nil, errors.Errorf("dpop: token expired at %s", claims.Expiry.Time().String())
	}
	if claims.NotBefore != nil && now.Add(jwtgo.DefaultTimeSkew).Before(claims.NotBefore.Time()) {
		return nil, errors.Errorf("dpop: token is not valid before %s", claims.NotBefore.Time().String())
	}

	_, err = parser.Parse(phdr, nil, func(token *jwtgo.Token) (any, error) {
		return pjwk.Public().Key, nil
	})
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: unable to verify token")
	}
	if cfg.ExpectedIssuer != "" && claims.Issuer != cfg.ExpectedIssuer {
		return nil, errors.Errorf("dpop: invalid issuer")
	}
	if cfg.ExpectedSubject != "" && claims.Subject != cfg.ExpectedSubject {
		return nil, errors.Errorf("dpop: invalid subject")
	}
	if cfg.ExpectedAudience != "" && !claims.Audience.Contains(cfg.ExpectedAudience) {
		return nil, errors.Errorf("dpop: invalid audience")
	}
	if cfg.ExpectedNonce != "" && claims.Nonce != cfg.ExpectedNonce {
		return nil, errors.Errorf("dpop: invalid nonce")
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

	// logger.KV(xlog.DEBUG,
	// 	"key", res.Thumbprint,
	// 	"claims", claims,
	// )

	return res, nil
}

const jwsJSONPrefix = "{"

func proofHeaders(phdr string) ([]jose.Header, error) {
	if strings.HasPrefix(strings.TrimSpace(phdr), jwsJSONPrefix) {
		jws, err := jose.ParseSigned(phdr, supportedSignatureAlgorithms)
		if err != nil {
			return nil, err
		}
		return headersFrom(jws), nil
	}
	if h, ok := compactJOSEHeader(phdr); ok {
		return []jose.Header{h}, nil
	}
	pjwt, err := jwt.ParseSigned(phdr, supportedSignatureAlgorithms)
	if err != nil {
		return nil, err
	}
	return pjwt.Headers, nil
}

func headersFrom(jws *jose.JSONWebSignature) []jose.Header {
	headers := make([]jose.Header, len(jws.Signatures))
	for i, sig := range jws.Signatures {
		headers[i] = sig.Header
	}
	return headers
}

type compactProtectedHeader struct {
	Typ string           `json:"typ"`
	Alg string           `json:"alg"`
	JWK *jose.JSONWebKey `json:"jwk,omitempty"`
}

func compactJOSEHeader(phdr string) (jose.Header, bool) {
	protected, rest, ok := strings.Cut(phdr, ".")
	if !ok {
		return jose.Header{}, false
	}
	if _, extra, ok := strings.Cut(rest, "."); !ok || strings.ContainsRune(extra, '.') {
		return jose.Header{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return jose.Header{}, false
	}
	var parsed compactProtectedHeader
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return jose.Header{}, false
	}
	extra := map[jose.HeaderKey]any{}
	if parsed.Typ != "" {
		extra[jose.HeaderType] = parsed.Typ
	}
	return jose.Header{
		Algorithm:    parsed.Alg,
		JSONWebKey:   parsed.JWK,
		ExtraHeaders: extra,
	}, true
}

func checkProofHeaders(headers []jose.Header) (*jose.JSONWebKey, error) {
	if len(headers) != 1 {
		return nil, errors.New("dpop: token contains multiple headers")
	}

	pjwtTyp, ok := headers[0].ExtraHeaders[jose.HeaderType]
	if !ok {
		return nil, errors.New("dpop: typ field not found in header")
	}

	if pjwtTyp != jwtHeaderTypeDPOP {
		return nil, errors.New("dpop: invalid typ header")
	}

	pjwk := headers[0].JSONWebKey
	if pjwk == nil {
		return nil, errors.New("dpop: jwk field not found in header")
	}
	if !pjwk.IsPublic() {
		return nil, errors.New("dpop: jwk field in header must be public key")
	}

	algo := jose.SignatureAlgorithm(headers[0].Algorithm)
	if !supportedSignatureAlgorithm[algo] {
		return nil, errors.Errorf("dpop: alg not allowed: %s", algo)
	}
	return pjwk, nil
}

// supportedSignatureAlgorithms is the allow-list passed to the go-jose parser
// after compact header checks. Compact proofs decode the protected header first
// so a private jwk or HMAC alg is rejected with a DPoP error rather than a
// parse error. JSON serialization is parsed here so a multi-signature proof
// can be rejected as multiple headers.
var supportedSignatureAlgorithms = slices.Sorted(maps.Keys(supportedSignatureAlgorithm))

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
	pjwt, err := jwt.ParseSigned(t, supportedSignatureAlgorithms)
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
