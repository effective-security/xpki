package dpop

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	jwtgo "github.com/effective-security/xpki/jwt"
	"github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
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

	// ExternalURL is the trusted external origin of this server, as
	// scheme://host[:port]. When set, VerifyRequestClaims takes the htu
	// scheme and host from it instead of the request URL and Host header,
	// which are client-controlled. Set it for plain-HTTP servers and for
	// servers reached under a different name than the Host they receive.
	ExternalURL string
	// ReplayCache, when set, records each accepted proof and rejects a
	// second use of the same jti with the same key (ErrReplay) until the
	// proof leaves its acceptance window. When nil, VerifyClaims does not
	// detect replayed proofs.
	ReplayCache ReplayCache
	// AccessToken, when set, is the access token presented with the proof
	// to a protected resource. The proof must then carry an ath claim equal
	// to AccessTokenHash(AccessToken), and ExpectedThumbprint must be set
	// too: ath alone does not bind the proof key to the token. Leave it
	// empty at the token endpoint. Set it per request, on a copy of a shared
	// VerifyConfig.
	AccessToken string
	// ExpectedThumbprint, when set, is the cnf.jkt value of the access token
	// presented with the proof; the proof key thumbprint must equal it. Set
	// it per request, with AccessToken.
	ExpectedThumbprint string
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
	Claims *jwtgo.Claims
	Key    *jose.JSONWebKey
	// Thumbprint is the RFC 7638 SHA-256 thumbprint of Key, to compare
	// with the access token cnf.jkt claim
	Thumbprint string
	// AccessTokenHash is the proof ath claim, if present
	AccessTokenHash string
}

// proofClaims are the DPoP proof claims: the shared JWT claims plus the
// proof-only ath claim.
type proofClaims struct {
	jwtgo.Claims
	AccessTokenHash string `json:"ath,omitempty"`
}

// VerifyRequestClaims verifies the DPoP proof of an HTTP request received
// by a server; see VerifyClaims. The htu claim is compared with the request
// URI built from cfg.ExternalURL, or else from the request URL and Host
// (https when the URL has no scheme), without query and fragment. The
// request context is passed to cfg.ReplayCache.
func VerifyRequestClaims(cfg VerifyConfig, req *http.Request) (*Result, error) {
	phdr := req.Header.Get(HTTPHeader)
	if phdr == "" && cfg.EnableQuery {
		phdr = queryString(req.URL, "dpop")
	}
	if phdr == "" {
		return nil, errors.New("dpop: HTTP Header not present in request")
	}

	uri, err := requestURI(cfg, req)
	if err != nil {
		return nil, err
	}
	return VerifyClaimsContext(req.Context(), cfg, phdr, req.Method, uri)
}

// VerifyClaims is VerifyClaimsContext with context.Background().
func VerifyClaims(cfg VerifyConfig, phdr, httpMethod, httpURI string) (*Result, error) {
	return VerifyClaimsContext(context.Background(), cfg, phdr, httpMethod, httpURI)
}

// VerifyClaimsContext verifies DPoP proof phdr for a request with httpMethod
// and httpURI (RFC 9449 §4.3) and returns its claims, key and key
// thumbprint. The signature is verified with the embedded public jwk before
// any claim is used. htu is compared with httpURI after URI normalization
// (scheme and host case-insensitive, path case-sensitive, query and fragment
// ignored). When set, cfg.AccessToken requires a matching ath claim and must
// be paired with cfg.ExpectedThumbprint, which requires the proof key to match
// the access token cnf.jkt; cfg.ReplayCache records the proof after every other check
// passed, rejecting a replayed jti with ErrReplay. Without cfg.ReplayCache the
// caller is responsible for replay detection.
func VerifyClaimsContext(ctx context.Context, cfg VerifyConfig, phdr, httpMethod, httpURI string) (*Result, error) {
	// anyone holding the token can compute ath; only cnf.jkt binds the key
	if cfg.AccessToken != "" && cfg.ExpectedThumbprint == "" {
		return nil, errors.New("dpop: ExpectedThumbprint is required with AccessToken")
	}
	headers, err := proofHeaders(phdr)
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: failed to parse header")
	}
	pjwk, err := checkProofHeaders(headers)
	if err != nil {
		return nil, err
	}

	jws, err := jose.ParseSignedCompact(phdr, supportedSignatureAlgorithms)
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: failed to parse header")
	}
	payload, err := jws.Verify(pjwk.Public().Key)
	if err != nil {
		return nil, errors.WithMessagef(err, "dpop: unable to verify token")
	}

	// go-jose's json fork matches member names case-sensitively, as
	// GetTokenInfo and other go-jose consumers do; "JTI" is not "jti"
	pc := &proofClaims{}
	dec := josejson.NewDecoder(bytes.NewReader(payload))
	dec.SetNumberType(josejson.UnmarshalJSONNumber)
	if err = dec.Decode(pc); err != nil {
		return nil, errors.WithMessagef(err, "dpop: claims not found in DPoP header")
	}
	claims := &pc.Claims
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

	// case-insensitive although HTTP methods are case-sensitive (XPKI-108)
	if !strings.EqualFold(claims.HTTPMethod, httpMethod) {
		return nil, errors.Errorf("dpop: claim mismatch: http_method: %q, actual: %q",
			claims.HTTPMethod, httpMethod)
	}

	if err = matchHTU(claims.HTTPUri, httpURI); err != nil {
		return nil, err
	}

	now := TimeNowFn()
	iat := claims.IssuedAt.Time()
	if now.Sub(iat) > DefaultExpiration {
		return nil, errors.Errorf("dpop: iat claim expired: %s", iat.String())
	}
	if iat.After(now.Add(jwtgo.DefaultTimeSkew)) {
		return nil, errors.Errorf("dpop: iat claim is in the future: %s", iat.String())
	}
	// the proof is accepted until iat+DefaultExpiration, or exp if earlier
	acceptedUntil := iat.Add(DefaultExpiration)
	if claims.Expiry != nil {
		exp := claims.Expiry.Time()
		if now.After(exp) {
			return nil, errors.Errorf("dpop: token expired at %s", exp.String())
		}
		if exp.Before(acceptedUntil) {
			acceptedUntil = exp
		}
	}
	if claims.NotBefore != nil && now.Add(jwtgo.DefaultTimeSkew).Before(claims.NotBefore.Time()) {
		return nil, errors.Errorf("dpop: token is not valid before %s", claims.NotBefore.Time().String())
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
	if cfg.AccessToken != "" {
		if pc.AccessTokenHash == "" {
			return nil, errors.New("dpop: claim not found: ath")
		}
		if !constantTimeEqual(pc.AccessTokenHash, AccessTokenHash(cfg.AccessToken)) {
			return nil, errors.New("dpop: claim mismatch: ath")
		}
	}
	tb, err := Thumbprint(pjwk)
	if err != nil {
		return nil, err
	}
	if cfg.ExpectedThumbprint != "" && !constantTimeEqual(tb, cfg.ExpectedThumbprint) {
		return nil, errors.New("dpop: proof key does not match cnf.jkt")
	}

	if cfg.ReplayCache != nil {
		if err = cfg.ReplayCache.Add(ctx, replayKey(tb, claims.ID), acceptedUntil); err != nil {
			return nil, errors.WithMessagef(err, "dpop: proof rejected")
		}
	}

	res := &Result{
		Claims:          claims,
		Key:             pjwk,
		Thumbprint:      tb,
		AccessTokenHash: pc.AccessTokenHash,
	}
	return res, nil
}

// matchHTU compares the htu claim with the request URI after normalization.
func matchHTU(htu, httpURI string) error {
	claimed, err := normalizeHTU(htu)
	if err != nil {
		return errors.WithMessagef(err, "dpop: invalid http_uri claim")
	}
	actual, err := normalizeHTU(httpURI)
	if err != nil {
		return errors.WithMessagef(err, "dpop: invalid request URI")
	}
	if claimed != actual {
		return errors.Errorf("dpop: claim mismatch: http_uri: %q, actual: %q", htu, httpURI)
	}
	return nil
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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
	// case-sensitive like go-jose's own header parsing, so "TYP" is not "typ"
	var parsed compactProtectedHeader
	if err := josejson.Unmarshal(raw, &parsed); err != nil {
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
// can be rejected as multiple headers. The signature is verified by go-jose,
// which implements every algorithm listed here and rejects a jwk whose key
// type or curve does not fit the alg (XPKI-074).
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
