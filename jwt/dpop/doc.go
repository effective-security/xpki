// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession
// (RFC 9449): clients build DPoP proof JWTs for HTTP requests with Signer and
// ForRequest; servers verify them with VerifyRequestClaims or
// VerifyClaimsContext and bind the resulting key thumbprint to the access
// token "cnf.jkt" claim.
//
// Verification is opt-in beyond the proof itself. Set VerifyConfig.ReplayCache
// to reject a replayed jti: NewMemoryReplayCache for one process, or
// NewSharedReplayCache over a store that all instances of the server share,
// such as Redis (SET NX with an expiry); without it replay detection is the
// caller's job. At a
// protected resource set both AccessToken, to require a matching "ath"
// claim, and ExpectedThumbprint, to the token "cnf.jkt"; these are
// per-request values, so set them on a copy of a shared config. Set
// ExternalURL when the
// server's public scheme or host differs from the request it receives:
//
//	cfg := dpop.VerifyConfig{
//		ExternalURL:        "https://api.example.com",
//		ReplayCache:        replayCache, // shared by all requests
//		AccessToken:        accessToken,
//		ExpectedThumbprint: cnfJKT,
//	}
//	res, err := dpop.VerifyRequestClaims(cfg, req)
//
// Set VerifyConfig.NonceSource to require server-provided nonces (RFC 9449
// §8 and §9), which bound the age of a proof by the server's clock and stop
// proofs generated in advance. NewHMACNonceSource needs no store: every
// instance with the same secrets, label and rotation issues and accepts the
// same nonces. A proof
// without a recent nonce fails with an error that errors.Is matches to
// ErrUseDPoPNonce; the server answers it with NonceSource.Nonce in the
// NonceHTTPHeader (DPoP-Nonce) header, as an HTTP 400 error with the code
// ErrorUseDPoPNonce from an authorization server or an HTTP 401 with
// UseDPoPNonceChallenge from a resource server, and the client retries with
// map[string]any{dpop.ClaimNonce: nonce} as the ForRequest extra claims.
// A server may also send a new nonce in any other response, for example
// when NonceSource.Nonce differs from the nonce claim of the proof it just
// accepted, which saves clients the use_dpop_nonce round trip when the nonce
// changes; responses that carry one should not be cached.
//
// A proof can be signed with an ML-DSA key (NewSigner with any crypto.Signer
// whose public key is an *mldsa.PublicKey): RFC 9964 algorithms are accepted,
// and the embedded jwk is an AKP key. An ML-DSA proof carries the public key
// and the signature, about 6 KB with ML-DSA-44, 8 KB with ML-DSA-65 and 11 KB
// with ML-DSA-87, which can exceed the header limit of an HTTP server or proxy.
//
// Clients add the "ath" claim with
// map[string]any{dpop.ClaimAccessTokenHash: dpop.AccessTokenHash(token)} as
// the ForRequest extra claims.
package dpop
