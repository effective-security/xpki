// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession
// (RFC 9449): clients build DPoP proof JWTs for HTTP requests with Signer and
// ForRequest; servers verify them with VerifyRequestClaims or
// VerifyClaimsContext and bind the resulting key thumbprint to the access
// token "cnf.jkt" claim.
//
// Verification is opt-in beyond the proof itself. Set VerifyConfig.ReplayCache
// (NewMemoryReplayCache for one process, or a shared store) to reject a
// replayed jti; without it replay detection is the caller's job. At a
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
