// Package dpop implements OAuth 2.0 Demonstrating Proof of Possession
// (RFC 9449): clients build DPoP proof JWTs for HTTP requests with Signer and
// ForRequest; servers verify them with VerifyRequestClaims or VerifyClaims and
// bind the resulting key thumbprint to the access token "cnf.jkt" claim.
// Replay (jti) tracking and "ath" binding are left to the caller.
package dpop
