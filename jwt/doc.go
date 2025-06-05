// Package jwt provides JSON Web Token (JWT) signing, verification, and parsing capabilities.
//
// This package implements JWT as defined by RFC 7519, with support for:
//   - JWT signing and verification using various algorithms (HMAC, RSA, ECDSA)
//   - JWT parsing and validation with configurable verification options
//   - JWKS (JSON Web Key Set) for key management and distribution
//   - DPoP (Demonstration of Proof-of-Possession) tokens as per RFC 9449
//   - OAuth2 client credentials flow
//   - Access token generation and validation
//
// The package provides both high-level APIs for common use cases and
// lower-level primitives for advanced JWT operations.
package jwt
