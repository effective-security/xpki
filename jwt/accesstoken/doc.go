// Package accesstoken wraps a jwt.Provider and a dataprotection.Provider to
// issue opaque encrypted access tokens of the form "pat.<base64url(AES-GCM
// (claims))>" while still parsing plain JWTs through the inner provider.
package accesstoken
