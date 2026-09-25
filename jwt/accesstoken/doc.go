// Package accesstoken wraps a jwt.Provider and a dataprotection.Provider to
// issue opaque encrypted access tokens of the form "pat.<base64url(AES-GCM
// (claims))>" while still parsing plain JWTs through the inner provider.
//
// Every pat. token expires. Sign keeps a caller-supplied exp; otherwise it
// adds iat, nbf and an exp after WithTokenExpiry, or the inner provider's
// TokenExpiry, and fails when neither is set. ParseToken rejects pat. tokens
// without exp unless WithAllowNoExpiry is set to migrate perpetual tokens
// issued by older versions.
//
//	dp, err := dataprotection.NewSymmetric(secret)
//	if err != nil {
//		return err
//	}
//	p := accesstoken.New(dp, nil, accesstoken.WithTokenExpiry(time.Hour))
//	token, err := p.Sign(ctx, jwt.MapClaims{"sub": "user"})
//	if err != nil {
//		return err
//	}
//	claims, err := p.ParseToken(ctx, token, nil)
package accesstoken
