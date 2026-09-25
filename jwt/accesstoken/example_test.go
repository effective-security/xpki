package accesstoken_test

import (
	"context"
	"fmt"
	"time"

	"github.com/effective-security/xpki/dataprotection"
	"github.com/effective-security/xpki/jwt"
	"github.com/effective-security/xpki/jwt/accesstoken"
)

// ExampleNew compiles the usage sample from doc.go.
func ExampleNew() {
	ctx := context.Background()
	dp, err := dataprotection.NewSymmetric([]byte("secret"))
	if err != nil {
		panic(err)
	}
	p := accesstoken.New(dp, nil, accesstoken.WithTokenExpiry(time.Hour))
	token, err := p.Sign(ctx, jwt.MapClaims{"sub": "user"})
	if err != nil {
		panic(err)
	}
	claims, err := p.ParseToken(ctx, token, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(claims.String("sub"), claims.Time("exp") != nil)
	// Output: user true
}
