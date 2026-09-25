package dpop_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/effective-security/xpki/jwt/dpop"
)

// A protected resource verifies the proof sent with a DPoP-bound access
// token: htu against its trusted external origin, ath against the presented
// token, the proof key against the token cnf.jkt, and jti against a replay
// cache shared by all requests.
func ExampleVerifyRequestClaims() {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := dpop.NewSigner(key)
	accessToken := "access-token-bound-to-the-key"
	cnfJKT := signer.JWKThumbprint() // from the access token cnf.jkt claim

	// client
	creq, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1/items?page=2", nil)
	_, _ = dpop.ForRequest(signer, creq, map[string]any{
		dpop.ClaimAccessTokenHash: dpop.AccessTokenHash(accessToken),
	})

	// server, behind a proxy that forwards the request as plain HTTP
	replay := dpop.NewMemoryReplayCache(0)
	cfg := dpop.VerifyConfig{
		ExternalURL:        "https://api.example.com",
		ReplayCache:        replay,
		AccessToken:        accessToken,
		ExpectedThumbprint: cnfJKT,
	}
	sreq := httptest.NewRequest(http.MethodGet, "/v1/items?page=2", nil)
	sreq.Host = "backend:8080"
	sreq.Header.Set(dpop.HTTPHeader, creq.Header.Get(dpop.HTTPHeader))

	res, err := dpop.VerifyRequestClaims(cfg, sreq)
	fmt.Println(err, res.Claims.HTTPUri)
	_, err = dpop.VerifyRequestClaims(cfg, sreq)
	fmt.Println(err)
	// Output:
	// <nil> https://api.example.com/v1/items
	// dpop: proof rejected: dpop: proof replayed
}
