package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/effective-security/xpki/v2/jwt/dpop"
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

// A server that issues nonces answers a proof without one, or with a stale
// one, with a use_dpop_nonce error and a fresh nonce in the DPoP-Nonce
// header; the client signs a new proof with that nonce and keeps using it
// until the server sends another.
func ExampleHMACNonceSource() {
	secret := make([]byte, dpop.MinNonceSecretSize)
	_, _ = rand.Read(secret) // the same secret on every instance of the server
	nonces, _ := dpop.NewHMACNonceSource(dpop.HMACNonceConfig{
		Secrets: [][]byte{secret},
		Label:   "api.example.com",
	})
	cfg := dpop.VerifyConfig{NonceSource: nonces}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := dpop.NewSigner(key)
	u, _ := url.Parse("https://api.example.com/v1/items")
	ctx := context.Background()

	proof, _ := signer.Sign(ctx, http.MethodGet, u, nil)
	_, err := dpop.VerifyClaims(cfg, proof, http.MethodGet, u.String())
	if errors.Is(err, dpop.ErrUseDPoPNonce) {
		// a resource server answers HTTP 401 with WWW-Authenticate:
		// dpop.UseDPoPNonceChallenge, an authorization server HTTP 400 with
		// the error code dpop.ErrorUseDPoPNonce; both set the nonce header
		nonce, _ := nonces.Nonce(ctx)
		fmt.Println(err, "->", dpop.NonceHTTPHeader)

		proof, _ = signer.Sign(ctx, http.MethodGet, u, map[string]any{dpop.ClaimNonce: nonce})
	}
	_, err = dpop.VerifyClaims(cfg, proof, http.MethodGet, u.String())
	fmt.Println(err)
	// Output:
	// dpop: claim not found: nonce -> DPoP-Nonce
	// <nil>
}
