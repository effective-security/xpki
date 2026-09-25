package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/effective-security/xpki/jwt"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

const benchKeyID = "bench-kid"

// newBenchJWKSServer serves a one-key JWKS document and counts fetches.
func newBenchJWKSServer(b *testing.B) (*httptest.Server, *atomic.Int64) {
	b.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)
	body, err := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: benchKeyID, Algorithm: "RS256", Use: "sig"},
		},
	})
	require.NoError(b, err)

	fetches := new(atomic.Int64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	b.Cleanup(srv.Close)
	return srv, fetches
}

// BenchmarkRemoteKeySet records lookup cost and remote fetches per lookup
// (XPKI-070) for known kids, repeated unknown kids, and concurrent unique
// unknown kids. It uses only the default NewRemoteKeySet configuration.
func BenchmarkRemoteKeySet(b *testing.B) {
	ctx := context.Background()

	b.Run("known", func(b *testing.B) {
		srv, fetches := newBenchJWKSServer(b)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL)
		_, err := ks.GetKey(ctx, benchKeyID)
		require.NoError(b, err)
		fetches.Store(0)
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := ks.GetKey(ctx, benchKeyID); err != nil {
					b.Error(err)
					return
				}
			}
		})
		b.ReportMetric(float64(fetches.Load())/float64(b.N), "fetches/op")
	})

	b.Run("unknown_repeated", func(b *testing.B) {
		srv, fetches := newBenchJWKSServer(b)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL)
		_, err := ks.GetKey(ctx, benchKeyID)
		require.NoError(b, err)
		fetches.Store(0)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if _, err := ks.GetKey(ctx, "missing"); err == nil {
				b.Fatal("expected unknown kid error")
			}
		}
		b.ReportMetric(float64(fetches.Load())/float64(b.N), "fetches/op")
	})

	b.Run("unknown_unique_parallel", func(b *testing.B) {
		srv, fetches := newBenchJWKSServer(b)
		ks := jwt.NewRemoteKeySet(ctx, srv.URL)
		_, err := ks.GetKey(ctx, benchKeyID)
		require.NoError(b, err)
		fetches.Store(0)
		var seq atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				kid := "missing-" + strconv.FormatInt(seq.Add(1), 10)
				if _, err := ks.GetKey(ctx, kid); err == nil {
					b.Error("expected unknown kid error")
					return
				}
			}
		})
		b.ReportMetric(float64(fetches.Load())/float64(b.N), "fetches/op")
	})
}
