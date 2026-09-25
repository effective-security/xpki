package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

const (
	benchHTU    = "https://api.example.com/v1/resource"
	benchMethod = http.MethodGet
)

func benchSigner(b *testing.B) jose.Signer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)
	s, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &jose.SignerOptions{
		EmbedJWK: true,
		ExtraHeaders: map[jose.HeaderKey]any{
			jose.HeaderType: "dpop+jwt",
		},
	})
	require.NoError(b, err)
	return s
}

func benchProof(b *testing.B, s jose.Signer, jti string) string {
	token, err := jwt.Signed(s).Claims(map[string]any{
		"jti": jti,
		"htm": benchMethod,
		"htu": benchHTU,
		"iat": time.Now().Unix(),
	}).Serialize()
	require.NoError(b, err)
	return token
}

// BenchmarkVerifyClaims verifies one ES256 proof without a replay cache. It
// uses only the API that predates the replay cache so that it can be run
// against the previous implementation.
func BenchmarkVerifyClaims(b *testing.B) {
	proof := benchProof(b, benchSigner(b), "bench-jti")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := dpop.VerifyClaims(dpop.VerifyConfig{}, proof, benchMethod, benchHTU); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkVerifyClaimsReplayCache verifies b.N unique proofs through one
// MemoryReplayCache and reports the retained entries.
func BenchmarkVerifyClaimsReplayCache(b *testing.B) {
	s := benchSigner(b)
	proofs := make([]string, b.N)
	for i := range proofs {
		proofs[i] = benchProof(b, s, strconv.Itoa(i))
	}
	cache := dpop.NewMemoryReplayCache(b.N)
	cfg := dpop.VerifyConfig{ReplayCache: cache}
	var next atomic.Int64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			proof := proofs[next.Add(1)-1]
			if _, err := dpop.VerifyClaims(cfg, proof, benchMethod, benchHTU); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(cache.Len()), "entries")
}

// BenchmarkMemoryReplayCache measures the cache alone: admitting unique keys,
// rejecting a replayed key, and admitting at capacity while evicting expired
// entries.
func BenchmarkMemoryReplayCache(b *testing.B) {
	ctx := context.Background()
	expiresAt := time.Now().Add(time.Hour)

	b.Run("unique", func(b *testing.B) {
		keys := make([]string, b.N)
		for i := range keys {
			keys[i] = strconv.Itoa(i)
		}
		cache := dpop.NewMemoryReplayCache(b.N)
		var next atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if err := cache.Add(ctx, keys[next.Add(1)-1], expiresAt); err != nil {
					b.Error(err)
					return
				}
			}
		})
		b.StopTimer()
		b.ReportMetric(float64(cache.Len()), "entries")
	})

	b.Run("replayed", func(b *testing.B) {
		cache := dpop.NewMemoryReplayCache(1)
		require.NoError(b, cache.Add(ctx, "k", expiresAt))
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if err := cache.Add(ctx, "k", expiresAt); err == nil {
					b.Error("replay accepted")
					return
				}
			}
		})
	})

	b.Run("evict_at_capacity", func(b *testing.B) {
		const capacity = 1024
		keys := make([]string, b.N)
		for i := range keys {
			keys[i] = strconv.Itoa(i)
		}
		cache := dpop.NewMemoryReplayCache(capacity)
		var next atomic.Int64
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// already expired: the next Add evicts it
				if err := cache.Add(ctx, keys[next.Add(1)-1], time.Now()); err != nil {
					b.Error(err)
					return
				}
			}
		})
		b.StopTimer()
		b.ReportMetric(float64(cache.Len()), "entries")
	})
}
