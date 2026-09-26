package gcpkmscrypto_test

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
)

// BenchmarkGenerateKeyWait measures key generation over a fake client whose
// version is PENDING_GENERATION for the given number of polls, with a wait
// that returns at once, so the time is CPU work and the polls and waits per
// operation are deterministic (XPKI-024).
func BenchmarkGenerateKeyWait(b *testing.B) {
	for _, pending := range []int{0, 3, 59} {
		b.Run(fmt.Sprintf("pending=%d", pending), func(b *testing.B) {
			remaining := 0
			ver := enabledVersion(genKey, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)
			pendingVer := enabledVersion(genKey, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256)
			pendingVer.State = kmspb.CryptoKeyVersion_PENDING_GENERATION
			key := &kmspb.CryptoKey{Name: genKeyName}
			public := &kmspb.PublicKey{Pem: p256PublicPEM}
			client := &fakeKMS{
				createCryptoKey: func(*kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) { return key, nil },
				getCryptoKeyVersion: func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
					if remaining > 0 {
						remaining--
						return pendingVer, nil
					}
					return ver, nil
				},
				getPublicKey: func(*kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) { return public, nil },
			}
			provider := gcpkmscrypto.NewTestProvider(testTokenCfg(coverageKeyring), client, coverageKeyring)
			waits := 0
			gcpkmscrypto.SetGenerationWait(provider, time.Second, 60, func(context.Context, time.Duration) error {
				waits++
				return nil
			})

			b.ReportAllocs()
			for b.Loop() {
				remaining = pending
				if _, err := provider.GenerateECDSAKey("bench", elliptic.P256()); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(client.CallCount("GetCryptoKeyVersion"))/float64(b.N), "polls/op")
			b.ReportMetric(float64(waits)/float64(b.N), "waits/op")
		})
	}
}

// BenchmarkGenerateKeyCloseLatency measures how long Close takes to end a
// key generation blocked in its wait between polls (XPKI-024).
func BenchmarkGenerateKeyCloseLatency(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		polled := make(chan struct{}, 1)
		client := generatingKMS(60, kmspb.CryptoKeyVersion_ENABLED)
		poll := client.getCryptoKeyVersion
		client.getCryptoKeyVersion = func(req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			polled <- struct{}{}
			return poll(req)
		}
		provider := gcpkmscrypto.NewTestProvider(testTokenCfg(coverageKeyring), client, coverageKeyring)
		gcpkmscrypto.SetGenerationWait(provider, time.Hour, 60, nil)
		done := make(chan error, 1)
		go func() {
			_, err := provider.GenerateECDSAKey("bench", elliptic.P256())
			done <- err
		}()
		<-polled
		b.StartTimer()

		if err := provider.Close(); err != nil {
			b.Fatal(err)
		}
		if err := <-done; err == nil {
			b.Fatal("generation did not stop")
		}
	}
}
