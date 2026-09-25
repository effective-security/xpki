package crypto11

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	pkcs11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
)

const (
	benchRandomSize = 32
	// benchPoolSize is the default session limit (DefaultMaxSessions, and
	// the pool channel size before XPKI-005).
	benchPoolSize = 1024
	// benchSaturationBorrowers exceeds benchPoolSize.
	benchSaturationBorrowers = 1100
	benchSaturationTimeout   = 10 * time.Second
	benchSettle              = 100 * time.Millisecond
)

// probeSessionHandle opens and closes an unpooled session and returns its
// handle. SoftHSM allocates session handles from an increasing counter, so
// the difference between two probes approximates the sessions opened in
// between.
func probeSessionHandle(tb testing.TB) pkcs11.SessionHandle {
	tb.Helper()
	s, err := p11lib.NewSession(p11lib.Slot.id)
	require.NoError(tb, err)
	require.NoError(tb, p11lib.Ctx.CloseSession(s))
	return s
}

// liveSessions counts the session handles in (from, to) that are still open.
func liveSessions(from, to pkcs11.SessionHandle) int {
	live := 0
	for h := from + 1; h < to; h++ {
		if _, err := p11lib.Ctx.GetSessionInfo(h); err == nil {
			live++
		}
	}
	return live
}

func reportSessions(b *testing.B, before pkcs11.SessionHandle) {
	b.StopTimer()
	after := probeSessionHandle(b)
	b.ReportMetric(float64(after-before-1), "opened")
	b.ReportMetric(float64(liveSessions(before, after)), "live")
}

func BenchmarkSession_GenRandomSerial(b *testing.B) {
	requireP11(b)
	buf := make([]byte, benchRandomSize)
	before := probeSessionHandle(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := p11lib.GenRandom(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
	reportSessions(b, before)
}

func BenchmarkSession_GenRandomParallel(b *testing.B) {
	requireP11(b)
	before := probeSessionHandle(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, benchRandomSize)
		for pb.Next() {
			if _, err := p11lib.GenRandom(buf); err != nil {
				b.Error(err)
				return
			}
		}
	})
	reportSessions(b, before)
}

func BenchmarkSession_SignECDSAParallel(b *testing.B) {
	requireP11(b)
	priv, err := p11lib.GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(b, err)
	defer func() { _ = p11lib.DestroyKeyPairOnSlot(p11lib.Slot.id, string(mustKeyID(b, priv))) }()
	digest := sha256.Sum256([]byte("bench"))

	before := probeSessionHandle(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := priv.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
				b.Error(err)
				return
			}
		}
	})
	reportSessions(b, before)
}

// BenchmarkSession_Saturation starts more borrowers than the default pool
// size, each holding its session until the pool is full, and reports the
// peak concurrent borrowers and how many borrowers did not finish within
// the timeout. Run with -benchtime=1x.
func BenchmarkSession_Saturation(b *testing.B) {
	requireP11(b)
	for b.Loop() {
		before := probeSessionHandle(b)
		var inUse, peak atomic.Int32
		release := make(chan struct{})
		finished := make(chan error, benchSaturationBorrowers)
		for range benchSaturationBorrowers {
			go func() {
				finished <- p11lib.withSession(p11lib.Slot.id, func(pkcs11.SessionHandle) error {
					n := inUse.Add(1)
					for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
					}
					<-release
					inUse.Add(-1)
					return nil
				})
			}()
		}
		// wait until the pool is full, then give the rest a chance to borrow;
		// a borrower that fails before borrowing ends the run
		completed := 0
		deadline := time.After(benchSaturationTimeout)
		for inUse.Load() < benchPoolSize {
			select {
			case err := <-finished:
				close(release)
				b.Fatalf("borrower failed before the pool was full: %v", err)
			case <-deadline:
				close(release)
				b.Fatalf("pool did not fill: %d of %d borrowed", inUse.Load(), benchPoolSize)
			case <-time.After(time.Millisecond):
			}
		}
		time.Sleep(benchSettle)
		close(release)

		deadline = time.After(benchSaturationTimeout)
	wait:
		for completed < benchSaturationBorrowers {
			select {
			case err := <-finished:
				if err != nil {
					b.Errorf("borrower: %v", err)
				}
				completed++
			case <-deadline:
				break wait
			}
		}
		b.StopTimer()
		after := probeSessionHandle(b)
		b.ReportMetric(float64(peak.Load()), "peak")
		b.ReportMetric(float64(benchSaturationBorrowers-completed), "stuck")
		b.ReportMetric(float64(after-before-1), "opened")
		b.ReportMetric(float64(liveSessions(before, after)), "live")
		b.StartTimer()
	}
}

// BenchmarkLifecycle_InitClose measures a full Init/GenRandom/Close cycle of
// a second wrapper and reports the sessions left open by the cycles.
func BenchmarkLifecycle_InitClose(b *testing.B) {
	requireP11(b)
	cfg, err := LoadTokenConfig(SoftHSMConfig)
	require.NoError(b, err)
	buf := make([]byte, benchRandomSize)
	before := probeSessionHandle(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		lib, err := Init(cfg)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = lib.GenRandom(buf); err != nil {
			b.Fatal(err)
		}
		closeLib(b, lib)
	}
	reportSessions(b, before)
}

func mustKeyID(tb testing.TB, priv *PKCS11PrivateKeyECDSA) []byte {
	tb.Helper()
	return mustKeyIDOn(tb, p11lib, priv)
}
