package cryptoprov_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	concurrentWorkers   = 8
	concurrentProviders = 32
	benchAddEvery       = 1024
	benchAddPool        = 64
)

// namedProvider is a real in-memory provider registered under its own
// manufacturer and model, so several of them fit in one Crypto.
type namedProvider struct {
	cryptoprov.Provider
	manufacturer string
	model        string
}

func (p *namedProvider) Manufacturer() string { return p.manufacturer }
func (p *namedProvider) Model() string        { return p.model }

func newNamedProvider(manufacturer, model string) *namedProvider {
	return &namedProvider{
		Provider:     inmemcrypto.NewProvider(),
		manufacturer: manufacturer,
		model:        model,
	}
}

// TestCryptoConcurrentAddLookup overlaps Add of new and already registered
// providers with ByManufacturer lookups (XPKI-016).
func TestCryptoConcurrentAddLookup(t *testing.T) {
	t.Parallel()

	def := newNamedProvider("default", "m")
	pre := newNamedProvider("pre", "m")
	cp, err := cryptoprov.New(def, []cryptoprov.Provider{pre})
	require.NoError(t, err)

	added := make([]*namedProvider, concurrentProviders)
	for i := range added {
		added[i] = newNamedProvider(fmt.Sprintf("added-%d", i), "m")
	}

	start := make(chan struct{})
	errs := make(chan error, concurrentWorkers*concurrentProviders*4)
	var wg sync.WaitGroup
	for w := range concurrentWorkers {
		wg.Go(func() {
			<-start
			for i := range concurrentProviders {
				// every worker adds the same instances: re-adding one is a no-op
				p := added[(i+w)%concurrentProviders]
				if err := cp.Add(p); err != nil {
					errs <- err
				}
				if err := cp.Add(pre); err != nil {
					errs <- err
				}
				if got, err := cp.ByManufacturer("pre", "m"); err != nil || got != pre {
					errs <- fmt.Errorf("pre lookup: %v, %T", err, got)
				}
				if got, err := cp.ByManufacturer("default", "m"); err != nil || got != def {
					errs <- fmt.Errorf("default lookup: %v, %T", err, got)
				}
				// the lookup may run before or after another worker adds it
				if got, err := cp.ByManufacturer(p.manufacturer, "m"); err == nil && got != p {
					errs <- fmt.Errorf("added lookup returned another provider: %s", got.Manufacturer())
				}
			}
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}

	for _, p := range added {
		got, err := cp.ByManufacturer(p.manufacturer, p.model)
		require.NoError(t, err)
		assert.Same(t, p, got)
	}
}

func newBenchCrypto(b *testing.B, extra int) *cryptoprov.Crypto {
	b.Helper()
	providers := make([]cryptoprov.Provider, extra)
	for i := range providers {
		providers[i] = newNamedProvider(fmt.Sprintf("extra-%d", i), "m")
	}
	cp, err := cryptoprov.New(newNamedProvider("default", "m"), providers)
	require.NoError(b, err)
	return cp
}

// BenchmarkByManufacturer measures lookups of the default provider, of a
// registered provider and of a missing one, serially and in parallel.
func BenchmarkByManufacturer(b *testing.B) {
	for _, extra := range []int{1, 16} {
		for _, bc := range []struct {
			name         string
			manufacturer string
			found        bool
		}{
			{name: "default", manufacturer: "default", found: true},
			{name: "registered", manufacturer: "extra-0", found: true},
			{name: "missing", manufacturer: "missing"},
		} {
			cp := newBenchCrypto(b, extra)
			lookup := func() {
				_, err := cp.ByManufacturer(bc.manufacturer, "m")
				if (err == nil) != bc.found {
					b.Fatalf("lookup %s: %v", bc.manufacturer, err)
				}
			}
			b.Run(fmt.Sprintf("extra=%d/%s/serial", extra, bc.name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					lookup()
				}
			})
			b.Run(fmt.Sprintf("extra=%d/%s/parallel", extra, bc.name), func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						lookup()
					}
				})
			})
		}
	}
}

// BenchmarkByManufacturerWithAdd measures parallel lookups of a registered
// provider while one in every benchAddEvery operations adds a provider from a
// pool of benchAddPool: the first benchAddPool calls register new providers,
// later ones re-add a registered instance (a no-op), so the registry stays
// small, as it does in practice. It has no pre-fix baseline: the
// unsynchronized map write crashes the old code.
func BenchmarkByManufacturerWithAdd(b *testing.B) {
	pool := make([]*namedProvider, benchAddPool)
	for i := range pool {
		pool[i] = newNamedProvider(fmt.Sprintf("new-%d", i), "m")
	}
	cp := newBenchCrypto(b, 16)
	var adds atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		n := 0
		for pb.Next() {
			n++
			if n%benchAddEvery == 0 {
				p := pool[adds.Add(1)%benchAddPool]
				if err := cp.Add(p); err != nil {
					b.Fatal(err)
				}
				continue
			}
			if _, err := cp.ByManufacturer("extra-0", "m"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
