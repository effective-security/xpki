package testca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	concurrentWorkers = 32
	serialsPerWorker  = 8
	firstSerial       = int64(123)
	spareOptionName   = "unused subject option"
)

func TestConcurrentDefaultNames(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	entities := make([]*testca.Entity, concurrentWorkers)

	runConcurrent(concurrentWorkers, func(i int) {
		entities[i] = testca.NewEntity(testca.PrivateKey(key))
	})

	names := make(map[string]struct{}, len(entities))
	for _, entity := range entities {
		name := entity.Certificate.Subject.CommonName
		assert.True(t, name == testca.DefaultCommonName || strings.HasPrefix(name, testca.DefaultCommonName+" #"), "unexpected default name: %q", name)
		assert.NotContains(t, names, name, "duplicate default name")
		names[name] = struct{}{}
		err := entity.Certificate.CheckSignature(entity.Certificate.SignatureAlgorithm, entity.Certificate.RawTBSCertificate, entity.Certificate.Signature)
		require.NoError(t, err)
	}
}

func TestConcurrentSerialNumbers(t *testing.T) {
	for _, start := range []int64{0, firstSerial} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			issuer := &testca.Entity{
				NextSN: start,
			}
			serials := make([]int64, concurrentWorkers*serialsPerWorker)
			runConcurrent(concurrentWorkers, func(worker int) {
				for i := range serialsPerWorker {
					serials[worker*serialsPerWorker+i] = issuer.IncrementSN()
				}
			})

			expected := make([]int64, len(serials))
			for i := range expected {
				expected[i] = start + int64(i)
			}
			assert.ElementsMatch(t, expected, serials)
			assert.Equal(t, start+int64(len(serials)), issuer.NextSN)

			// Direct field access remains supported when no calls are in flight.
			issuer.NextSN = firstSerial
			assert.Equal(t, firstSerial, issuer.IncrementSN())
			assert.Equal(t, firstSerial+1, issuer.NextSN)
		})
	}
}

func TestConcurrentIssue(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer := testca.NewEntity(
		testca.Authority,
		testca.PrivateKey(issuerKey),
		testca.NextSerialNumber(firstSerial),
	)
	entities := make([]*testca.Entity, concurrentWorkers)
	// Reuse read-only options with spare capacity to catch writes by Issue.
	options := []testca.Option{
		testca.PrivateKey(leafKey),
		testca.Issuer(nil),
		testca.Subject(pkix.Name{CommonName: spareOptionName}),
	}
	runConcurrent(concurrentWorkers, func(i int) {
		entities[i] = issuer.Issue(options[:2]...)
	})

	serials := make([]int64, len(entities))
	expected := make([]int64, len(entities))
	names := make(map[string]struct{}, len(entities))
	for i, entity := range entities {
		assert.Same(t, issuer, entity.Issuer)
		err := entity.Certificate.CheckSignatureFrom(issuer.Certificate)
		require.NoError(t, err)
		serials[i] = entity.Certificate.SerialNumber.Int64()
		expected[i] = firstSerial + int64(i)
		name := entity.Certificate.Subject.CommonName
		assert.NotContains(t, names, name, "duplicate issued name")
		names[name] = struct{}{}
	}
	assert.ElementsMatch(t, expected, serials)
	assert.Equal(t, firstSerial+int64(len(entities)), issuer.NextSN)

	// The unused option must still apply when the caller uses its full slice.
	probe := testca.NewEntity(options...)
	assert.Equal(t, spareOptionName, probe.Certificate.Subject.CommonName)
	assert.Nil(t, probe.Issuer)
}

// Release all workers together so the tested reads and writes overlap.
func runConcurrent(workers int, fn func(int)) {
	var ready, done sync.WaitGroup
	ready.Add(workers)
	done.Add(workers)
	start := make(chan struct{})
	for i := range workers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			fn(i)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
}
