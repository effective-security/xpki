package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/oid"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const (
	// ekuOCSPSigning and ekuServerAuth are DER extended key usage values.
	ekuOCSPSigning = "hex:300a06082b06010505070309"
	ekuServerAuth  = "hex:300a06082b06010505070301"

	delegatedProfile   = "ocsp"
	delegatedOCSPTTL   = time.Hour
	delegatedCertTTL   = 24 * time.Hour
	responderDeadline  = 10 * time.Second
	concurrentRequests = 32
)

var errSignerUnavailable = errors.New("signer unavailable")

// countingSigner counts CA signatures and fails them on demand. With gate
// set, each signature waits until the gate is closed.
type countingSigner struct {
	crypto.Signer
	fail  atomic.Bool
	calls atomic.Int32
	gate  chan struct{}
}

func (s *countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	if s.gate != nil {
		<-s.gate
	}
	if s.fail.Load() {
		return nil, errors.WithStack(errSignerUnavailable)
	}
	return s.Signer.Sign(r, digest, opts)
}

// delegatedTestIssuer returns an issuer with a delegated OCSP profile;
// caOpts are extra options for the CA certificate.
func delegatedTestIssuer(t testing.TB, caOpts ...testca.Option) (*Issuer, *testca.Entity, *countingSigner) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	opts := append([]testca.Option{
		testca.Subject(pkix.Name{CommonName: "Delegating issuer"}),
		testca.PrivateKey(key),
		testca.Authority,
		testca.KeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign),
	}, caOpts...)
	entity := testca.NewEntity(opts...)
	profile := &CertProfile{
		Usage:       []string{"digital signature", "ocsp signing"},
		Expiry:      csr.Duration(delegatedCertTTL),
		OCSPNoCheck: true,
	}
	require.NoError(t, profile.Validate())
	signer := &countingSigner{Signer: key}
	issuer, err := CreateIssuer(&IssuerConfig{
		Label: "delegating",
		AIA: &AIAConfig{
			OcspURL:              "http://localhost/ocsp",
			CrlURL:               "http://localhost/crl",
			OCSPExpiry:           delegatedOCSPTTL,
			DelegatedOCSPProfile: delegatedProfile,
		},
		Profiles: map[string]*CertProfile{
			delegatedProfile: profile,
		},
	}, testca.ToPEM(entity.Certificate), nil, nil, signer)
	require.NoError(t, err)
	return issuer, entity, signer
}

// responderWithin runs f with a deadline, so a deadlock (XPKI-051) fails
// the test instead of hanging the suite.
func responderWithin(t *testing.T, f func() (*OCSPResponder, error)) (*OCSPResponder, error) {
	t.Helper()
	type result struct {
		r   *OCSPResponder
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := f()
		done <- result{r, err}
	}()
	select {
	case res := <-done:
		return res.r, res.err
	case <-time.After(responderDeadline):
		t.Fatal("delegated OCSP responder creation did not return (XPKI-051)")
		return nil, nil
	}
}

// preload publishes a delegated responder issued by entity that expires at
// notAfter.
func preload(issuer *Issuer, entity *testca.Entity, notAfter time.Time) *OCSPResponder {
	cert := entity.Issue(
		testca.Subject(pkix.Name{CommonName: "Cached responder"}),
		testca.ExtKeyUsage(x509.ExtKeyUsageOCSPSigning),
		testca.KeyUsage(x509.KeyUsageDigitalSignature),
		testca.NotBefore(notAfter.Add(-delegatedCertTTL)),
		testca.NotAfter(notAfter),
	)
	r := &OCSPResponder{
		Cert:   cert.Certificate,
		Signer: cert.PrivateKey,
	}
	issuer.delegated.Store(r)
	return r
}

func signGood(issuer *Issuer, serial int64) ([]byte, error) {
	return issuer.SignOCSP(&OCSPSignRequest{
		SerialNumber: big.NewInt(serial),
		Status:       OCSPStatusGood,
	})
}

// assertDelegatedResponder checks a responder issued by the delegated profile.
func assertDelegatedResponder(t *testing.T, issuer *Issuer, r *OCSPResponder) {
	t.Helper()
	require.NotNil(t, r)
	require.NotSame(t, issuer.caResponder, r)
	assert.Equal(t, "OCSP Responder", r.Cert.Subject.CommonName)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, r.Cert.ExtKeyUsage)
	assert.True(t, certutil.HasOCSPNoCheck(r.Cert))
	assert.Empty(t, r.Cert.OCSPServer)
	assert.Empty(t, r.Cert.CRLDistributionPoints)
	assert.False(t, r.Cert.IsCA)
	require.NoError(t, r.Cert.CheckSignatureFrom(issuer.Bundle().Cert))
	assert.True(t, r.Cert.PublicKey.(*ecdsa.PublicKey).Equal(r.Signer.Public()))
	assert.True(t, time.Now().Add(issuer.OcspExpiry()).Before(r.Cert.NotAfter))
}

// parseDelegated parses a response and returns the embedded responder
// certificate after checking the response signature against it.
func parseDelegated(t *testing.T, der []byte, issuer *x509.Certificate) (*ocsp.Response, *x509.Certificate) {
	t.Helper()
	response, err := ocsp.ParseResponse(der, issuer)
	require.NoError(t, err)
	require.NotNil(t, response.Certificate)
	require.NoError(t, response.CheckSignatureFrom(response.Certificate))
	return response, response.Certificate
}

func TestDelegatedOCSPFreshCreation(t *testing.T) {
	t.Parallel()
	issuer, entity, signer := delegatedTestIssuer(t)

	r, err := responderWithin(t, issuer.CreateDelegatedOCSPSigner)
	require.NoError(t, err)
	assertDelegatedResponder(t, issuer, r)
	assert.Equal(t, int32(1), signer.calls.Load())

	reused, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Same(t, r, reused)
	assert.Equal(t, int32(1), signer.calls.Load())

	der, err := signGood(issuer, 44)
	require.NoError(t, err)
	response, cert := parseDelegated(t, der, entity.Certificate)
	assert.True(t, r.Cert.Equal(cert))
	assert.Equal(t, big.NewInt(44), response.SerialNumber)
	assert.Equal(t, delegatedOCSPTTL, response.NextUpdate.Sub(response.ThisUpdate))
}

func TestDelegatedOCSPFreshSignOCSP(t *testing.T) {
	t.Parallel()
	issuer, entity, _ := delegatedTestIssuer(t)

	var der []byte
	_, err := responderWithin(t, func() (*OCSPResponder, error) {
		var err error
		der, err = signGood(issuer, 45)
		return nil, err
	})
	require.NoError(t, err)
	_, cert := parseDelegated(t, der, entity.Certificate)
	current := issuer.delegated.Load()
	assertDelegatedResponder(t, issuer, current)
	assert.True(t, current.Cert.Equal(cert))
}

func TestDelegatedOCSPRenewal(t *testing.T) {
	t.Parallel()
	issuer, entity, signer := delegatedTestIssuer(t)
	// expires within the OCSP expiry interval, so it is due for renewal
	old := preload(issuer, entity, time.Now().Add(delegatedOCSPTTL/2))

	der, err := signGood(issuer, 46)
	require.NoError(t, err)
	_, cert := parseDelegated(t, der, entity.Certificate)
	renewed := issuer.delegated.Load()
	require.NotSame(t, old, renewed)
	assertDelegatedResponder(t, issuer, renewed)
	assert.True(t, renewed.Cert.Equal(cert))
	assert.Equal(t, int32(1), signer.calls.Load())
}

func TestDelegatedOCSPRenewalFailureUsesValidCache(t *testing.T) {
	t.Parallel()
	issuer, entity, signer := delegatedTestIssuer(t)
	notAfter := time.Now().Add(delegatedOCSPTTL / 2).Truncate(time.Second)
	old := preload(issuer, entity, notAfter)
	signer.fail.Store(true)

	// CreateDelegatedOCSPSigner reports the failure
	r, err := issuer.CreateDelegatedOCSPSigner()
	require.ErrorIs(t, err, errSignerUnavailable)
	assert.Contains(t, err.Error(), "delegated OCSP responder is not available: failed to sign OCSP responder")
	assert.Nil(t, r)
	assert.Equal(t, int32(1), signer.calls.Load())
	assert.Same(t, old, issuer.delegated.Load())

	// within the retry interval it keeps reporting it without an attempt
	_, again := issuer.CreateDelegatedOCSPSigner()
	assert.Equal(t, err.Error(), again.Error())
	assert.Equal(t, int32(1), signer.calls.Load())

	// SignOCSP uses the valid cached responder without another attempt
	// within the retry interval, and the response does not outlive it
	der, err := signGood(issuer, 47)
	require.NoError(t, err)
	response, cert := parseDelegated(t, der, entity.Certificate)
	assert.True(t, old.Cert.Equal(cert))
	assert.Equal(t, notAfter.UTC(), response.NextUpdate)
	assert.Equal(t, int32(1), signer.calls.Load())

	// after the retry interval SignOCSP tries again and still falls back
	later := time.Now().Add(ocspRenewRetryInterval + time.Second)
	r, err = issuer.delegatedResponder(later, true)
	require.NoError(t, err)
	assert.Same(t, old, r)
	assert.Equal(t, int32(2), signer.calls.Load())

	// once the signer recovers, the next attempt renews
	signer.fail.Store(false)
	r, err = issuer.delegatedResponder(later.Add(ocspRenewRetryInterval+time.Second), true)
	require.NoError(t, err)
	require.NotSame(t, old, r)
	assertDelegatedResponder(t, issuer, r)
	assert.Same(t, r, issuer.delegated.Load())
	assert.Equal(t, &ocspRenewal{}, issuer.renewal.Load())
	r2, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Same(t, r, r2)
}

func TestDelegatedOCSPFailureWithoutValidResponder(t *testing.T) {
	t.Parallel()
	t.Run("none cached", func(t *testing.T) {
		t.Parallel()
		issuer, _, signer := delegatedTestIssuer(t)
		signer.fail.Store(true)

		for range 2 {
			der, err := signGood(issuer, 48)
			require.ErrorIs(t, err, errSignerUnavailable)
			assert.Contains(t, err.Error(), "delegated OCSP responder is not available")
			assert.Nil(t, der)
		}
		// without a usable responder every request tries again
		assert.Equal(t, int32(2), signer.calls.Load())
		assert.Nil(t, issuer.delegated.Load())
	})
	t.Run("cache expired", func(t *testing.T) {
		t.Parallel()
		issuer, entity, signer := delegatedTestIssuer(t)
		old := preload(issuer, entity, time.Now().Add(delegatedOCSPTTL/2))
		signer.fail.Store(true)

		r, err := issuer.delegatedResponder(old.Cert.NotAfter, true)
		require.ErrorIs(t, err, errSignerUnavailable)
		assert.Nil(t, r)
		assert.Same(t, old, issuer.delegated.Load())
	})
}

func TestDelegatedOCSPResponderClipsNextUpdate(t *testing.T) {
	t.Parallel()
	issuer, entity, _ := delegatedTestIssuer(t)
	r, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	notAfter := r.Cert.NotAfter.UTC()

	thisUpdate := time.Now().UTC().Truncate(time.Second)
	nextUpdate := notAfter.Add(time.Hour)
	der, err := issuer.SignOCSP(&OCSPSignRequest{
		SerialNumber: big.NewInt(49),
		Status:       OCSPStatusGood,
		ThisUpdate:   &thisUpdate,
		NextUpdate:   &nextUpdate,
	})
	require.NoError(t, err)
	response, _ := parseDelegated(t, der, entity.Certificate)
	assert.Equal(t, notAfter, response.NextUpdate)

	late := notAfter
	der, err = issuer.SignOCSP(&OCSPSignRequest{
		SerialNumber: big.NewInt(49),
		Status:       OCSPStatusGood,
		ThisUpdate:   &late,
	})
	require.EqualError(t, err, "delegated OCSP responder expires at "+notAfter.Format(time.RFC3339)+
		", before thisUpdate "+notAfter.Format(time.RFC3339))
	assert.Nil(t, der)
}

func TestDelegatedOCSPShortLivedResponderIsNotReissued(t *testing.T) {
	t.Parallel()
	// the CA expires within the OCSP expiry interval, so Sign caps every
	// responder at the CA's NotAfter and it is due for renewal when issued
	caNotAfter := time.Now().Add(delegatedOCSPTTL / 2).Truncate(time.Second)
	issuer, entity, signer := delegatedTestIssuer(t, testca.NotAfter(caNotAfter))

	first, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Equal(t, caNotAfter.UTC(), first.Cert.NotAfter)
	again, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Same(t, first, again)

	der, err := signGood(issuer, 50)
	require.NoError(t, err)
	response, _ := parseDelegated(t, der, entity.Certificate)
	assert.Equal(t, first.Cert.NotAfter.UTC(), response.NextUpdate)
	assert.Equal(t, int32(1), signer.calls.Load())
}

func TestDelegatedOCSPWaitersShareFailure(t *testing.T) {
	t.Parallel()
	issuer, _, signer := delegatedTestIssuer(t)
	signer.gate = make(chan struct{})
	signer.fail.Store(true)
	// counts callers that have read the pre-failure renewal state and are
	// about to wait for renewLock
	var waiting sync.WaitGroup
	waiting.Add(concurrentRequests + 1)
	issuer.renewWaitHook = waiting.Done

	// the first caller holds renewLock inside the failing CA signature
	first := make(chan error, 1)
	go func() {
		_, err := signGood(issuer, 51)
		first <- err
	}()
	require.Eventually(t, func() bool { return signer.calls.Load() == 1 }, responderDeadline, time.Millisecond)

	// the others queue for renewLock with no usable responder; the failure
	// is published only after all of them have read the prior state
	var wg sync.WaitGroup
	errs := make([]error, concurrentRequests)
	for i := range concurrentRequests {
		wg.Go(func() {
			_, errs[i] = signGood(issuer, int64(200+i))
		})
	}
	waiting.Wait()
	close(signer.gate)
	wg.Wait()

	require.ErrorIs(t, <-first, errSignerUnavailable)
	for i, err := range errs {
		require.ErrorIs(t, err, errSignerUnavailable, "request %d", i)
		assert.Contains(t, err.Error(), "delegated OCSP responder is not available")
	}
	// the waiters share the failure instead of retrying one after another
	assert.Equal(t, int32(1), signer.calls.Load())
}

func TestCreateIssuerDelegatedOCSPProfile(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	entity := testca.NewEntity(testca.PrivateKey(key), testca.Authority, testca.KeyUsage(x509.KeyUsageCertSign))
	for _, tc := range []struct {
		name      string
		profile   *CertProfile
		err       string
		errPrefix string
	}{
		{
			name: "missing",
			err:  `issuer "ca": delegated_ocsp_profile "ocsp" not found`,
		},
		{
			name: "no ocsp signing",
			profile: &CertProfile{
				Usage:  []string{"digital signature", "server auth"},
				Expiry: csr.Duration(delegatedCertTTL),
			},
			err: `issuer "ca": delegated_ocsp_profile "ocsp" extended key usage must include "ocsp signing"`,
		},
		{
			name: "EKU extension without ocsp signing",
			profile: &CertProfile{
				Usage:  []string{"ocsp signing"},
				Expiry: csr.Duration(delegatedCertTTL),
				Extensions: []csr.X509Extension{
					{
						ID:    csr.OID(oid.ExtensionExtendedKeyUsage),
						Value: ekuServerAuth,
					},
				},
			},
			err: `issuer "ca": delegated_ocsp_profile "ocsp" extended key usage must include "ocsp signing"`,
		},
		{
			name: "malformed EKU extension",
			profile: &CertProfile{
				Usage:  []string{"ocsp signing"},
				Expiry: csr.Duration(delegatedCertTTL),
				Extensions: []csr.X509Extension{
					{
						ID:    csr.OID(oid.ExtensionExtendedKeyUsage),
						Value: "hex:0102",
					},
				},
			},
			// the asn1 detail that follows is not part of the contract
			errPrefix: `issuer "ca": delegated_ocsp_profile "ocsp": invalid extended key usage extension: asn1: `,
		},
		{
			name: "CA profile",
			profile: &CertProfile{
				Usage:        []string{"ocsp signing", "cert sign"},
				Expiry:       csr.Duration(delegatedCertTTL),
				CAConstraint: CAConstraint{IsCA: true},
			},
			err: `issuer "ca": delegated_ocsp_profile "ocsp" must not be a CA profile`,
		},
		{
			name: "expiry equals ocsp_expiry",
			profile: &CertProfile{
				Usage:  []string{"ocsp signing"},
				Expiry: csr.Duration(delegatedOCSPTTL),
			},
			err: `issuer "ca": delegated_ocsp_profile "ocsp" expiry 1h0m0s must exceed ocsp_expiry 1h0m0s + backdate 5m0s + 1m0s`,
		},
		{
			// NotBefore is backdated, so this responder would be due for
			// renewal when issued
			name: "expiry just above ocsp_expiry",
			profile: &CertProfile{
				Usage:  []string{"ocsp signing"},
				Expiry: csr.Duration(delegatedOCSPTTL + time.Second),
			},
			err: `issuer "ca": delegated_ocsp_profile "ocsp" expiry 1h0m1s must exceed ocsp_expiry 1h0m0s + backdate 5m0s + 1m0s`,
		},
		{
			name: "expiry at the backdate bound",
			profile: &CertProfile{
				Usage:  []string{"ocsp signing"},
				Expiry: csr.Duration(delegatedOCSPTTL + defaultBackdate + delegatedValidityMargin),
			},
			err: `issuer "ca": delegated_ocsp_profile "ocsp" expiry 1h6m0s must exceed ocsp_expiry 1h0m0s + backdate 5m0s + 1m0s`,
		},
		{
			name: "explicit backdate",
			profile: &CertProfile{
				Usage:    []string{"ocsp signing"},
				Expiry:   csr.Duration(delegatedOCSPTTL + 10*time.Minute),
				Backdate: csr.Duration(30 * time.Minute),
			},
			err: `issuer "ca": delegated_ocsp_profile "ocsp" expiry 1h10m0s must exceed ocsp_expiry 1h0m0s + backdate 30m0s + 1m0s`,
		},
		{
			name: "explicit EKU extension",
			profile: &CertProfile{
				Usage:  []string{"digital signature"},
				Expiry: csr.Duration(delegatedCertTTL),
				Extensions: []csr.X509Extension{
					{
						ID:    csr.OID(oid.ExtensionExtendedKeyUsage),
						Value: ekuOCSPSigning,
					},
				},
			},
		},
		{
			name: "shortest valid expiry",
			profile: &CertProfile{
				Usage:       []string{"ocsp signing"},
				Expiry:      csr.Duration(delegatedOCSPTTL + defaultBackdate + delegatedValidityMargin + time.Second),
				OCSPNoCheck: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			profiles := map[string]*CertProfile{}
			if tc.profile != nil {
				profiles[delegatedProfile] = tc.profile
			}
			issuer, err := CreateIssuer(&IssuerConfig{
				Label: "ca",
				AIA: &AIAConfig{
					OCSPExpiry:           delegatedOCSPTTL,
					DelegatedOCSPProfile: delegatedProfile,
				},
				Profiles: profiles,
			}, testca.ToPEM(entity.Certificate), nil, nil, key)
			switch {
			case tc.errPrefix != "":
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tc.errPrefix), err.Error())
			case tc.err != "":
				require.EqualError(t, err, tc.err)
			default:
				require.NoError(t, err)
				// the first responder is not due for renewal
				r, err := issuer.CreateDelegatedOCSPSigner()
				require.NoError(t, err)
				assert.True(t, validFor(r, time.Now().Add(delegatedOCSPTTL)), r.Cert.NotAfter)
				assert.Equal(t, &ocspRenewal{}, issuer.renewal.Load())
			}
		})
	}
}

func TestDelegatedOCSPRawEKUProfile(t *testing.T) {
	t.Parallel()
	issuer, entity, _ := delegatedTestIssuer(t)
	// the OCSP signing EKU comes only from a raw profile extension
	profile := &CertProfile{
		Usage:       []string{"digital signature"},
		Expiry:      csr.Duration(delegatedCertTTL),
		OCSPNoCheck: true,
		Extensions: []csr.X509Extension{
			{
				ID:    csr.OID(oid.ExtensionExtendedKeyUsage),
				Value: ekuOCSPSigning,
			},
		},
	}
	require.NoError(t, profile.Validate())
	issuer.AddProfile(delegatedProfile, profile)

	r, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	// recognized as a responder: no AIA OCSP/CRL URLs
	assertDelegatedResponder(t, issuer, r)
	der, err := signGood(issuer, 52)
	require.NoError(t, err)
	_, cert := parseDelegated(t, der, entity.Certificate)
	assert.True(t, r.Cert.Equal(cert))
}

func TestDelegatedOCSPReplacedProfileIsRevalidated(t *testing.T) {
	t.Parallel()
	issuer, entity, signer := delegatedTestIssuer(t)
	old := preload(issuer, entity, time.Now().Add(delegatedOCSPTTL/2))

	// a valid profile, but not one that can issue a delegated responder
	replacement := &CertProfile{
		Usage:  []string{"digital signature", "server auth"},
		Expiry: csr.Duration(delegatedCertTTL),
	}
	require.NoError(t, replacement.Validate())
	issuer.AddProfile(delegatedProfile, replacement)

	r, err := issuer.CreateDelegatedOCSPSigner()
	require.EqualError(t, err, `delegated OCSP responder is not available: delegated_ocsp_profile "ocsp" extended key usage must include "ocsp signing"`)
	assert.Nil(t, r)
	// rejected before signing anything
	assert.Equal(t, int32(0), signer.calls.Load())

	// SignOCSP keeps using the still-valid cached responder
	der, err := signGood(issuer, 53)
	require.NoError(t, err)
	_, cert := parseDelegated(t, der, entity.Certificate)
	assert.True(t, old.Cert.Equal(cert))
}

func TestDelegatedOCSPSlowFailureAfterExpiry(t *testing.T) {
	t.Parallel()
	issuer, entity, signer := delegatedTestIssuer(t)
	old := preload(issuer, entity, time.Now().Add(delegatedOCSPTTL/2))
	signer.fail.Store(true)
	signer.gate = make(chan struct{})
	const signDelay = 100 * time.Millisecond
	time.AfterFunc(signDelay, func() { close(signer.gate) })

	// valid when the attempt starts, expired when the slow failure returns
	now := old.Cert.NotAfter.Add(-signDelay / 2)
	r, err := issuer.delegatedResponder(now, true)
	require.ErrorIs(t, err, errSignerUnavailable)
	assert.Nil(t, r)
	assert.Equal(t, int32(1), signer.calls.Load())
	// the retry interval starts when the attempt ended
	retryAt := issuer.renewal.Load().retryAt
	assert.False(t, retryAt.Before(now.Add(signDelay+ocspRenewRetryInterval)), retryAt)
}

// runConcurrent starts n goroutines released together and returns their
// OCSP responses.
func runConcurrent(t *testing.T, issuer *Issuer, n int, extra func()) [][]byte {
	t.Helper()
	start := make(chan struct{})
	responses := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			responses[i], errs[i] = signGood(issuer, int64(100+i))
		})
	}
	if extra != nil {
		wg.Go(func() {
			<-start
			extra()
		})
	}
	close(start)
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i], "request %d", i)
	}
	return responses
}

func TestDelegatedOCSPConcurrentColdStart(t *testing.T) {
	t.Parallel()
	issuer, entity, signer := delegatedTestIssuer(t)

	responses := runConcurrent(t, issuer, concurrentRequests, nil)
	current := issuer.delegated.Load()
	assertDelegatedResponder(t, issuer, current)
	for _, der := range responses {
		_, cert := parseDelegated(t, der, entity.Certificate)
		assert.True(t, current.Cert.Equal(cert))
	}
	// exactly one responder issued
	assert.Equal(t, int32(1), signer.calls.Load())
}

func TestDelegatedOCSPConcurrentRenewal(t *testing.T) {
	t.Parallel()
	issuer, entity, signer := delegatedTestIssuer(t)
	old := preload(issuer, entity, time.Now().Add(delegatedOCSPTTL/2))

	// profile registration overlaps the renewal's profile lookup
	responses := runConcurrent(t, issuer, concurrentRequests, func() {
		issuer.AddProfile("extra", &CertProfile{})
	})
	renewed := issuer.delegated.Load()
	require.NotSame(t, old, renewed)
	assertDelegatedResponder(t, issuer, renewed)
	for _, der := range responses {
		_, cert := parseDelegated(t, der, entity.Certificate)
		assert.True(t, cert.Equal(old.Cert) || cert.Equal(renewed.Cert))
	}
	assert.Equal(t, int32(1), signer.calls.Load())
	assert.NotNil(t, issuer.Profile("extra"))
}

func TestCAResponderConcurrent(t *testing.T) {
	t.Parallel()
	issuer, entity := ocspTestIssuer(t)

	responses := runConcurrent(t, issuer, concurrentRequests, nil)
	for _, der := range responses {
		response, err := ocsp.ParseResponse(der, entity.Certificate)
		require.NoError(t, err)
		assert.Nil(t, response.Certificate)
	}
	r, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Same(t, issuer.caResponder, r)
}
