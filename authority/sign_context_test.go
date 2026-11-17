package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/effective-security/xpki/v2/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shortWait bounds a caller that is expected to give up on its context.
const shortWait = 50 * time.Millisecond

// cancelledContext returns a context of t that is already cancelled.
func cancelledContext(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

func TestIssuerSignCancelled(t *testing.T) {
	t.Parallel()
	issuer, _, signer := delegatedTestIssuer(t)
	ctx := cancelledContext(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, _, err = issuer.Sign(ctx, csr.SignRequest{
		Request: policyCSR(t, key, nil),
		Profile: delegatedProfile,
	})
	require.ErrorIs(t, err, context.Canceled)
	_, err = issuer.SignProof(ctx, []byte("proof"))
	require.ErrorIs(t, err, context.Canceled)
	_, err = issuer.SignOCSP(ctx, &OCSPSignRequest{SerialNumber: big.NewInt(1), Status: OCSPStatusGood})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(0), signer.calls.Load(), "the CA key signed with a cancelled context")
	assert.Nil(t, issuer.renewal.Load(), "a renewal started for a cancelled caller")

	proof, err := issuer.SignProof(t.Context(), []byte("proof"))
	require.NoError(t, err)
	require.NoError(t, issuer.VerifyProof([]byte("proof"), proof))
}

// TestDelegatedOCSPRenewalOutlivesCaller checks that a caller that leaves
// while it waits for a renewal does not fail the renewal: it completes, is
// published, and the next caller gets it without another CA signature.
func TestDelegatedOCSPRenewalOutlivesCaller(t *testing.T) {
	t.Parallel()
	issuer, _, signer := delegatedTestIssuer(t)
	signer.gate = make(chan struct{})
	signer.entered = make(chan struct{})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := issuer.CreateDelegatedOCSPSigner(ctx)
		done <- err
	}()
	select {
	case <-signer.entered:
	case <-time.After(responderDeadline):
		t.Fatal("the renewal did not reach the CA signer")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		assert.Contains(t, err.Error(), "delegated OCSP responder is not available")
	case <-time.After(responderDeadline):
		t.Fatal("the cancelled caller did not return")
	}

	close(signer.gate)
	r, err := responderWithin(t, issuer.CreateDelegatedOCSPSigner)
	require.NoError(t, err)
	assertDelegatedResponder(t, issuer, r)
	assert.Equal(t, int32(1), signer.calls.Load(), "the renewal was started again")
	assert.Equal(t, &ocspRenewal{}, issuer.renewal.Load())
}

// TestDelegatedOCSPSlowRenewalShortDeadlines checks that requests whose
// deadline is shorter than a renewal keep signing with the valid cached
// responder while one renewal runs, and that the renewal is not restarted
// by each of them.
func TestDelegatedOCSPSlowRenewalShortDeadlines(t *testing.T) {
	t.Parallel()
	issuer, entity, signer := delegatedTestIssuer(t)
	// valid, but due for renewal
	old := preload(issuer, entity, time.Now().Add(delegatedOCSPTTL/2))
	signer.gate = make(chan struct{})

	var running *ocspRenewCall
	for i := range 5 {
		ctx, cancel := context.WithTimeout(t.Context(), shortWait)
		der, err := signGood(ctx, issuer, int64(300+i))
		cancel()
		require.NoError(t, err, "request %d", i)
		_, cert := parseDelegated(t, der, entity.Certificate)
		assert.True(t, old.Cert.Equal(cert), "request %d", i)
		if i == 0 {
			running = issuer.renewing.Load()
			require.NotNil(t, running)
		}
		assert.Same(t, running, issuer.renewing.Load(), "request %d started another renewal", i)
	}
	require.Eventually(t, func() bool { return signer.calls.Load() == 1 }, responderDeadline, time.Millisecond, "each request restarted the renewal")

	close(signer.gate)
	require.Eventually(t, func() bool { return issuer.renewing.Load() == nil }, responderDeadline, time.Millisecond)
	assert.NotSame(t, old, issuer.delegated.Load())
	assertDelegatedResponder(t, issuer, issuer.delegated.Load())
	assert.Equal(t, int32(1), signer.calls.Load())
}

// TestDelegatedOCSPWaiterDeadline checks that a caller queued behind a
// renewal blocked on the CA signer leaves when its context ends, and that
// the renewal in progress is not affected.
func TestDelegatedOCSPWaiterDeadline(t *testing.T) {
	t.Parallel()
	issuer, _, signer := delegatedTestIssuer(t)
	signer.gate = make(chan struct{})
	signer.entered = make(chan struct{})

	first := make(chan error, 1)
	go func() {
		_, err := issuer.CreateDelegatedOCSPSigner(t.Context())
		first <- err
	}()
	select {
	case <-signer.entered:
	case <-time.After(responderDeadline):
		t.Fatal("the renewal did not reach the CA signer")
	}

	ctx, cancel := context.WithTimeout(t.Context(), shortWait)
	defer cancel()
	_, err := issuer.SignOCSP(ctx, &OCSPSignRequest{SerialNumber: big.NewInt(2), Status: OCSPStatusGood})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "delegated OCSP responder is not available")

	close(signer.gate)
	select {
	case err := <-first:
		require.NoError(t, err)
	case <-time.After(responderDeadline):
		t.Fatal("the renewal did not finish")
	}
	assert.NotNil(t, issuer.delegated.Load())
	assert.Equal(t, int32(1), signer.calls.Load())
}
