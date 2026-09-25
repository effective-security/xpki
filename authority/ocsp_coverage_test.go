package authority

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func ocspTestIssuer(t testing.TB) (*Issuer, *testca.Entity) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	entity := testca.NewEntity(testca.Subject(pkix.Name{CommonName: "OCSP issuer"}), testca.PrivateKey(key), testca.Authority, testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign))
	issuer, err := CreateIssuer(&IssuerConfig{
		Label: "ocsp-test",
		AIA:   &AIAConfig{OCSPExpiry: time.Hour},
	}, testca.ToPEM(entity.Certificate), nil, nil, key)
	require.NoError(t, err)
	return issuer, entity
}

func TestSignOCSPResponses(t *testing.T) {
	issuer, entity := ocspTestIssuer(t)
	thisUpdate := time.Now().UTC().Truncate(time.Second)
	nextUpdate := thisUpdate.Add(2 * time.Hour)
	revokedAt := thisUpdate.Add(-time.Hour)
	extension := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
		Value: []byte{5, 0},
	}
	for _, tc := range []struct {
		name, status string
		code         int
		hash         crypto.Hash
	}{
		{"good default hash", OCSPStatusGood, ocsp.Good, 0},
		{"revoked SHA256", OCSPStatusRevoked, ocsp.Revoked, crypto.SHA256},
		{"unknown SHA384", OCSPStatusUnknown, ocsp.Unknown, crypto.SHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := issuer.SignOCSP(&OCSPSignRequest{
				SerialNumber: big.NewInt(42),
				Status:       tc.status,
				Reason:       ocsp.KeyCompromise,
				RevokedAt:    revokedAt,
				IssuerHash:   tc.hash,
				ThisUpdate:   &thisUpdate,
				NextUpdate:   &nextUpdate,
				Extensions:   []pkix.Extension{extension},
			})
			require.NoError(t, err)
			response, err := ocsp.ParseResponse(der, entity.Certificate)
			require.NoError(t, err)
			assert.Equal(t, tc.code, response.Status)
			assert.Equal(t, big.NewInt(42), response.SerialNumber)
			assert.Equal(t, thisUpdate, response.ThisUpdate)
			assert.Equal(t, nextUpdate, response.NextUpdate)
			assert.Equal(t, []pkix.Extension{extension}, response.Extensions)
			assert.Nil(t, response.Certificate)
			if tc.code == ocsp.Revoked {
				assert.Equal(t, revokedAt, response.RevokedAt)
				assert.Equal(t, ocsp.KeyCompromise, response.RevocationReason)
			} else {
				assert.True(t, response.RevokedAt.IsZero())
			}
			hash := tc.hash
			if hash == 0 {
				hash = crypto.SHA1
			}
			assert.Equal(t, hash, response.IssuerHash)
		})
	}
	before := time.Now().Truncate(time.Minute)
	der, err := issuer.SignOCSP(&OCSPSignRequest{
		SerialNumber: big.NewInt(43),
		Status:       OCSPStatusGood,
	})
	require.NoError(t, err)
	response, err := ocsp.ParseResponse(der, entity.Certificate)
	require.NoError(t, err)
	assert.False(t, response.ThisUpdate.Before(before))
	assert.False(t, response.ThisUpdate.After(time.Now().Truncate(time.Minute)))
	assert.Equal(t, issuer.OcspExpiry(), response.NextUpdate.Sub(response.ThisUpdate))
	_, err = issuer.SignOCSP(&OCSPSignRequest{Status: "invalid"})
	require.EqualError(t, err, "invalid status: invalid")
	_, err = issuer.SignOCSP(&OCSPSignRequest{
		Status:       OCSPStatusGood,
		SerialNumber: big.NewInt(1),
		IssuerHash:   crypto.MD5,
	})
	require.ErrorContains(t, err, "unsupported")
}

func TestOCSPResponderReuse(t *testing.T) {
	issuer, entity := ocspTestIssuer(t)
	responder, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Same(t, entity.PrivateKey, responder.Signer)
	assert.True(t, entity.Certificate.Equal(responder.Cert))
	reused, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Same(t, responder, reused)

	// A valid cached delegated responder is reused and embedded in responses;
	// fresh creation and renewal are covered by ocsp_responder_test.go.
	delegated := entity.Issue(testca.Subject(pkix.Name{CommonName: "Delegated responder"}), testca.ExtKeyUsage(x509.ExtKeyUsageOCSPSigning), testca.KeyUsage(x509.KeyUsageDigitalSignature))
	issuer.cfg.AIA = &AIAConfig{DelegatedOCSPProfile: "ocsp"}
	cached := &OCSPResponder{
		Cert:   delegated.Certificate,
		Signer: delegated.PrivateKey,
	}
	issuer.delegated.Store(cached)
	reused, err = issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Same(t, cached, reused)
	der, err := issuer.SignOCSP(&OCSPSignRequest{
		Status:       OCSPStatusGood,
		SerialNumber: big.NewInt(44),
	})
	require.NoError(t, err)
	response, err := ocsp.ParseResponse(der, entity.Certificate)
	require.NoError(t, err)
	require.NotNil(t, response.Certificate)
	assert.True(t, delegated.Certificate.Equal(response.Certificate))
	assert.True(t, certutil.IsOCSPSigner(response.Certificate))
	require.NoError(t, response.CheckSignatureFrom(delegated.Certificate))
}
