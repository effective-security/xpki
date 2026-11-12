package certutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const (
	// ocspVectorSerial is the serial number of the OpenSSL OCSP vectors.
	ocspVectorSerial = 0x1001
	// ocspTestSerial is the serial number of the generated responses.
	ocspTestSerial = 4242
)

// ocspTemplate returns a response template for status.
func ocspTemplate(status int) ocsp.Response {
	now := time.Now().UTC().Truncate(time.Minute)
	template := ocsp.Response{
		Status:       status,
		SerialNumber: big.NewInt(ocspTestSerial),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	}
	if status == ocsp.Revoked {
		template.RevokedAt = now.Add(-time.Hour)
		template.RevocationReason = ocsp.KeyCompromise
	}
	return template
}

// mldsaCA returns a CA whose key is ML-DSA of params.
func mldsaCA(t *testing.T, params mldsa.Parameters) (*testca.Entity, crypto.Signer) {
	t.Helper()
	key, err := mldsa.GenerateKey(params)
	require.NoError(t, err)
	return testca.NewEntity(testca.Authority, testca.PrivateKey(key), testca.KeyUsage(x509.KeyUsageCertSign)), key
}

// TestCreateOCSPResponseMLDSA signs direct and delegated responses for every
// parameter set and status, and reads them back.
func TestCreateOCSPResponseMLDSA(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		params mldsa.Parameters
		algo   x509.SignatureAlgorithm
	}{
		{mldsa.MLDSA44(), x509.MLDSA44},
		{mldsa.MLDSA65(), x509.MLDSA65},
		{mldsa.MLDSA87(), x509.MLDSA87},
	} {
		t.Run(tc.params.String(), func(t *testing.T) {
			t.Parallel()
			ca, caKey := mldsaCA(t, tc.params)

			for _, status := range []int{ocsp.Good, ocsp.Revoked, ocsp.Unknown} {
				template := ocspTemplate(status)
				der, err := certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template, caKey)
				require.NoError(t, err)

				res, err := certutil.ParseOCSPResponse(der, ca.Certificate)
				require.NoError(t, err)
				assert.Equal(t, status, res.Status)
				assert.Equal(t, tc.algo, res.SignatureAlgorithm)
				assert.Equal(t, template.SerialNumber, res.SerialNumber)
				assert.True(t, template.ThisUpdate.Equal(res.ThisUpdate))
				assert.True(t, template.NextUpdate.Equal(res.NextUpdate))
				assert.Equal(t, der, res.Raw)
				assert.Nil(t, res.Certificate)
				assert.Equal(t, crypto.SHA1, res.IssuerHash, "the x/crypto default")
				assert.Equal(t, ca.Certificate.RawSubject, res.RawResponderName)
				require.NoError(t, res.CheckSignatureFrom(ca.Certificate))
				if status == ocsp.Revoked {
					assert.Equal(t, ocsp.KeyCompromise, res.RevocationReason)
					assert.True(t, template.RevokedAt.Equal(res.RevokedAt))
				}

				// the encoding is what x/crypto reads, without verification
				plain, err := ocsp.ParseResponse(der, nil)
				require.NoError(t, err)
				assert.Equal(t, status, plain.Status)
				assert.Equal(t, res.TBSResponseData, plain.TBSResponseData)
				assert.Equal(t, res.Signature, plain.Signature)
				assert.Equal(t, x509.UnknownSignatureAlgorithm, plain.SignatureAlgorithm)
				// x/crypto cannot verify ML-DSA; if this starts to pass, the
				// local path can go
				_, err = ocsp.ParseResponse(der, ca.Certificate)
				require.ErrorContains(t, err, "bad OCSP signature")
			}

			// a delegated responder of another parameter set, embedded
			responderKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
			require.NoError(t, err)
			responder := ca.Issue(testca.PrivateKey(responderKey), testca.ExtKeyUsage(x509.ExtKeyUsageOCSPSigning))
			template := ocspTemplate(ocsp.Good)
			template.Certificate = responder.Certificate
			template.IssuerHash = crypto.SHA256
			// the parameter set fixes the algorithm, whatever the template says
			template.SignatureAlgorithm = x509.ECDSAWithSHA256
			der, err := certutil.CreateOCSPResponse(ca.Certificate, responder.Certificate, template, responderKey)
			require.NoError(t, err)

			res, err := certutil.ParseOCSPResponse(der, ca.Certificate)
			require.NoError(t, err)
			assert.Equal(t, x509.MLDSA44, res.SignatureAlgorithm)
			assert.Equal(t, crypto.SHA256, res.IssuerHash)
			require.NotNil(t, res.Certificate)
			assert.True(t, responder.Certificate.Equal(res.Certificate))
			assert.Equal(t, responder.Certificate.RawSubject, res.RawResponderName)

			// without an issuer only the embedded certificate is checked
			res, err = certutil.ParseOCSPResponse(der, nil)
			require.NoError(t, err)
			require.NotNil(t, res.Certificate)

			// x/crypto checks an embedded certificate even with no issuer
			_, err = ocsp.ParseResponse(der, nil)
			require.ErrorContains(t, err, "bad signature on embedded certificate")
		})
	}
}

// TestCreateOCSPResponseClassical keeps the x/crypto path for classical keys:
// the response reads with both parsers, also when an ML-DSA CA certifies an
// ECDSA responder.
func TestCreateOCSPResponseClassical(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testca.NewEntity(testca.Authority, testca.PrivateKey(ecKey), testca.KeyUsage(x509.KeyUsageCertSign))
	der, err := certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, ocspTemplate(ocsp.Good), ecKey)
	require.NoError(t, err)
	res, err := certutil.ParseOCSPResponse(der, ca.Certificate)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA256, res.SignatureAlgorithm)
	_, err = ocsp.ParseResponse(der, ca.Certificate)
	require.NoError(t, err)

	pqCA, _ := mldsaCA(t, mldsa.MLDSA65())
	responderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	responder := pqCA.Issue(testca.PrivateKey(responderKey), testca.ExtKeyUsage(x509.ExtKeyUsageOCSPSigning))
	template := ocspTemplate(ocsp.Good)
	template.Certificate = responder.Certificate
	der, err = certutil.CreateOCSPResponse(pqCA.Certificate, responder.Certificate, template, responderKey)
	require.NoError(t, err)
	res, err = certutil.ParseOCSPResponse(der, pqCA.Certificate)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA256, res.SignatureAlgorithm)
	require.NotNil(t, res.Certificate)
	assert.Equal(t, x509.MLDSA65, res.Certificate.SignatureAlgorithm)
}

// failingSigner is a signer whose backend fails, like a KMS key.
type failingSigner struct {
	pub crypto.PublicKey
}

func (s failingSigner) Public() crypto.PublicKey { return s.pub }

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("backend failed")
}

// TestCreateOCSPResponseErrors covers invalid arguments and signer failures.
func TestCreateOCSPResponseErrors(t *testing.T) {
	t.Parallel()
	ca, key := mldsaCA(t, mldsa.MLDSA44())
	template := ocspTemplate(ocsp.Good)

	_, err := certutil.CreateOCSPResponse(nil, ca.Certificate, template, key)
	require.EqualError(t, err, "issuer certificate is nil")
	_, err = certutil.CreateOCSPResponse(ca.Certificate, nil, template, key)
	require.EqualError(t, err, "responder certificate is nil")
	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template, nil)
	require.EqualError(t, err, "signer is nil")

	// keys that must fail, not panic: crypto/mldsa panics on them
	var nilKey *mldsa.PrivateKey
	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template, nilKey)
	require.EqualError(t, err, "signer is nil")
	var nilECKey *ecdsa.PrivateKey
	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template, nilECKey)
	require.EqualError(t, err, "signer is nil")
	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template, &mldsa.PrivateKey{})
	require.EqualError(t, err, "invalid ML-DSA private key")
	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template,
		failingSigner{pub: &mldsa.PublicKey{}})
	require.EqualError(t, err, "invalid ML-DSA public key")

	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template,
		failingSigner{pub: key.Public()})
	require.EqualError(t, err, "unable to sign the OCSP response: backend failed")

	// x/crypto signs for a classical key, so its error comes from the signer
	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template,
		failingSigner{pub: mustECDSAPublic(t)})
	require.ErrorContains(t, err, "backend failed")
	require.NotContains(t, err.Error(), "unable to sign the OCSP response")

	// a key type neither path signs with
	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, template,
		failingSigner{pub: "not a key"})
	require.ErrorContains(t, err, "only RSA and ECDSA keys supported")

	bad := template
	bad.SerialNumber = nil
	_, err = certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, bad, key)
	require.Error(t, err, "x/crypto cannot encode a nil serial number")
}

func mustECDSAPublic(t *testing.T) crypto.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key.Public()
}

// asn1 mirrors of the OCSP structures, to build hostile responses
type testResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type testOCSPResponse struct {
	Status   asn1.Enumerated
	Response testResponseBytes `asn1:"explicit,tag:0,optional"`
}

type testBasicResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// rewriteOCSP decodes a response, lets change modify the basic response and
// encodes it again.
func rewriteOCSP(t *testing.T, der []byte, change func(*testBasicResponse)) []byte {
	t.Helper()
	outer := decodeTestOCSP(t, der)
	basic := decodeTestBasic(t, &outer)
	change(&basic)
	var err error
	outer.Response.Response, err = asn1.Marshal(basic)
	require.NoError(t, err)
	res, err := asn1.Marshal(outer)
	require.NoError(t, err)
	return res
}

func decodeTestOCSP(t *testing.T, der []byte) testOCSPResponse {
	t.Helper()
	var outer testOCSPResponse
	rest, err := asn1.Unmarshal(der, &outer)
	require.NoError(t, err)
	require.Empty(t, rest)
	return outer
}

func decodeTestBasic(t *testing.T, outer *testOCSPResponse) testBasicResponse {
	t.Helper()
	var basic testBasicResponse
	rest, err := asn1.Unmarshal(outer.Response.Response, &basic)
	require.NoError(t, err)
	require.Empty(t, rest)
	return basic
}

// TestParseOCSPResponseRejects covers responses that must not verify.
func TestParseOCSPResponseRejects(t *testing.T) {
	t.Parallel()
	ca, key := mldsaCA(t, mldsa.MLDSA65())
	other, _ := mldsaCA(t, mldsa.MLDSA65())
	otherParams, _ := mldsaCA(t, mldsa.MLDSA87())
	ecCA := testca.NewEntity(testca.Authority)

	direct, err := certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, ocspTemplate(ocsp.Good), key)
	require.NoError(t, err)

	responderKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	responder := ca.Issue(testca.PrivateKey(responderKey), testca.ExtKeyUsage(x509.ExtKeyUsageOCSPSigning))
	template := ocspTemplate(ocsp.Good)
	template.Certificate = responder.Certificate
	delegated, err := certutil.CreateOCSPResponse(ca.Certificate, responder.Certificate, template, responderKey)
	require.NoError(t, err)

	// the failure is an ocsp.ParseError, as x/crypto reports a classical one
	requireBadSignature := func(der []byte, issuer *x509.Certificate) {
		t.Helper()
		_, err := certutil.ParseOCSPResponse(der, issuer)
		require.ErrorContains(t, err, "bad OCSP signature")
		var parseErr ocsp.ParseError
		require.ErrorAs(t, err, &parseErr)
	}

	for _, issuer := range []*testca.Entity{other, otherParams, ecCA} {
		requireBadSignature(direct, issuer.Certificate)
		// a responder the issuer did not certify
		requireBadSignature(delegated, issuer.Certificate)
	}

	flipped := rewriteOCSP(t, direct, func(b *testBasicResponse) {
		b.Signature.Bytes[0] ^= 0xFF
	})
	requireBadSignature(flipped, ca.Certificate)

	// the signed data of another response, so the fields parse and differ
	otherTemplate := ocspTemplate(ocsp.Revoked)
	otherDirect, err := certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, otherTemplate, key)
	require.NoError(t, err)
	otherOuter := decodeTestOCSP(t, otherDirect)
	otherBasic := decodeTestBasic(t, &otherOuter)
	swappedTBS := rewriteOCSP(t, direct, func(b *testBasicResponse) {
		b.TBSResponseData = otherBasic.TBSResponseData
	})
	requireBadSignature(swappedTBS, ca.Certificate)

	// an algorithm that does not fit the key: another parameter set, a classical one
	for _, oid := range []asn1.ObjectIdentifier{
		{2, 16, 840, 1, 101, 3, 4, 3, 17},
		{1, 2, 840, 10045, 4, 3, 2},
	} {
		swappedAlgo := rewriteOCSP(t, direct, func(b *testBasicResponse) {
			b.SignatureAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oid}
		})
		requireBadSignature(swappedAlgo, ca.Certificate)
	}

	// a non-success status wins over ML-DSA response bytes
	outer := decodeTestOCSP(t, direct)
	outer.Status = asn1.Enumerated(ocsp.Unauthorized)
	unauthorized, err := asn1.Marshal(outer)
	require.NoError(t, err)
	_, err = certutil.ParseOCSPResponse(unauthorized, ca.Certificate)
	var unauthorizedErr ocsp.ResponseError
	require.ErrorAs(t, err, &unauthorizedErr)
	assert.Equal(t, ocsp.Unauthorized, unauthorizedErr.Status)

	// the embedded certificate must match the signature, not just the issuer
	wrongCert := rewriteOCSP(t, direct, func(b *testBasicResponse) {
		b.Certificates = []asn1.RawValue{{FullBytes: responder.Certificate.Raw}}
	})
	_, err = certutil.ParseOCSPResponse(wrongCert, ca.Certificate)
	require.ErrorContains(t, err, "bad signature on embedded certificate")

	garbageCert := rewriteOCSP(t, direct, func(b *testBasicResponse) {
		// a well-formed value that is not a certificate
		b.Certificates = []asn1.RawValue{{FullBytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}}
	})
	_, err = certutil.ParseOCSPResponse(garbageCert, ca.Certificate)
	require.ErrorContains(t, err, "unable to parse the embedded certificate")

	// RFC 9881: the parameters are absent
	withParams := rewriteOCSP(t, direct, func(b *testBasicResponse) {
		b.SignatureAlgorithm.Parameters = asn1.NullRawValue
	})
	_, err = certutil.ParseOCSPResponse(withParams, ca.Certificate)
	require.EqualError(t, err, "invalid OCSP response: ML-DSA-65 signature algorithm has parameters")

	// x/crypto reports what is not an ML-DSA basic response
	_, err = certutil.ParseOCSPResponse(append(append([]byte{}, direct...), 0), ca.Certificate)
	require.ErrorContains(t, err, "trailing data in OCSP response")
	_, err = certutil.ParseOCSPResponse([]byte{1, 2, 3}, ca.Certificate)
	require.Error(t, err)
	_, err = certutil.ParseOCSPResponse(ocsp.UnauthorizedErrorResponse, ca.Certificate)
	var status ocsp.ResponseError
	require.ErrorAs(t, err, &status)
	assert.Equal(t, ocsp.Unauthorized, status.Status)
}

// TestParseOCSPResponseForCert selects the status of a certificate.
func TestParseOCSPResponseForCert(t *testing.T) {
	t.Parallel()
	ca, key := mldsaCA(t, mldsa.MLDSA44())
	der, err := certutil.CreateOCSPResponse(ca.Certificate, ca.Certificate, ocspTemplate(ocsp.Revoked), key)
	require.NoError(t, err)

	res, err := certutil.ParseOCSPResponseForCert(der, &x509.Certificate{SerialNumber: big.NewInt(ocspTestSerial)}, ca.Certificate)
	require.NoError(t, err)
	assert.Equal(t, ocsp.Revoked, res.Status)

	_, err = certutil.ParseOCSPResponseForCert(der, &x509.Certificate{SerialNumber: big.NewInt(1)}, ca.Certificate)
	require.ErrorContains(t, err, "no response matching the supplied certificate")
}

// TestParseOCSPResponseOpenSSL reads the responses OpenSSL 3.5 signed with
// ML-DSA, directly and through a delegated responder, so the local encoding is
// not only checked against itself.
func TestParseOCSPResponseOpenSSL(t *testing.T) {
	t.Parallel()
	ca, err := certutil.ParseFromPEM(pqcVector(t, 65, "crt"))
	require.NoError(t, err)
	leafPEM, err := os.ReadFile(filepath.Join(pqcTestdata, "mldsa65-leaf.crt"))
	require.NoError(t, err)
	leaf, err := certutil.ParseFromPEM(leafPEM)
	require.NoError(t, err)

	for _, tc := range []struct {
		file     string
		algo     x509.SignatureAlgorithm
		embedded *x509.Certificate
	}{
		{file: "mldsa65-ocsp.der", algo: x509.MLDSA65, embedded: ca},
		{file: "mldsa65-ocsp-nocerts.der", algo: x509.MLDSA65},
		{file: "mldsa65-ocsp-delegated.der", algo: x509.MLDSA44, embedded: leaf},
	} {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			der, err := os.ReadFile(filepath.Join(pqcTestdata, tc.file))
			require.NoError(t, err)

			res, err := certutil.ParseOCSPResponseForCert(der, leaf, ca)
			require.NoError(t, err)
			assert.Equal(t, ocsp.Good, res.Status)
			assert.Equal(t, big.NewInt(ocspVectorSerial), res.SerialNumber)
			assert.Equal(t, tc.algo, res.SignatureAlgorithm)
			if tc.embedded != nil {
				require.NotNil(t, res.Certificate)
				assert.True(t, tc.embedded.Equal(res.Certificate))
			} else {
				assert.Nil(t, res.Certificate)
			}

			// the response answers a request for this certificate: serial and
			// hash algorithm, the fields ocsp.Response exposes (ROADMAP item 11)
			req, err := certutil.CreateOCSPRequest(leaf, ca, crypto.SHA1)
			require.NoError(t, err)
			parsed, err := ocsp.ParseRequest(req)
			require.NoError(t, err)
			assert.Equal(t, parsed.SerialNumber, res.SerialNumber)
			assert.Equal(t, parsed.HashAlgorithm, res.IssuerHash)

			// an issuer that signed neither the response nor the responder
			other, _ := mldsaCA(t, mldsa.MLDSA65())
			_, err = certutil.ParseOCSPResponse(der, other.Certificate)
			require.ErrorContains(t, err, "bad OCSP signature")
		})
	}
}
