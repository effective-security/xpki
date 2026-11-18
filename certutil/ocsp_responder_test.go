package certutil_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const (
	// errResponderEKU is the error for a delegated responder without the
	// OCSP signing extended key usage.
	errResponderEKU = "OCSP responder certificate has no OCSP signing extended key usage"
	// errResponderValidity starts the error for a responder outside its
	// validity.
	errResponderValidity = "OCSP responder certificate is not valid now: valid from "
	// errCertID is the error for a CertID of another issuer.
	errCertID = "OCSP response CertID does not match the issuer"
)

// ecdsaKey returns a testca option with a new P-256 key, faster than the
// default RSA key.
func ecdsaKey(t *testing.T) testca.Option {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return testca.PrivateKey(key)
}

// requireError requires err to be want or, when want ends with a space, to
// start with it.
func requireError(t *testing.T, err error, want string) {
	t.Helper()
	if strings.HasSuffix(want, " ") {
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), want), "%q does not start with %q", err.Error(), want)
		return
	}
	require.EqualError(t, err, want)
}

// TestVerifyOCSPResponder applies the responder and CertID rules of RFC 6960
// §4.2.2.2 to responses the parsers accept, for classical and ML-DSA keys
// (ROADMAP item 11). parserRejects marks the cases a parser given the issuer
// already rejects; those responses are parsed without the issuer, so the
// check is made by VerifyOCSPResponder alone.
func TestVerifyOCSPResponder(t *testing.T) {
	t.Parallel()
	for _, family := range []struct {
		name string
		key  func(t *testing.T) testca.Option
	}{
		{
			name: "ECDSA",
			key:  ecdsaKey,
		},
		{
			name: "ML-DSA",
			key:  func(*testing.T) testca.Option { return testca.MLDSAKey(mldsa.MLDSA44()) },
		},
	} {
		t.Run(family.name, func(t *testing.T) {
			t.Parallel()
			now := time.Now()
			caName := pkix.Name{CommonName: "OCSP responder CA"}
			newCA := func(name pkix.Name, key testca.Option) *testca.Entity {
				return testca.NewEntity(testca.Authority, testca.Subject(name), testca.KeyUsage(x509.KeyUsageCertSign), key)
			}
			ca := newCA(caName, family.key(t))
			// the CA key in another certificate, the CA name with another key
			// and another CA
			caKey := newCA(pkix.Name{CommonName: "CA key"}, testca.PrivateKey(ca.PrivateKey))
			impostor := newCA(caName, family.key(t))
			other := newCA(pkix.Name{CommonName: "Other CA"}, family.key(t))
			responder := func(issuer *testca.Entity, opts ...testca.Option) *testca.Entity {
				return issuer.Issue(append([]testca.Option{family.key(t)}, opts...)...)
			}
			ocspSigning := testca.ExtKeyUsage(x509.ExtKeyUsageOCSPSigning)
			expired := responder(ca, ocspSigning, testca.NotBefore(now.Add(-48*time.Hour)), testca.NotAfter(now.Add(-24*time.Hour)))

			for _, tc := range []struct {
				name string
				// signer signs the response, with its certificate embedded
				// unless direct is set
				signer *testca.Entity
				direct bool
				// embed is embedded instead of the signer's certificate
				embed *x509.Certificate
				// certID is the issuer the CertID names, ca when nil
				certID     *testca.Entity
				hash       crypto.Hash
				thisUpdate time.Time
				// parserRejects is set when the parser rejects it with the issuer
				parserRejects bool
				want          string
			}{
				{name: "CA", signer: ca, direct: true},
				{name: "CA certificate", signer: ca},
				{name: "CA key in another certificate", signer: ca, embed: caKey.Certificate},
				{name: "delegated", signer: responder(ca, ocspSigning)},
				{name: "SHA-256 CertID", signer: ca, hash: crypto.SHA256},
				{name: "SHA-384 CertID", signer: ca, hash: crypto.SHA384},
				{name: "SHA-512 CertID", signer: ca, hash: crypto.SHA512},
				{
					name:   "client certificate",
					signer: responder(ca, testca.ExtKeyUsage(x509.ExtKeyUsageClientAuth)),
					want:   errResponderEKU,
				},
				{
					name:   "any extended key usage",
					signer: responder(ca, testca.ExtKeyUsage(x509.ExtKeyUsageAny)),
					want:   errResponderEKU,
				},
				{name: "no extended key usage", signer: responder(ca), want: errResponderEKU},
				{
					// the key of an expired responder signs within its validity
					name:       "expired responder",
					signer:     expired,
					thisUpdate: now.Add(-36 * time.Hour),
					want:       errResponderValidity,
				},
				{
					name:   "responder not yet valid",
					signer: responder(ca, ocspSigning, testca.NotBefore(now.Add(time.Hour))),
					want:   errResponderValidity,
				},
				{
					name:          "responder of another CA",
					signer:        responder(other, ocspSigning),
					parserRejects: true,
					want:          "OCSP responder certificate is not issued by the issuer",
				},
				{
					name:          "responder of the CA name with another key",
					signer:        responder(impostor, ocspSigning),
					parserRejects: true,
					want:          "OCSP responder certificate is not signed by the issuer: ",
				},
				{
					name:          "another key",
					signer:        other,
					direct:        true,
					parserRejects: true,
					want:          "bad OCSP signature: ",
				},
				{name: "CertID of another CA", signer: ca, certID: other, want: errCertID},
				{name: "CertID of the CA key with another name", signer: ca, certID: caKey, want: errCertID},
				{name: "CertID of the CA name with another key", signer: ca, certID: impostor, want: errCertID},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					thisUpdate := tc.thisUpdate
					if thisUpdate.IsZero() {
						thisUpdate = now.Add(-time.Minute)
					}
					template := ocsp.Response{
						Status:       ocsp.Good,
						SerialNumber: big.NewInt(ocspTestSerial),
						ThisUpdate:   thisUpdate.UTC().Truncate(time.Minute),
						NextUpdate:   now.Add(time.Hour).UTC().Truncate(time.Minute),
						IssuerHash:   tc.hash,
					}
					responderCert := tc.signer.Certificate
					if tc.embed != nil {
						responderCert = tc.embed
					}
					if !tc.direct {
						template.Certificate = responderCert
					}
					certID := ca
					if tc.certID != nil {
						certID = tc.certID
					}
					der, err := certutil.CreateOCSPResponse(t.Context(), certID.Certificate, responderCert, template, tc.signer.PrivateKey)
					require.NoError(t, err)

					res, err := certutil.ParseOCSPResponseForCert(der, &x509.Certificate{SerialNumber: big.NewInt(ocspTestSerial)}, ca.Certificate)
					if tc.parserRejects {
						var parseErr ocsp.ParseError
						require.ErrorAs(t, err, &parseErr)
						res, err = certutil.ParseOCSPResponse(der, nil)
					}
					require.NoError(t, err)
					assert.Equal(t, ocsp.Good, res.Status)

					err = certutil.VerifyOCSPResponder(res, ca.Certificate)
					if tc.want == "" {
						require.NoError(t, err)
						return
					}
					requireError(t, err, tc.want)
				})
			}
		})
	}
}

// TestVerifyOCSPResponderInput covers the input VerifyOCSPResponder rejects
// before or apart from the responder rules, on responses changed after
// parsing and signed again by the CA key.
func TestVerifyOCSPResponderInput(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testca.NewEntity(testca.Authority, testca.KeyUsage(x509.KeyUsageCertSign), testca.PrivateKey(key))
	template := ocspTemplate(ocsp.Good)
	template.IssuerHash = crypto.SHA256
	der, err := certutil.CreateOCSPResponse(t.Context(), ca.Certificate, ca.Certificate, template, key)
	require.NoError(t, err)
	parsed, err := certutil.ParseOCSPResponse(der, ca.Certificate)
	require.NoError(t, err)
	require.NoError(t, certutil.VerifyOCSPResponder(parsed, ca.Certificate))

	// resigned returns a copy of parsed with tbs as its signed data
	resigned := func(tbs []byte) *ocsp.Response {
		digest := sha256.Sum256(tbs)
		signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err)
		res := *parsed
		res.TBSResponseData = tbs
		res.Signature = signature
		res.SignatureAlgorithm = x509.ECDSAWithSHA256
		return &res
	}
	withSerial := func(serial *big.Int) *ocsp.Response {
		res := *parsed
		res.SerialNumber = serial
		return &res
	}
	// the SHA-256 CertID algorithm, and SHA-224, which x/crypto does not read
	sha256OID := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	sha224OID := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}
	require.Equal(t, 1, bytes.Count(parsed.TBSResponseData, sha256OID))

	for _, tc := range []struct {
		name   string
		res    *ocsp.Response
		issuer *x509.Certificate
		want   string
	}{
		{name: "nil response", issuer: ca.Certificate, want: "OCSP response is nil"},
		{name: "nil issuer", res: parsed, want: "issuer certificate is nil"},
		{
			name:   "no serial number",
			res:    withSerial(nil),
			issuer: ca.Certificate,
			want:   "OCSP response has no serial number",
		},
		{
			name:   "other serial number",
			res:    withSerial(big.NewInt(1)),
			issuer: ca.Certificate,
			want:   "OCSP response has no status for serial number 1",
		},
		{
			name:   "malformed data",
			res:    resigned([]byte{0x30, 0x01, 0x02}),
			issuer: ca.Certificate,
			want:   "unable to decode the OCSP response data: ",
		},
		{
			name:   "trailing data",
			res:    resigned(append(bytes.Clone(parsed.TBSResponseData), 0)),
			issuer: ca.Certificate,
			want:   "trailing data in the OCSP response data",
		},
		{
			name:   "unsupported CertID hash",
			res:    resigned(bytes.Replace(parsed.TBSResponseData, sha256OID, sha224OID, 1)),
			issuer: ca.Certificate,
			want:   "unsupported OCSP CertID hash algorithm: 2.16.840.1.101.3.4.2.4",
		},
		{
			name:   "issuer that did not sign",
			res:    parsed,
			issuer: testca.NewEntity(testca.Authority, ecdsaKey(t)).Certificate,
			want:   "bad OCSP signature: ",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireError(t, certutil.VerifyOCSPResponder(tc.res, tc.issuer), tc.want)
		})
	}
}
