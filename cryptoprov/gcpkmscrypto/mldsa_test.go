package gcpkmscrypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// mldsaAlgorithms tables the six ML-DSA KMS algorithms.
var mldsaAlgorithms = []struct {
	algorithm  kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	params     mldsa.Parameters
	externalMu bool
	sigAlg     x509.SignatureAlgorithm
}{
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44, mldsa.MLDSA44(), false, x509.MLDSA44},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65, mldsa.MLDSA65(), false, x509.MLDSA65},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87, mldsa.MLDSA87(), false, x509.MLDSA87},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU, mldsa.MLDSA44(), true, x509.MLDSA44},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, mldsa.MLDSA65(), true, x509.MLDSA65},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU, mldsa.MLDSA87(), true, x509.MLDSA87},
}

// TestSignerSignatureAlgorithmMLDSA tables the ML-DSA KMS to X.509 mapping.
func TestSignerSignatureAlgorithmMLDSA(t *testing.T) {
	t.Parallel()
	for _, tc := range mldsaAlgorithms {
		signer := gcpkmscrypto.NewSigner(signKeyID, "label", nil, tc.algorithm, nil).(*gcpkmscrypto.Signer)
		assert.Equal(t, tc.sigAlg, signer.SignatureAlgorithm(), tc.algorithm.String())
		assert.Equal(t, tc.sigAlg, csr.DefaultSigAlgo(signer), tc.algorithm.String())
	}
}

// TestMLDSASignRejectsOptionsLocally checks that a digest hash, a mismatched
// or classical public key, a μ or context for a message algorithm and a
// malformed μ fail before any RPC.
func TestMLDSASignRejectsOptionsLocally(t *testing.T) {
	t.Parallel()
	client := &fakeKMS{}
	provider := newProvider(t, client)
	key44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	require.NoError(t, err)
	key65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer := func(pub crypto.PublicKey, algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) crypto.Signer {
		return gcpkmscrypto.NewSigner(signKeyID, "label", pub, algorithm, provider)
	}
	message := []byte("message")

	for _, tc := range []struct {
		name    string
		signer  crypto.Signer
		message []byte
		opts    crypto.SignerOpts
		err     string
	}{
		{name: "sha256", signer: signer(key65.Public(), kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU), message: make([]byte, 32), opts: crypto.SHA256, err: "ML-DSA signs a message, not a digest: unsupported signer options SHA-256"},
		{name: "sha384 message algorithm", signer: signer(key65.Public(), kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65), message: make([]byte, 48), opts: crypto.SHA384, err: "ML-DSA signs a message, not a digest: unsupported signer options SHA-384"},
		{name: "ecdsa public key", signer: signer(ecKey.Public(), kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU), message: message, err: "key algorithm PQ_SIGN_ML_DSA_65_EXTERNAL_MU needs an ML-DSA public key, got *ecdsa.PublicKey"},
		{name: "parameter set mismatch", signer: signer(key44.Public(), kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU), message: message, err: "public key parameter set ML-DSA-44 does not match key algorithm PQ_SIGN_ML_DSA_65_EXTERNAL_MU"},
		{name: "mu for message algorithm", signer: signer(key65.Public(), kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65), message: make([]byte, 64), opts: crypto.MLDSAMu, err: "key algorithm PQ_SIGN_ML_DSA_65 signs the message; μ needs an EXTERNAL_MU algorithm"},
		{name: "context for message algorithm", signer: signer(key65.Public(), kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65), message: message, opts: &mldsa.Options{Context: "xpki"}, err: "key algorithm PQ_SIGN_ML_DSA_65 does not support a context string"},
		{name: "short mu", signer: signer(key65.Public(), kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU), message: make([]byte, 63), opts: crypto.MLDSAMu, err: "μ length 63 does not match ML-DSA (64 bytes)"},
		{name: "ml-dsa key with digest algorithm", signer: signer(key65.Public(), kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256), message: message, err: "signer options are required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := tc.signer.Sign(rand.Reader, tc.message, tc.opts)
			require.EqualError(t, err, tc.err)
			assert.Nil(t, sig)
		})
	}
	assert.Empty(t, client.Calls(), "no RPC for locally rejected input")
}

// TestMLDSASignRequest checks what reaches KMS: μ in Data with its checksum
// for an EXTERNAL_MU algorithm, the message itself for the others, no
// digest, and the response integrity checks on the data checksum.
func TestMLDSASignRequest(t *testing.T) {
	t.Parallel()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	message := []byte("to be signed")
	mu, err := cryptoprov.MLDSAMu(key.PublicKey(), "", message)
	require.NoError(t, err)
	ctxMu, err := cryptoprov.MLDSAMu(key.PublicKey(), "xpki", message)
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		opts      crypto.SignerOpts
		message   []byte
		wantData  []byte
	}{
		{name: "external mu nil", algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, message: message, wantData: mu},
		{name: "external mu zero hash", algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, opts: crypto.Hash(0), message: message, wantData: mu},
		{name: "external mu context", algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, opts: &mldsa.Options{Context: "xpki"}, message: message, wantData: ctxMu},
		{name: "external mu given", algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, opts: crypto.MLDSAMu, message: mu, wantData: mu},
		{name: "message", algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65, message: message, wantData: message},
		{name: "message empty options", algorithm: kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65, opts: &mldsa.Options{}, message: message, wantData: message},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got *kmspb.AsymmetricSignRequest
			client := &fakeKMS{
				asymmetricSign: func(req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
					got = req
					return dataSignResponse(req, []byte("signature")), nil
				},
			}
			signer := gcpkmscrypto.NewSigner(signKeyID, "label", key.PublicKey(), tc.algorithm, newProvider(t, client))
			sig, err := signer.Sign(rand.Reader, tc.message, tc.opts)
			require.NoError(t, err)
			assert.Equal(t, []byte("signature"), sig)
			require.NotNil(t, got)
			assert.Equal(t, signKeyVersion, got.GetName())
			assert.Equal(t, tc.wantData, got.GetData())
			assert.Nil(t, got.GetDigest())
			assert.Nil(t, got.GetDigestCrc32C())
			assert.Equal(t, int64(gcpkmscrypto.Crc32c(tc.wantData)), got.GetDataCrc32C().GetValue())
		})
	}

	t.Run("response integrity", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name     string
			response func(*kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse
			err      string
		}{
			{
				name: "data checksum not verified",
				response: func(req *kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse {
					resp := dataSignResponse(req, []byte("signature"))
					resp.VerifiedDataCrc32C = false
					resp.VerifiedDigestCrc32C = true
					return resp
				},
				err: "request corrupted in-transit",
			},
			{
				name: "no signature checksum",
				response: func(req *kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse {
					resp := dataSignResponse(req, []byte("signature"))
					resp.SignatureCrc32C = nil
					return resp
				},
				err: "response has no signature checksum",
			},
			{
				name: "signature checksum mismatch",
				response: func(req *kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse {
					resp := dataSignResponse(req, []byte("signature"))
					resp.SignatureCrc32C = wrapperspb.Int64(1)
					return resp
				},
				err: "response corrupted in-transit",
			},
			{
				name: "nil response",
				response: func(*kmspb.AsymmetricSignRequest) *kmspb.AsymmetricSignResponse {
					return nil
				},
				err: "unable to sign: empty response",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				client := &fakeKMS{
					asymmetricSign: func(req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
						return tc.response(req), nil
					},
				}
				signer := gcpkmscrypto.NewSigner(signKeyID, "label", key.PublicKey(), kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, newProvider(t, client))
				_, err := signer.Sign(rand.Reader, message, nil)
				require.EqualError(t, err, tc.err)
			})
		}
	})
}

// TestMLDSAKeysOnFakeKMS runs every ML-DSA algorithm against the in-process
// gRPC KMS through the real SDK client: GetKey, KeyInfo type and parameter
// set, signatures that verify locally, a CSR through csr.Provider and a
// self-signed certificate.
func TestMLDSAKeysOnFakeKMS(t *testing.T) {
	t.Parallel()
	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	csrProv := csr.NewProvider(provider)
	message := []byte("signed by the fake KMS")

	for _, tc := range mldsaAlgorithms {
		t.Run(tc.algorithm.String(), func(t *testing.T) {
			name := "pq-" + tc.algorithm.String()
			s.AddKey(t, name, tc.algorithm, name)

			priv, err := provider.GetKey(name)
			require.NoError(t, err)
			signer := priv.(*gcpkmscrypto.Signer)
			pub, ok := signer.Public().(*mldsa.PublicKey)
			require.True(t, ok, "%T", signer.Public())
			assert.Equal(t, tc.params, pub.Parameters())
			assert.Equal(t, tc.algorithm, signer.Algorithm())
			assert.True(t, pub.Equal(s.PublicKey(t, testKeyring+cryptoKeysPath+name+versionsPath+"1")))

			ki, err := provider.KeyInfo(0, name, true)
			require.NoError(t, err)
			assert.Equal(t, certutil.KeyTypeMLDSA, ki.Type)
			assert.Equal(t, tc.params.String(), ki.Meta[cryptoprov.MetaParameterSet])
			assert.Equal(t, tc.algorithm.String(), ki.Meta["algo"])
			// the NIST_PQC bytes are re-encoded as a PEM SubjectPublicKeyInfo
			block, _ := pem.Decode([]byte(ki.PublicKey))
			require.NotNil(t, block, "KeyInfo.PublicKey is PEM")
			parsedPub, err := x509.ParsePKIXPublicKey(block.Bytes)
			require.NoError(t, err)
			assert.True(t, pub.Equal(parsedPub))

			sig, err := signer.Sign(rand.Reader, message, nil)
			require.NoError(t, err)
			require.NoError(t, mldsa.Verify(pub, message, sig, nil))
			if tc.externalMu {
				ctx := &mldsa.Options{Context: "xpki"}
				sig, err = signer.Sign(rand.Reader, message, ctx)
				require.NoError(t, err)
				require.NoError(t, mldsa.Verify(pub, message, sig, ctx))
			}

			csrPEM, err := csrProv.SignRequest(priv, &csr.CertificateRequest{
				CommonName: "pq.example.com",
				SAN:        []string{"pq.example.com"},
			})
			require.NoError(t, err)
			parsed := parseCSR(t, csrPEM)
			assert.Equal(t, tc.sigAlg, parsed.SignatureAlgorithm)
			assert.True(t, pub.Equal(parsed.PublicKey))

			template := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "pq root"},
				NotBefore:             time.Now().Add(-time.Minute),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer)
			require.NoError(t, err)
			crt, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			require.NoError(t, crt.CheckSignatureFrom(crt))
			assert.Equal(t, tc.sigAlg, crt.SignatureAlgorithm)
		})
	}
}

// TestMLDSAPublicKeyFormat checks the GetPublicKey contract for ML-DSA
// versions: the request asks for the NIST_PQC format and the response's
// raw key is accepted only with a matching checksum; a PEM-only response,
// as KMS gives for classical keys, is an empty response.
func TestMLDSAPublicKeyFormat(t *testing.T) {
	t.Parallel()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	raw := key.PublicKey().Bytes()
	const algorithm = kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU
	version := enabledVersion("pq", algorithm)
	keyName := coverageKeyring + "/cryptoKeys/pq"

	newClient := func(public func(*kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error)) *fakeKMS {
		return &fakeKMS{
			getCryptoKey: func(req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
				return &kmspb.CryptoKey{Name: req.GetName(), Labels: map[string]string{"label": "pq"}}, nil
			},
			getCryptoKeyVersion: func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				return version, nil
			},
			getPublicKey: public,
		}
	}
	checksummed := func(data []byte, crc *wrapperspb.Int64Value) *kmspb.PublicKey {
		return &kmspb.PublicKey{
			Name:            version.GetName(),
			Algorithm:       algorithm,
			PublicKeyFormat: kmspb.PublicKey_NIST_PQC,
			PublicKey: &kmspb.ChecksummedData{
				Data:           data,
				Crc32CChecksum: crc,
			},
		}
	}

	t.Run("accepted", func(t *testing.T) {
		var got *kmspb.GetPublicKeyRequest
		client := newClient(func(req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
			got = req
			return checksummed(raw, wrapperspb.Int64(int64(gcpkmscrypto.Crc32c(raw)))), nil
		})
		priv, err := newProvider(t, client).GetKey("pq/cryptoKeyVersions/1")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, kmspb.PublicKey_NIST_PQC, got.GetPublicKeyFormat())
		assert.Equal(t, keyName+"/cryptoKeyVersions/1", got.GetName())
		assert.True(t, key.PublicKey().Equal(priv.(crypto.Signer).Public()))

		ki, err := newProvider(t, client).KeyInfo(0, "pq/cryptoKeyVersions/1", true)
		require.NoError(t, err)
		block, _ := pem.Decode([]byte(ki.PublicKey))
		require.NotNil(t, block)
		parsedPub, err := x509.ParsePKIXPublicKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, key.PublicKey().Equal(parsedPub))
	})

	for _, tc := range []struct {
		name string
		resp *kmspb.PublicKey
		err  string
	}{
		{name: "no checksum", resp: checksummed(raw, nil), err: "public key has no checksum"},
		{name: "checksum mismatch", resp: checksummed(raw, wrapperspb.Int64(1)), err: "public key corrupted in-transit"},
		{name: "wrong parameter set", resp: checksummed(raw[:mldsa.MLDSA44PublicKeySize], wrapperspb.Int64(int64(gcpkmscrypto.Crc32c(raw[:mldsa.MLDSA44PublicKeySize])))), err: "failed to parse public key: "},
		{name: "pem only", resp: &kmspb.PublicKey{Name: version.GetName(), Algorithm: algorithm, Pem: "-----BEGIN PUBLIC KEY-----\n"}, err: "failed to get public key: empty response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newClient(func(*kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
				return tc.resp, nil
			})
			_, err := newProvider(t, client).GetKey("pq/cryptoKeyVersions/1")
			require.ErrorContains(t, err, tc.err)
			_, err = newProvider(t, client).KeyInfo(0, "pq/cryptoKeyVersions/1", true)
			require.ErrorContains(t, err, "failed to get public key, id=pq/cryptoKeyVersions/1: ")
			require.ErrorContains(t, err, tc.err)
		})
	}
}

// TestGenerateMLDSAKeyOnFakeKMS creates keys of every parameter set: the
// EXTERNAL_MU algorithm is used, the label and version id are set, the URI
// pins the version and the signer verifies locally.
func TestGenerateMLDSAKeyOnFakeKMS(t *testing.T) {
	t.Parallel()
	s := newFakeKMSServer()
	provider := grpcProvider(t, s)

	for _, tc := range mldsaAlgorithms {
		if !tc.externalMu {
			continue
		}
		priv, err := provider.GenerateMLDSAKey("PQ Key "+tc.params.String(), tc.params)
		require.NoError(t, err, tc.params.String())
		signer := priv.(*gcpkmscrypto.Signer)
		assert.Equal(t, tc.algorithm, signer.Algorithm())
		assert.Equal(t, tc.sigAlg, signer.SignatureAlgorithm())

		keyID, label, err := provider.IdentifyKey(priv)
		require.NoError(t, err)
		wantLabel, _ := gcpkmscrypto.KeyLabelAndID("PQ Key " + tc.params.String())
		assert.Equal(t, wantLabel, label)
		assert.Contains(t, keyID, versionsPath+"1")

		uri, _, err := provider.ExportKey(keyID)
		require.NoError(t, err)
		assert.Contains(t, uri, "id="+keyID+";")

		pub := signer.Public().(*mldsa.PublicKey)
		sig, err := signer.Sign(rand.Reader, []byte("message"), nil)
		require.NoError(t, err)
		require.NoError(t, mldsa.Verify(pub, []byte("message"), sig, nil))
	}
	assert.Equal(t, 3, s.CallCount("CreateCryptoKey"))
}
