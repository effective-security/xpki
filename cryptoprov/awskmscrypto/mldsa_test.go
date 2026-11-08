package awskmscrypto_test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/internal/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mldsaSpecs tables the parameter sets and their KMS key specs.
var mldsaSpecs = []struct {
	params mldsa.Parameters
	spec   types.KeySpec
	sigAlg x509.SignatureAlgorithm
}{
	{mldsa.MLDSA44(), types.KeySpecMlDsa44, x509.MLDSA44},
	{mldsa.MLDSA65(), types.KeySpecMlDsa65, x509.MLDSA65},
	{mldsa.MLDSA87(), types.KeySpecMlDsa87, x509.MLDSA87},
}

// mldsaSignerFor creates an ML-DSA key of spec in client and returns its
// signer and public key.
func mldsaSignerFor(t *testing.T, client *fakeKMS, provider *awskmscrypto.Provider, spec types.KeySpec) (*awskmscrypto.Signer, *mldsa.PublicKey, string) {
	t.Helper()
	keyID := client.mustAddKey(t, "pq-"+string(spec), spec, types.KeyUsageTypeSignVerify)
	priv, err := provider.GetKey(keyID)
	require.NoError(t, err)
	signer, ok := priv.(*awskmscrypto.Signer)
	require.True(t, ok)
	pub, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok, "%T", signer.Public())
	return signer, pub, keyID
}

// TestGenerateMLDSAKeys checks the created keys: spec, usage, alias and
// algorithm, the signer's public key, and KeyInfo/EnumKeys type and
// parameter set.
func TestGenerateMLDSAKeys(t *testing.T) {
	t.Parallel()
	client := newFakeKMS()
	provider := newProvider(t, client)

	for _, tc := range mldsaSpecs {
		label := "pq/" + tc.params.String()
		priv, err := provider.GenerateMLDSAKey(label, tc.params)
		require.NoError(t, err, tc.params.String())
		signer, ok := priv.(*awskmscrypto.Signer)
		require.True(t, ok)
		pub, ok := signer.Public().(*mldsa.PublicKey)
		require.True(t, ok, "%T", signer.Public())
		assert.Equal(t, tc.params, pub.Parameters())
		assert.Equal(t, []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecMlDsaShake256}, signer.SigningAlgorithms())
		assert.True(t, certutil.IsPostQuantumKey(signer))
		assert.Equal(t, tc.sigAlg, csr.DefaultSigAlgo(signer))

		keyID, gotLabel, err := provider.IdentifyKey(priv)
		require.NoError(t, err)
		assert.Equal(t, label, gotLabel)

		ki, err := provider.KeyInfo(0, keyID, true)
		require.NoError(t, err)
		assert.Equal(t, certutil.KeyTypeMLDSA, ki.Type)
		assert.Equal(t, tc.params.String(), ki.Meta[cryptoprov.MetaParameterSet])
		assert.Equal(t, string(types.KeyUsageTypeSignVerify), ki.Meta["usage"])
		block, _ := pem.Decode([]byte(ki.PublicKey))
		require.NotNil(t, block)
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		require.NoError(t, err)
		assert.True(t, pub.Equal(parsed))

		// the key is found through its alias too
		again, err := provider.GetKey(awskmscrypto.AliasFromLabel(label))
		require.NoError(t, err)
		assert.True(t, pub.Equal(again.(crypto.Signer).Public()))
	}

	keys, err := provider.EnumKeys(0, "pq/")
	require.NoError(t, err)
	require.Len(t, keys, len(mldsaSpecs))
	for i, ki := range keys {
		assert.Equal(t, certutil.KeyTypeMLDSA, ki.Type)
		assert.Equal(t, mldsaSpecs[i].params.String(), ki.Meta[cryptoprov.MetaParameterSet])
	}

	// classical keys report their type and no parameter set
	ec, err := provider.GenerateECDSAKey("classical", nil)
	require.EqualError(t, err, "unsupported curve")
	assert.Nil(t, ec)
	rsaKey, err := provider.GenerateRSAKey("classical", 2048, 1)
	require.NoError(t, err)
	rsaID, _, err := provider.IdentifyKey(rsaKey)
	require.NoError(t, err)
	ki, err := provider.KeyInfo(0, rsaID, false)
	require.NoError(t, err)
	assert.Equal(t, certutil.KeyTypeRSA, ki.Type)
	assert.NotContains(t, ki.Meta, cryptoprov.MetaParameterSet)
}

// TestMLDSASignRequests checks what reaches KMS for every option form the
// signer contract allows: an EXTERNAL_MU request carrying μ, computed from
// the message and context or given as is, whose signature verifies the
// message locally.
func TestMLDSASignRequests(t *testing.T) {
	t.Parallel()
	message := []byte("to be signed by KMS")
	for _, tc := range mldsaSpecs {
		t.Run(tc.params.String(), func(t *testing.T) {
			t.Parallel()
			client := newFakeKMS()
			provider := newProvider(t, client)
			signer, pub, keyID := mldsaSignerFor(t, client, provider, tc.spec)

			mu, err := cryptoprov.MLDSAMu(pub, "", message)
			require.NoError(t, err)
			ctxMu, err := cryptoprov.MLDSAMu(pub, "xpki", message)
			require.NoError(t, err)

			for _, oc := range []struct {
				name    string
				message []byte
				opts    crypto.SignerOpts
				wantMu  []byte
				verify  *mldsa.Options
			}{
				{name: "nil", message: message, opts: nil, wantMu: mu},
				{name: "zero hash", message: message, opts: crypto.Hash(0), wantMu: mu},
				{name: "empty options", message: message, opts: &mldsa.Options{}, wantMu: mu},
				{name: "context", message: message, opts: &mldsa.Options{Context: "xpki"}, wantMu: ctxMu, verify: &mldsa.Options{Context: "xpki"}},
				{name: "mu", message: mu, opts: crypto.MLDSAMu, wantMu: mu},
			} {
				t.Run(oc.name, func(t *testing.T) {
					before := len(client.SignRequests())
					sig, err := signer.Sign(rand.Reader, oc.message, oc.opts)
					require.NoError(t, err)
					require.NoError(t, mldsa.Verify(pub, message, sig, oc.verify))

					requests := client.SignRequests()
					require.Len(t, requests, before+1)
					req := requests[before]
					assert.Equal(t, keyID, aws.ToString(req.KeyId))
					assert.Equal(t, types.MessageTypeExternalMu, req.MessageType)
					assert.Equal(t, types.SigningAlgorithmSpecMlDsaShake256, req.SigningAlgorithm)
					assert.Equal(t, oc.wantMu, req.Message, "the message itself is never sent")
				})
			}
		})
	}
}

// TestMLDSASignRejectsOptionsLocally checks that a digest hash, a μ of the
// wrong length and a key without the ML-DSA algorithm fail before any RPC.
func TestMLDSASignRejectsOptionsLocally(t *testing.T) {
	t.Parallel()
	client := newFakeKMS()
	provider := newProvider(t, client)
	signer, pub, keyID := mldsaSignerFor(t, client, provider, types.KeySpecMlDsa65)
	before := client.CallCount("Sign")

	for _, tc := range []struct {
		name    string
		signer  crypto.Signer
		message []byte
		opts    crypto.SignerOpts
		err     string
	}{
		{name: "sha256", signer: signer, message: make([]byte, 32), opts: crypto.SHA256, err: "ML-DSA signs a message, not a digest: unsupported signer options SHA-256"},
		{name: "sha512", signer: signer, message: make([]byte, 64), opts: crypto.SHA512, err: "ML-DSA signs a message, not a digest: unsupported signer options SHA-512"},
		{name: "short mu", signer: signer, message: make([]byte, 32), opts: crypto.MLDSAMu, err: "μ length 32 does not match ML-DSA (64 bytes)"},
		{name: "empty mu", signer: signer, message: nil, opts: crypto.MLDSAMu, err: "μ length 0 does not match ML-DSA (64 bytes)"},
		{
			name:    "no algorithm",
			signer:  awskmscrypto.NewSigner(keyID, "label", nil, pub, client),
			message: []byte("message"),
			opts:    nil,
			err:     "key " + keyID + " does not support ML_DSA_SHAKE_256 (supported: [])",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig, err := tc.signer.Sign(rand.Reader, tc.message, tc.opts)
			require.EqualError(t, err, tc.err)
			assert.Nil(t, sig)
		})
	}
	assert.Equal(t, before, client.CallCount("Sign"), "no RPC for locally rejected input")
}

// TestMLDSASignResponses covers KMS failures and empty responses.
func TestMLDSASignResponses(t *testing.T) {
	t.Parallel()
	client := newFakeKMS()
	provider := newProvider(t, client)
	signer, _, _ := mldsaSignerFor(t, client, provider, types.KeySpecMlDsa44)

	client.sign = func(*kms.SignInput) (*kms.SignOutput, error) {
		return &kms.SignOutput{}, nil
	}
	_, err := signer.Sign(rand.Reader, []byte("message"), nil)
	require.EqualError(t, err, "unable to sign: empty response")

	client.sign = func(*kms.SignInput) (*kms.SignOutput, error) {
		return nil, &types.DisabledException{Message: aws.String("key is disabled")}
	}
	_, err = signer.Sign(rand.Reader, []byte("message"), nil)
	require.ErrorContains(t, err, "unable to sign: ")
	var disabled *types.DisabledException
	require.ErrorAs(t, err, &disabled)
}

// TestMLDSACSRAndCertificate signs a CSR through csr.Provider and a
// self-signed certificate with a KMS ML-DSA key of every parameter set;
// both verify locally with the KMS public key.
func TestMLDSACSRAndCertificate(t *testing.T) {
	t.Parallel()
	for _, tc := range mldsaSpecs {
		t.Run(tc.params.String(), func(t *testing.T) {
			t.Parallel()
			client := newFakeKMS()
			provider := newProvider(t, client)
			csrProv := csr.NewProvider(provider)

			size := map[types.KeySpec]int{types.KeySpecMlDsa44: csr.MLDSA44, types.KeySpecMlDsa65: csr.MLDSA65, types.KeySpecMlDsa87: csr.MLDSA87}[tc.spec]
			req := csrProv.NewSigningCertificateRequest("pq", csr.AlgoMLDSA, size, "pq.example.com", nil, []string{"pq.example.com"})
			csrPEM, keyURI, keyID, pub, err := csrProv.CreateRequestAndExportKey(req)
			require.NoError(t, err)
			assert.NotEmpty(t, keyID)
			assert.Contains(t, string(keyURI), "pkcs11:manufacturer=AWSKMS;model=KMS;id="+keyID)

			block, _ := pem.Decode(csrPEM)
			require.NotNil(t, block)
			parsed, err := x509.ParseCertificateRequest(block.Bytes)
			require.NoError(t, err)
			require.NoError(t, parsed.CheckSignature())
			assert.Equal(t, tc.sigAlg, parsed.SignatureAlgorithm)
			assert.True(t, pub.(*mldsa.PublicKey).Equal(parsed.PublicKey))

			signer, err := provider.GetKey(keyID)
			require.NoError(t, err)
			template := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "pq root"},
				NotBefore:             time.Now().Add(-time.Minute),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer.(crypto.Signer))
			require.NoError(t, err)
			crt, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			require.NoError(t, crt.CheckSignatureFrom(crt))
			assert.Equal(t, tc.sigAlg, crt.SignatureAlgorithm)
			assert.True(t, certutil.IsPostQuantumCertificate(crt))
		})
	}
}

// TestKmsProviderMLDSA is the gated integration test: it needs the KMS the
// test config points to (local-kms on :14556 by default). local-kms 3.11.7
// rejects the ML_DSA key specs with a ValidationException, in which case
// the test is skipped with that reason; against a KMS that supports them
// it creates a key, signs, verifies and schedules the key for deletion.
func TestKmsProviderMLDSA(t *testing.T) {
	testenv.RequireTCP(t, "local-kms", localKMSAddr)
	t.Setenv("AWS_ACCESS_KEY_ID", "notusedbyemulator")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "notusedbyemulator")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	cfg := &mockTokenCfg{
		manufacturer: awskmscrypto.ProviderName,
		model:        "KMS",
		atts:         "Endpoint=" + localKMSEndpoint + ",Region=eu-west-2",
	}
	provider, err := awskmscrypto.KmsLoader(cfg)
	require.NoError(t, err)

	priv, err := provider.GenerateMLDSAKey("TestKmsProviderMLDSA", mldsa.MLDSA65())
	if err != nil {
		// local-kms rejects the key spec with its enum constraint message;
		// any other failure is a real one
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ValidationException" &&
			strings.Contains(apiErr.ErrorMessage(), "at 'KeySpec' failed to satisfy constraint") {
			t.Skipf("the KMS at %s does not support ML-DSA key specs: %v", localKMSAddr, err)
		}
		require.NoError(t, err)
	}
	keyID, _, err := provider.IdentifyKey(priv)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = provider.(cryptoprov.KeyManager).DestroyKeyPairOnSlot(0, keyID)
	})

	signer := priv.(crypto.Signer)
	pub, ok := signer.Public().(*mldsa.PublicKey)
	require.True(t, ok, "%T", signer.Public())
	message := []byte("signed by a real KMS")
	sig, err := signer.Sign(rand.Reader, message, nil)
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(pub, message, sig, nil))
}
