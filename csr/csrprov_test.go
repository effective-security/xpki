package csr_test

import (
	"context"
	"crypto"
	"testing"

	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/v2/csr"
	"github.com/effective-security/xpki/v2/internal/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// register supported
	_ "github.com/effective-security/xpki/v2/crypto11"
)

var softHSMConfig = testenv.SoftHSMConfig()

// loadProvider returns the SoftHSM provider. It skips the test when the
// SoftHSM config is missing, or fails it with XPKI_INTEGRATION=required
// (XPKI-100); a present config must load.
func loadProvider(t *testing.T) cryptoprov.Provider {
	t.Helper()
	testenv.RequireFile(t, "SoftHSM config", softHSMConfig)
	p, err := cryptoprov.LoadProvider(softHSMConfig)
	require.NoError(t, err)

	assert.Equal(t, "SoftHSM", p.Manufacturer())

	return p
}

func TestGenerateKeyAndRequest(t *testing.T) {
	defprov := loadProvider(t)
	prov := csr.NewProvider(defprov)

	tt := []struct {
		name   string
		req    *csr.CertificateRequest
		experr string
	}{
		{
			name:   "no key",
			req:    &csr.CertificateRequest{},
			experr: "invalid key request",
		},
		{
			name: "valid rsa",
			req: prov.NewSigningCertificateRequest("label", "RSA", 2048, "localhost", []csr.X509Name{
				{
					Organization:       "org1",
					OrganizationalUnit: "unit1",
				},
			}, []string{"127.0.0.1", "localhost"}),
			experr: "",
		},
		{
			name: "valid rsa",
			req: prov.NewSigningCertificateRequest("label", "ECDSA", 256, "localhost", []csr.X509Name{
				{
					Organization:       "org1",
					OrganizationalUnit: "unit1",
				},
			}, []string{"127.0.0.1", "localhost"}),
			experr: "",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			cr, k, kid, err := prov.GenerateKeyAndRequest(t.Context(), tc.req)
			if tc.experr != "" {
				assert.Nil(t, k)
				require.Error(t, err)
				assert.Equal(t, tc.experr, err.Error())
			} else {
				require.NoError(t, err)
				require.NotNil(t, cr)
				require.NotNil(t, k)
				assert.NotEmpty(t, kid)

				signer := k.(crypto.Signer)
				assert.Equal(t, tc.req.KeyRequest.SigAlgo(), csr.DefaultSigAlgo(signer))

				_, err = prov.SignRequest(t.Context(), k, tc.req)
				require.NoError(t, err)

				assert.Equal(t, tc.req.KeyRequest.SigAlgo(), csr.DefaultSigAlgo(signer))
			}
		})
	}
}

// TestSignRequestCancelled checks that a CSR is not signed with an ended
// context.
func TestSignRequestCancelled(t *testing.T) {
	t.Parallel()
	inmem := inmemcrypto.NewProvider()
	prov := csr.NewProvider(inmem)
	req := &csr.CertificateRequest{
		CommonName: "ctx.example.test",
		KeyRequest: prov.NewKeyRequest("ctx", csr.AlgoECDSA, csr.CurveP256, csr.SigningKey),
	}
	_, key, _, err := prov.GenerateKeyAndRequest(t.Context(), req)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = prov.SignRequest(ctx, key, req)
	require.ErrorIs(t, err, context.Canceled)
	_, _, _, err = prov.GenerateKeyAndRequest(ctx, req)
	require.ErrorIs(t, err, context.Canceled)
}

func TestCreateRequestAndExportKey(t *testing.T) {
	defprov := loadProvider(t)
	prov := csr.NewProvider(defprov)

	tt := []struct {
		name   string
		req    *csr.CertificateRequest
		experr string
	}{
		{
			name:   "empty",
			req:    &csr.CertificateRequest{},
			experr: "process request: invalid key request",
		},
		{
			name:   "no key",
			req:    &csr.CertificateRequest{CommonName: "localhost"},
			experr: "process request: invalid key request",
		},
		{
			name: "valid rsa",
			req: prov.NewSigningCertificateRequest("label", "RSA", 2048, "localhost", []csr.X509Name{
				{
					Organization:       "org1",
					OrganizationalUnit: "unit1",
				},
			}, []string{"127.0.0.1", "localhost"}),
			experr: "",
		},
		{
			name: "valid rsa",
			req: prov.NewSigningCertificateRequest("label", "ECDSA", 256, "localhost", []csr.X509Name{
				{
					Organization:       "org1",
					OrganizationalUnit: "unit1",
				},
			}, []string{"127.0.0.1", "localhost"}),
			experr: "",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			cr, k, kid, pub, err := prov.CreateRequestAndExportKey(t.Context(), tc.req)
			if tc.experr != "" {
				assert.Nil(t, k)
				require.Error(t, err)
				assert.Equal(t, tc.experr, err.Error())
			} else {
				require.NoError(t, err)
				require.NotNil(t, cr)
				require.NotNil(t, k)
				require.NotNil(t, pub)
				assert.NotEmpty(t, kid)
			}
		})
	}
}
