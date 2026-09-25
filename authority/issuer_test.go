package authority_test

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func (s *testSuite) TestNewIssuer() {
	cfg, err := authority.LoadConfig("testdata/ca-config.dev.yaml")
	s.Require().NoError(err)
	s.Require().NotNil(cfg.Authority)

	for _, isscfg := range cfg.Authority.Issuers {
		if isscfg.GetDisabled() {
			continue
		}

		issuer, err := authority.NewIssuer(&isscfg, s.crypto)
		s.Require().NoError(err)

		s.NotNil(issuer.Bundle())
		s.NotNil(issuer.Signer())
		s.NotEmpty(issuer.PEM())
		s.NotEmpty(issuer.Label())
		s.NotEmpty(issuer.KeyHash(crypto.SHA1))
		s.Nil(issuer.Profile("notfound"))

		//s.Equal(fmt.Sprintf("http://localhost:7880/v1/crl/%s.crl", issuer.SubjectKID()), issuer.CrlURL())
		//s.Equal(fmt.Sprintf("http://localhost:7880/v1/cert/%s.crt", issuer.SubjectKID()), issuer.AiaURL())
		//s.NotNil(issuer.AIAExtension("server"))
		//s.Nil(issuer.AIAExtension("not_supported"))
	}
}

func (s *testSuite) TestNewIssuerErrors() {

	aia := &authority.AIAConfig{
		AiaURL:  "https://localhost/v1/cert/${ISSUER_ID}",
		OcspURL: "https://localhost/v1/ocsp",
		CrlURL:  "https://localhost/v1/crl/${ISSUER_ID}",
	}
	cfg := &authority.IssuerConfig{
		KeyFile: "not_found",
		AIA:     aia,
	}
	_, err := authority.NewIssuer(cfg, s.crypto)
	s.EqualError(err, `unable to create signer: load key file: open not_found: no such file or directory`)

	cfg = &authority.IssuerConfig{
		KeyFile:  ca2KeyFile,
		CertFile: "not_found",
	}
	_, err = authority.NewIssuer(cfg, s.crypto)
	s.EqualError(err, `failed to load cert: open not_found: no such file or directory`)

	cfg = &authority.IssuerConfig{
		CertFile:       ca2CertFile,
		KeyFile:        ca2KeyFile,
		CABundleFile:   ca1CertFile,
		RootBundleFile: "not_found",
	}
	_, err = authority.NewIssuer(cfg, s.crypto)
	s.EqualError(err, `failed to load root-bundle: open not_found: no such file or directory`)

	cfg = &authority.IssuerConfig{
		CertFile:       ca2CertFile,
		KeyFile:        ca2KeyFile,
		CABundleFile:   "not_found",
		RootBundleFile: rootBundleFile,
	}
	_, err = authority.NewIssuer(cfg, s.crypto)
	s.EqualError(err, `failed to load ca-bundle: open not_found: no such file or directory`)
}

// TestNewIssuerDelegatedOCSP builds an issuer with a delegated OCSP profile
// from files; NewIssuer used to deadlock issuing the responder (XPKI-051).
func TestNewIssuerDelegatedOCSP(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.pem")
	keyFile := filepath.Join(dir, "ca.key")
	ca := testca.NewEntity(
		testca.Authority,
		testca.Subject(pkix.Name{CommonName: "[TEST] Delegating CA"}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	require.NoError(t, ca.SaveCertAndKey(certFile, keyFile, false))

	prov, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
	require.NoError(t, err)
	profile := &authority.CertProfile{
		Usage:       []string{"digital signature", "ocsp signing"},
		Expiry:      csr.OneYear,
		OCSPNoCheck: true,
	}
	require.NoError(t, profile.Validate())
	cfg := &authority.IssuerConfig{
		Label:    "delegating",
		CertFile: certFile,
		KeyFile:  keyFile,
		AIA: &authority.AIAConfig{
			OcspURL:              "http://localhost/ocsp",
			DelegatedOCSPProfile: "ocsp",
		},
		Profiles: map[string]*authority.CertProfile{
			"ocsp": profile,
		},
	}

	done := make(chan struct{})
	var issuer *authority.Issuer
	go func() {
		defer close(done)
		issuer, err = authority.NewIssuer(cfg, prov)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("NewIssuer with delegated_ocsp_profile did not return (XPKI-051)")
	}
	require.NoError(t, err)

	responder, err := issuer.CreateDelegatedOCSPSigner()
	require.NoError(t, err)
	assert.Equal(t, "OCSP Responder", responder.Cert.Subject.CommonName)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, responder.Cert.ExtKeyUsage)
	require.NoError(t, responder.Cert.CheckSignatureFrom(ca.Certificate))

	der, err := issuer.SignOCSP(&authority.OCSPSignRequest{
		SerialNumber: big.NewInt(7),
		Status:       authority.OCSPStatusGood,
	})
	require.NoError(t, err)
	response, err := ocsp.ParseResponse(der, ca.Certificate)
	require.NoError(t, err)
	require.NotNil(t, response.Certificate)
	assert.True(t, responder.Cert.Equal(response.Certificate))
	assert.Equal(t, big.NewInt(7), response.SerialNumber)
}
