package authority_test

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"

	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/testca"
	"github.com/effective-security/xpki/x/guid"
	"github.com/stretchr/testify/suite"

	// register providers
	_ "github.com/effective-security/xpki/crypto11"
	_ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"
)

var (
	ca1CertFile = "/tmp/xpki/certs/l1_ca.pem"
	ca1KeyFile  = "/tmp/xpki/certs/l1_ca.key"
	ca2CertFile = "/tmp/xpki/certs/l2_ca.pem"
	ca2KeyFile  = "/tmp/xpki/certs/l2_ca.key"
	//caBundleFile   = "/tmp/xpki/certs/cabundle.pem"
	rootBundleFile = "/tmp/xpki/certs/root_ca.pem"
)

var (
	falseVal = false
	trueVal  = true
)

type testSuite struct {
	suite.Suite

	crypto *cryptoprov.Crypto
}

func (s *testSuite) SetupSuite() {
	var err error
	s.crypto, err = cryptoprov.Load("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.yaml", nil)
	s.Require().NoError(err)

	rootCA := testca.NewEntity(
		testca.Authority,
		testca.Subject(pkix.Name{
			CommonName: "[TEST] Root CA One",
		}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	inter1 := rootCA.Issue(
		testca.Issuer(rootCA),
		testca.Authority,
		testca.Subject(pkix.Name{
			CommonName: "[TEST] Issuing CA One Level 1",
		}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)
	inter2 := inter1.Issue(
		testca.Issuer(inter1),
		testca.Authority,
		testca.Subject(pkix.Name{
			CommonName: "[TEST] Issuing CA One Level 2",
		}),
		testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature),
	)

	tmpDir := filepath.Join(os.TempDir(), "xpki", "certs")
	os.MkdirAll(tmpDir, os.ModePerm)

	rootBundleFile = filepath.Join(tmpDir, "root_ca.pem")
	s.Require().NoError(rootCA.SaveCertAndKey(rootBundleFile, "", false))

	ca1CertFile = filepath.Join(tmpDir, "l1_ca.pem")
	ca1KeyFile = filepath.Join(tmpDir, "l1_ca.key")
	s.Require().NoError(inter1.SaveCertAndKey(ca1CertFile, ca1KeyFile, false))

	ca2CertFile = filepath.Join(tmpDir, "l2_ca.pem")
	ca2KeyFile = filepath.Join(tmpDir, "l2_ca.key")
	s.Require().NoError(inter2.SaveCertAndKey(ca2CertFile, ca2KeyFile, false))
}

func (s *testSuite) TearDownSuite() {
}

func TestAuthority(t *testing.T) {
	suite.Run(t, new(testSuite))
}

func (s *testSuite) TestNewAuthority() {
	//
	// Test empty config
	//
	cfg := &authority.Config{}
	_, err := authority.NewAuthority(cfg, s.crypto)
	s.Require().Error(err)
	s.Equal("missing Authority configuration", err.Error())

	cfg, err = authority.LoadConfig("testdata/ca-config.dev.yaml")
	s.Require().NoError(err)

	//
	// Test invalid Issuer files
	//
	cfg3 := cfg.Copy()
	cfg3.Authority.Issuers = []authority.IssuerConfig{
		{
			Label:    "disabled",
			Disabled: &trueVal,
		},
		{
			Label:   "badkey",
			KeyFile: "not_found",
		},
	}

	_, err = authority.NewAuthority(cfg3, s.crypto)
	s.Require().Error(err)
	s.Equal("unable to create issuer: \"badkey\": unable to create signer: load key file: open not_found: no such file or directory", err.Error())

	//
	// test default Expiry and Renewal from Authority config
	//
	cfg4 := cfg.Copy()
	for i := range cfg4.Authority.Issuers {
		cfg4.Authority.Issuers[i].AIA = &authority.AIAConfig{}
	}

	a, err := authority.NewAuthority(cfg4, s.crypto)
	s.Require().NoError(err)
	issuers := a.Issuers()
	s.Equal(len(cfg4.Authority.Issuers), len(issuers))

	for _, issuer := range issuers {
		s.NotContains(issuer.AiaURL(), "${ISSUER_ID}")
		s.NotContains(issuer.CrlURL(), "${ISSUER_ID}")
		s.NotContains(issuer.OcspURL(), "${ISSUER_ID}")

		issuer.CrlRenewal()
		issuer.CrlExpiry()
		issuer.OcspExpiry()

		i, err := a.GetIssuerByLabel(issuer.Label())
		s.NoError(err)
		s.NotNil(i)

		i, err = a.GetIssuerByKeyID(issuer.SubjectKID())
		s.NoError(err)
		s.NotNil(i)

		i, err = a.GetIssuerByNameHash(crypto.SHA1, issuer.NameHash(crypto.SHA1))
		s.NoError(err)
		s.NotNil(i)
		_, err = a.GetIssuerByNameHash(crypto.SHA256, issuer.NameHash(crypto.SHA1))
		s.Error(err)

		i, err = a.GetIssuerByKeyHash(crypto.SHA1, issuer.KeyHash(crypto.SHA1))
		s.NoError(err)
		s.NotNil(i)
		_, err = a.GetIssuerByKeyHash(crypto.SHA256, issuer.KeyHash(crypto.SHA1))
		s.Error(err)

		for name, p := range cfg.Profiles {
			_, err = a.GetIssuerByProfile(name)
			if p.IssuerLabel == "*" {
				s.Error(err)
			} else {
				s.NoError(err)
			}
		}
	}

	_, err = a.GetIssuerByKeyID("xxxx")
	s.Error(err)
	s.Equal("issuer not found: xxxx", err.Error())

	_, err = a.GetIssuerByLabel("wrong")
	s.Error(err)
	s.Equal("issuer not found: wrong", err.Error())

	_, err = a.GetIssuerByProfile("wrong_profile")
	s.Error(err)
	s.Equal("issuer not found for profile: wrong_profile", err.Error())
}

func (s *testSuite) TestShakenRoot() {
	cfg, err := authority.LoadConfig("testdata/ca-config.bootstrap.yaml")
	s.Require().NoError(err)

	shaken := cfg.Profiles["SHAKEN_ROOT"]
	s.Require().NotNil(shaken)
	s.Require().NotEmpty(shaken.Extensions)

	crypto := s.crypto.Default()
	kr := csr.NewKeyRequest(crypto, "TestShakenRoot"+guid.MustCreate(), "ECDSA", 256, csr.SigningKey)
	rootReq := csr.CertificateRequest{
		CommonName: "[TEST] SHAKEN Root CA",
		KeyRequest: kr,
	}
	rootPEM, _, _, err := authority.NewRoot("SHAKEN_ROOT", cfg, crypto, &rootReq)
	s.Require().NoError(err)

	cert, err := certutil.ParseFromPEM(rootPEM)
	s.Require().NoError(err)

	s.Equal(x509.KeyUsageCertSign, cert.KeyUsage)
	ext := certutil.FindExtension(cert.Extensions, csr.OidExtensionKeyUsage)
	s.Require().NotNil(ext)
	s.False(ext.Critical)
}

func (s *testSuite) TestIssuerSign() {
	crypto := s.crypto.Default()
	kr := csr.NewKeyRequest(crypto, "TestNewRoot"+guid.MustCreate(), "ECDSA", 256, csr.SigningKey)
	rootReq := csr.CertificateRequest{
		CommonName: "[TEST] Trusty Root CA",
		KeyRequest: kr,
	}
	rootPEM, _, rootKey, err := authority.NewRoot("ROOT", rootCfg, crypto, &rootReq)
	s.Require().NoError(err)

	rootSigner, err := s.crypto.NewSignerFromPEM(rootKey)
	s.Require().NoError(err)

	cfg := &authority.IssuerConfig{
		AIA: &authority.AIAConfig{
			AiaURL:  "https://localhost/v1/cert/${ISSUER_ID}",
			OcspURL: "https://localhost/v1/ocsp",
			CrlURL:  "https://localhost/v1/crl/${ISSUER_ID}",
		},
		Label: "TrustyRoot",
		Profiles: map[string]*authority.CertProfile{
			"L1": {
				Usage:       []string{"cert sign", "crl sign"},
				Expiry:      1 * csr.OneYear,
				OCSPNoCheck: true,
				CAConstraint: authority.CAConstraint{
					IsCA:       true,
					MaxPathLen: 1,
				},
				Policies: []csr.CertificatePolicy{
					{
						ID: csr.OID{1, 2, 1000, 1},
						Qualifiers: []csr.CertificatePolicyQualifier{
							{Type: csr.CpsQualifierType, Value: "CPS"},
							{Type: csr.UserNoticeQualifierType, Value: "notice"},
						},
					},
				},
				AllowedExtensions: []csr.OID{
					{1, 3, 6, 1, 5, 5, 7, 1, 1},
				},
			},
			"RestrictedCA": {
				Usage:       []string{"cert sign", "crl sign"},
				Expiry:      1 * csr.OneYear,
				Backdate:    0,
				OCSPNoCheck: true,
				CAConstraint: authority.CAConstraint{
					IsCA:       true,
					MaxPathLen: 0,
				},
				AllowedNames: "^[Tt]rusty CA$",
				AllowedDNS:   "^trusty\\.com$",
				AllowedEmail: "^ca@trusty\\.com$",
				AllowedURI:   "^spiffe://trusty/.*$",
				AllowedCSRFields: &csr.AllowedFields{
					Subject:        true,
					DNSNames:       true,
					IPAddresses:    true,
					EmailAddresses: true,
					URIs:           true,
				},
				AllowedExtensions: []csr.OID{
					{1, 3, 6, 1, 5, 5, 7, 1, 1},
					{2, 5, 29, 17},
				},
			},
			"RestrictedServer": {
				Usage:        []string{"server auth", "signing", "key encipherment"},
				Expiry:       1 * csr.OneYear,
				Backdate:     0,
				AllowedNames: "trusty.com",
				AllowedDNS:   "^(www\\.)?trusty\\.com$",
				AllowedEmail: "^ca@trusty\\.com$",
				AllowedURI:   "^spiffe://trusty/.*$",
				AllowedCSRFields: &csr.AllowedFields{
					Subject:        true,
					DNSNames:       true,
					IPAddresses:    true,
					EmailAddresses: true,
					URIs:           true,
				},
				AllowedExtensions: []csr.OID{
					{1, 3, 6, 1, 5, 5, 7, 1, 1},
					{2, 5, 29, 17},
				},
			},
			"default": {
				Usage:        []string{"server auth", "signing", "key encipherment"},
				Expiry:       1 * csr.OneYear,
				Backdate:     0,
				AllowedNames: "trusty.com",
				AllowedURI:   "^spiffe://trusty/.*$",
				AllowedCSRFields: &csr.AllowedFields{
					Subject:  true,
					DNSNames: true,
					URIs:     true,
				},
				AllowedExtensions: []csr.OID{
					{1, 2, 3},
					{2, 5, 29, 17},
				},
			},
		},
	}

	for name, profile := range cfg.Profiles {
		s.NoError(profile.Validate(), "failed to validate %s profile", name)
	}

	rootCA, err := authority.CreateIssuer(cfg, rootPEM, nil, nil, rootSigner)
	s.Require().NoError(err)

	s.Run("default", func() {
		req := csr.CertificateRequest{
			CommonName: "trusty.com",
			SAN:        []string{"www.trusty.com", "127.0.0.1", "server@trusty.com", "spiffe://trusty/test"},
			KeyRequest: kr,
		}

		csrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&req)
		s.Require().NoError(err)

		sreq := csr.SignRequest{
			Request: string(csrPEM),
			SAN:     req.SAN,
			Extensions: []csr.X509Extension{
				{
					ID:    csr.OID{1, 2, 3},
					Value: "0500",
				},
			},
		}

		crt, _, err := rootCA.Sign(sreq)
		s.Require().NoError(err)
		s.Equal(req.CommonName, crt.Subject.CommonName)
		s.Equal(rootReq.CommonName, crt.Issuer.CommonName)
		s.False(crt.IsCA)
		s.Equal(-1, crt.MaxPathLen)
		s.NotEmpty(crt.IPAddresses)
		s.NotEmpty(crt.EmailAddresses)
		s.NotEmpty(crt.DNSNames)
		s.NotEmpty(crt.URIs)

		// test unknown profile
		sreq.Profile = "unknown"
		_, _, err = rootCA.Sign(sreq)
		s.Require().Error(err)
		s.Equal("unsupported profile: unknown", err.Error())
	})

	s.Run("Valid L1", func() {
		caReq := csr.CertificateRequest{
			CommonName: "[TEST] Trusty Level 1 CA",
			KeyRequest: kr,
		}

		caCsrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&caReq)
		s.Require().NoError(err)

		sreq := csr.SignRequest{
			SAN:     []string{"trusty@ekspand.com", "trusty.com", "127.0.0.1"},
			Request: string(caCsrPEM),
			Profile: "L1",
			Subject: &csr.X509Subject{
				CommonName: "Test L1 CA",
			},
		}

		caCrt, _, err := rootCA.Sign(sreq)
		s.Require().NoError(err)
		s.Equal(sreq.Subject.CommonName, caCrt.Subject.CommonName)
		s.Equal(rootReq.CommonName, caCrt.Issuer.CommonName)
		s.True(caCrt.IsCA)
		s.Equal(1, caCrt.MaxPathLen)
	})

	s.Run("RestrictedCA/NotAllowedCN", func() {
		caReq := csr.CertificateRequest{
			CommonName: "[TEST] Trusty Level 2 CA",
			KeyRequest: kr,
			SAN:        []string{"ca@trusty.com", "trusty.com", "127.0.0.1"},
			Names: []csr.X509Name{
				{
					O: "trusty",
					C: "US",
				},
			},
		}

		caCsrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&caReq)
		s.Require().NoError(err)

		sreq := csr.SignRequest{
			Request: string(caCsrPEM),
			Profile: "RestrictedCA",
		}

		_, _, err = rootCA.Sign(sreq)
		s.Require().Error(err)
		s.Equal("CommonName does not match allowed list: [TEST] Trusty Level 2 CA", err.Error())
	})

	s.Run("RestrictedCA/NotAllowedDNS", func() {
		caReq := csr.CertificateRequest{
			CommonName: "trusty CA",
			KeyRequest: kr,
			SAN:        []string{"ca@trusty.com", "trustyca.com", "127.0.0.1"},
			Names: []csr.X509Name{
				{
					O: "trusty",
					C: "US",
				},
			},
		}

		caCsrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&caReq)
		s.Require().NoError(err)

		sreq := csr.SignRequest{
			Request: string(caCsrPEM),
			Profile: "RestrictedCA",
		}

		_, _, err = rootCA.Sign(sreq)
		s.Require().Error(err)
		s.Equal("DNS Name does not match allowed list: trustyca.com", err.Error())
	})

	s.Run("RestrictedCA/NotAllowedURI", func() {
		caReq := csr.CertificateRequest{
			CommonName: "trusty CA",
			KeyRequest: kr,
			SAN:        []string{"ca@trusty.com", "127.0.0.1", "spiffe://google.com/ca"},
			Names: []csr.X509Name{
				{
					O: "trusty",
					C: "US",
				},
			},
		}

		caCsrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&caReq)
		s.Require().NoError(err)

		sreq := csr.SignRequest{
			SAN:     caReq.SAN,
			Request: string(caCsrPEM),
			Profile: "RestrictedCA",
		}

		_, _, err = rootCA.Sign(sreq)
		s.Require().Error(err)
		s.Equal("URI does not match allowed list: spiffe://google.com/ca", err.Error())
	})

	s.Run("RestrictedCA/NotAllowedEmail", func() {
		caReq := csr.CertificateRequest{
			CommonName: "trusty CA",
			KeyRequest: kr,
			SAN:        []string{"rootca@trusty.com", "trusty.com", "127.0.0.1"},
			Names: []csr.X509Name{
				{
					O: "trusty",
					C: "US",
				},
			},
		}

		caCsrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&caReq)
		s.Require().NoError(err)

		sreq := csr.SignRequest{
			Request: string(caCsrPEM),
			Profile: "RestrictedCA",
		}

		_, _, err = rootCA.Sign(sreq)
		s.Require().Error(err)
		s.Equal("Email does not match allowed list: rootca@trusty.com", err.Error())
	})

	s.Run("RestrictedCA/Valid", func() {
		caReq := csr.CertificateRequest{
			CommonName: "trusty CA",
			KeyRequest: kr,
			//SAN:        []string{"ca@trusty.com", "trusty.com", "127.0.0.1"},
			Names: []csr.X509Name{
				{
					O: "trusty",
					C: "US",
				},
			},
		}

		caCsrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&caReq)
		s.Require().NoError(err)

		sreq := csr.SignRequest{
			Request: string(caCsrPEM),
			Profile: "RestrictedCA",
		}

		caCrt, _, err := rootCA.Sign(sreq)
		s.Require().NoError(err)
		s.Equal(caReq.CommonName, caCrt.Subject.CommonName)
		s.Equal(rootReq.CommonName, caCrt.Issuer.CommonName)
		s.True(caCrt.IsCA)
		s.Equal(0, caCrt.MaxPathLen)
		s.True(caCrt.MaxPathLenZero)
		// for CA, these are not set:
		s.Empty(caCrt.DNSNames)
		s.Empty(caCrt.EmailAddresses)
		s.Empty(caCrt.IPAddresses)
	})

	s.Run("RestrictedServer/Valid", func() {
		req := csr.CertificateRequest{
			CommonName: "trusty.com",
			KeyRequest: kr,
			SAN:        []string{"ca@trusty.com", "www.trusty.com", "127.0.0.1"},
			Names: []csr.X509Name{
				{
					O: "trusty",
					C: "US",
				},
			},
		}

		csrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&req)
		s.Require().NoError(err)

		sreq := csr.SignRequest{
			Request: string(csrPEM),
			Profile: "RestrictedServer",
		}

		crt, _, err := rootCA.Sign(sreq)
		s.Require().NoError(err)
		s.Equal(req.CommonName, crt.Subject.CommonName)
		s.Equal(rootReq.CommonName, crt.Issuer.CommonName)
		s.False(crt.IsCA)
		s.Contains(crt.DNSNames, "www.trusty.com")
		s.Contains(crt.EmailAddresses, "ca@trusty.com")
		s.NotEmpty(crt.IPAddresses)
	})
}
