package authority_test

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/effective-security/x/guid"
	"github.com/effective-security/xpki/authority"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var rootCfg = &authority.Config{
	Profiles: map[string]*authority.CertProfile{
		"ROOT": {
			Usage:  []string{"cert sign", "crl sign"},
			Expiry: 5 * csr.OneYear,
			CAConstraint: authority.CAConstraint{
				IsCA:       true,
				MaxPathLen: -1,
			},
		},
	},
}

func (s *testSuite) TestNewRoot() {
	crypto := s.crypto.Default()
	kr := csr.NewKeyRequest(crypto, "TestNewRoot"+guid.MustCreate(), "ECDSA", 384, csr.SigningKey)
	req := csr.CertificateRequest{
		CommonName: "[TEST] Trusty Root CA",
		KeyRequest: kr,
	}

	certPEM, _, key, err := authority.NewRoot("ROOT", rootCfg, crypto, &req)
	s.Require().NoError(err)

	crt, err := certutil.ParseFromPEM(certPEM)
	s.Require().NoError(err)
	s.Equal(req.CommonName, crt.Subject.CommonName)
	s.Equal(req.CommonName, crt.Issuer.CommonName)
	s.True(crt.IsCA)
	s.True(crt.BasicConstraintsValid)
	s.Equal(-1, crt.MaxPathLen)

	_, err = s.crypto.NewSignerFromPEM(key)
	s.Require().NoError(err)
}

func TestNewRootEx(t *testing.T) {
	csrCA := `
	{
		"common_name": "[TEST] One Root CA",
		"names": [
			{
				"C": "US",
				"L": "CA",
				"O": "ekspand.com",
				"OU": "dev"
			}
		]
	}`

	defprov := inmemcrypto.NewProvider()
	prov := csr.NewProvider(defprov)

	req := csr.CertificateRequest{
		KeyRequest: prov.NewKeyRequest("TestNewRootEx", "ECDSA", 256, csr.SigningKey),
	}

	_, _, _, err := authority.NewRoot("ROOT", rootCfg, defprov, &req)
	require.NoError(t, err)

	err = json.Unmarshal([]byte(csrCA), &req)
	require.NoError(t, err, "invalid csr")

	var key, csrPEM, certPEM []byte
	certPEM, csrPEM, key, err = authority.NewRoot("ROOT", rootCfg, defprov, &req)
	require.NoError(t, err, "init CA")
	assert.NotNil(t, csrPEM)

	keyStr := string(key)
	assert.Contains(t, keyStr, "BEGIN")

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(certPEM))
	require.True(t, ok, "failed to parse root certificate")

	block, _ := pem.Decode([]byte(certPEM))
	require.NotEqual(t, block, "failed to parse certificate PEM")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")
	assert.True(t, cert.IsCA)
	assert.Equal(t, "[TEST] One Root CA", cert.Subject.CommonName)
	assert.Equal(t, []string{"dev"}, cert.Subject.OrganizationalUnit)
	assert.Equal(t, []string{"ekspand.com"}, cert.Subject.Organization)
	assert.Equal(t, cert.KeyUsage, x509.KeyUsageCRLSign|x509.KeyUsageCertSign)
	assert.Equal(t, -1, cert.MaxPathLen)
	assert.True(t, cert.BasicConstraintsValid)

	opts := x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageCodeSigning,
		},
	}

	_, err = cert.Verify(opts)
	require.NoError(t, err, "failed to verify certificate")
}
