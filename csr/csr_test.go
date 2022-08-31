package csr_test

import (
	"crypto/x509"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/x/guid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateRequestValidate(t *testing.T) {
	tcases := []struct {
		r   *csr.CertificateRequest
		err string
	}{
		{
			r:   &csr.CertificateRequest{CommonName: "ekspand.com"},
			err: "",
		},
		{
			r: &csr.CertificateRequest{
				Names: []csr.X509Name{{Organization: "ekspand"}},
			},
			err: "",
		},
		{
			r:   &csr.CertificateRequest{Names: []csr.X509Name{{}}},
			err: "empty name",
		},
	}

	for _, tc := range tcases {
		err := tc.r.Validate()
		if tc.err != "" {
			require.Error(t, err)
			assert.Equal(t, tc.err, err.Error())
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestCertificateRequestName(t *testing.T) {
	r := &csr.CertificateRequest{
		CommonName:   "ekspand.com",
		SerialNumber: "DN_SN_1234",
		Names: []csr.X509Name{
			{
				Organization: "ekspand",
				Province:     "WA",
				Country:      "US",
				EmailAddress: "d@test.com",
				SerialNumber: "namesSN_123",
			},
		},
	}

	n := r.Name()
	// GO does not recognize EmailAddress and skips SN in Names
	assert.Equal(t, "SERIALNUMBER=DN_SN_1234,CN=ekspand.com,O=ekspand,ST=WA,C=US,1.2.840.113549.1.9.1=#0c0a6440746573742e636f6d", n.String())
	assert.Equal(t, "DN_SN_1234", n.SerialNumber)
	assert.Equal(t, "ekspand", n.Organization[0])
	assert.Equal(t, "WA", n.Province[0])
	assert.Equal(t, "US", n.Country[0])
	assert.Len(t, n.Names, 7)
}

func TestX509SubjectName(t *testing.T) {
	r := &csr.X509Subject{
		CommonName:   "ekspand.com",
		SerialNumber: "1234",
		Names: []csr.X509Name{
			{
				Organization: "ekspand",
				Province:     "WA",
				Country:      "US",
			},
		},
	}

	n := r.Name()
	assert.Equal(t, "SERIALNUMBER=1234,CN=ekspand.com,O=ekspand,ST=WA,C=US", n.String())
}

func TestPopulateName(t *testing.T) {
	req := &csr.CertificateRequest{
		CommonName:   "ekspand.com",
		SerialNumber: "1234",
		Names: []csr.X509Name{
			{
				Organization: "ekspand",
				Province:     "CA",
				Country:      "USA",
			},
		},
	}
	n := req.Name()

	subj := &csr.X509Subject{
		Names: []csr.X509Name{
			{
				Organization: "ekspand.com",
				Province:     "WA",
				Country:      "US",
			},
		},
	}
	n2 := csr.PopulateName(nil, n)
	assert.Equal(t, "SERIALNUMBER=1234,CN=ekspand.com,O=ekspand,ST=CA,C=USA", n2.String())

	n2 = csr.PopulateName(subj, n)
	assert.Equal(t, "SERIALNUMBER=1234,CN=ekspand.com,O=ekspand.com,ST=WA,C=US", n2.String())
}

func TestParsePEM(t *testing.T) {
	pem := `-----BEGIN CERTIFICATE REQUEST-----
MIIBSjCB0QIBADBSMQswCQYDVQQGEwJVUzELMAkGA1UEBxMCV0ExEzARBgNVBAoT
CnRydXN0eS5jb20xITAfBgNVBAMMGFtURVNUXSBUcnVzdHkgTGV2ZWwgMSBDQTB2
MBAGByqGSM49AgEGBSuBBAAiA2IABITXg6XB0tSqS+8gLJ8iPEErcIkiXzA2VFuo
Y/joGvOXaq2GXQyOLXPXDLf0LlTNcQww6McTQUBRjocT7USwhR0EdTS4tfdgQi53
lE9lpMy4V5Gbg9x0t08PQ4EpXM+2KaAAMAoGCCqGSM49BAMDA2gAMGUCMQCut6W1
r6sX2RQbFtUPYEjg2EJdwo8KP0KMzDQEzdh0TzkFaTSxBvMjSR9L2HuntIYCMCuZ
18vhP1NmhNWaLmAPbbukNMhlrDgsezJXzN+/RFv3LCzzOLzHR4V90x6sb2jhmQ==
-----END CERTIFICATE REQUEST-----
`
	crt, err := csr.ParsePEM([]byte(pem))
	require.NoError(t, err)
	assert.Equal(t, "C=US, L=WA, O=trusty.com, CN=[TEST] Trusty Level 1 CA", certutil.NameToString(&crt.Subject))

	pem = `-----BEGIN CERTIFICATE REQUEST-----
	MIICiDCCAXACAQAwQzELMAkGA1UEBhMCVVMxCzAJBgNVBAcTAldBMRMwEQYDVQQK
	Ewp0cnVzdHkuY29tMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
	/ZgtJhZdT3bQjaXopUfn4faiL1aCYWlLr8BEJQ==
	-----END CERTIFICATE REQUEST-----
	`
	_, err = csr.ParsePEM([]byte(pem))
	require.Error(t, err)
	assert.Equal(t, "unable to parse PEM", err.Error())

	pem = `-----BEGIN CERTIFICATE-----
MIICiDCCAXACAQAwQzELMAkGA1UEBhMCVVMxCzAJBgNVBAcTAldBMRMwEQYDVQQK
Ewp0cnVzdHkuY29tMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
-----END CERTIFICATE-----
	`
	_, err = csr.ParsePEM([]byte(pem))
	require.Error(t, err)
	assert.Equal(t, "unsupported type in PEM: CERTIFICATE", err.Error())
}

func TestSetSAN(t *testing.T) {
	template := x509.Certificate{}

	csr.SetSAN(&template, []string{
		"ekspand.com",
		"localhost",
		"127.0.0.1",
		"::0",
		"ca@trusty.com",
	})
	assert.Len(t, template.DNSNames, 2)
	assert.Len(t, template.EmailAddresses, 1)
	assert.Len(t, template.IPAddresses, 2)
}

func TestEmailCSR(t *testing.T) {
	pem := `-----BEGIN CERTIFICATE REQUEST-----
MIIDJTCCAg0CAQAwgaYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKExRzYWxlc2ZvcmNlLmNv
bSwgaW5jLjEkMCIGA1UEAxMbc2Jha2tlci5naWEyaC51c2VyLnNmZGMubmV0MSUw
IwYJKoZIhvcNAQkBFhZzYmFra2VyQHNhbGVzZm9yY2UuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7iSk1EcfgnVm0eLfM7wLWIGd+OSo6n/zPqCt
BWbalUuyQJ2qgWpx/aZBKgGEubqdCB+CFm9n2oKGRDFoYF4GDuER+8tzvOQURHj1
GsJl9Iv7osdxQUkWEwX5aiXDV+UQ7sxaVe59ztLMwrxl9FoQD3lf8vnRaJKknBqe
pez0GalFGUd8s4vva0Ysl8H+myeeK6yra/QChSA5+CgdmLgt57uXjL9Fh6Z7cdei
oIuRAwc7xQ11PAyBaka3+p+lt6aUimvGmz5hxetPDA8Rnv1We4JrqUNH+Bk/IIZf
cGR/Q7oYhsJCXj+bbW+0GHpHwPTEwwQSkfvTU282IIzQlf7wHwIDAQABoDkwNwYJ
KoZIhvcNAQkOMSowKDAmBgNVHREEHzAdghtzYmFra2VyLmdpYTJoLnVzZXIuc2Zk
Yy5uZXQwDQYJKoZIhvcNAQELBQADggEBAI8qULnJQaslLaOUINS5vjsKRLym+4kj
/u3PAD2Bj77d9yYDYmNIY9W3msyI3IhNm6ORg4QTU7yReGqJKRe748b4dv80sAY9
NvXzUszyAHVb49tmlgWZXT5DxfYqVp0LaE8DqIaaioEWhjI4lLUsLso+aZ0Q7WWm
0wlPxCI7+vmccVlh4dr5oyCsbZMOSatlZ/VAbBVTu7XDmNDkvoaI5EC9bZUxhpbc
JQVA916hrGX210aBpqKJKAcrCRINSFFOe980oyHLd7/ZaYIdHuJPuft7bxh+9xN4
Zc4ZwfH06sPhMqldBjjIfn8CseykrozZkgH1DzvsRhl510xvXovA7Qs=
-----END CERTIFICATE REQUEST-----`

	csr, err := csr.ParsePEM([]byte(pem))
	require.NoError(t, err)
	assert.NotEmpty(t, csr.Subject.Names)
}

// TODO:
func TestCSR(t *testing.T) {
	crypto := inmemcrypto.NewProvider()
	kr := csr.NewKeyRequest(crypto, "TestCSR"+guid.MustCreate(), "ECDSA", 256, csr.SigningKey)

	req := csr.CertificateRequest{
		CommonName: "trusty.com",
		SAN:        []string{"www.trusty.com", "127.0.0.1", "server@trusty.com", "spiffe://trusty/test"},
		//KeyRequest: kr,
		Names: []csr.X509Name{
			{EmailAddress: "csra@test.com"},
		},
		KeyRequest: kr,
	}

	csrPEM, _, _, _, err := csr.NewProvider(crypto).CreateRequestAndExportKey(&req)
	require.NoError(t, err)

	crt, err := csr.ParsePEM(csrPEM)
	require.NoError(t, err)
	assert.NotEmpty(t, crt.Subject.Names)
}

func TestAddSAN(t *testing.T) {
	r := csr.CertificateRequest{
		SAN: []string{"localhost"},
	}

	r.AddSAN("localhost")
	r.AddSAN("127.0.0.1")

	assert.Len(t, r.SAN, 2)
}
