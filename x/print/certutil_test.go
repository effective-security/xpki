package print_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/oid"
	"github.com/effective-security/xpki/x/print"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const (
	testLeafCN          = "[TEST] Print Leaf"
	testRootCN          = "[TEST] Print Root"
	testNoExtCN         = "no-extensions"
	testOCSPResponderCN = "ocsp-responder"
	testDNSName         = "print.example.com"
	testEmail           = "admin@print.example.com"
	testOCSP            = "http://ocsp.print.example.com"
	testCRL             = "http://crl.print.example.com/ca.crl"
	testIssuingURL      = "http://ca.print.example.com/ca.crt"
	testSPIFFE          = "spiffe://print.example.com/leaf"
	testIPv4            = "192.0.2.1"
	testIPv6            = "2001:db8::1"
)

var (
	unknownExtensionOID = asn1.ObjectIdentifier{1, 3, 999, 1}
	// CAB Forum domain-validated certificate policy.
	testPolicyOID = asn1.ObjectIdentifier{2, 23, 140, 1, 2, 1}
)

func Test_PrintCerts(t *testing.T) {
	certs := loadCerts(t,
		"testdata/trusty_peer_wfe.pem",
		"testdata/goog-shaken-chain.pem",
	)

	spiffe, err := url.Parse(testSPIFFE)
	require.NoError(t, err)

	certs = append(certs, &x509.Certificate{
		Subject:               pkix.Name{CommonName: testLeafCN},
		Issuer:                pkix.Name{CommonName: testRootCN},
		SerialNumber:          big.NewInt(42),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		SubjectKeyId:          []byte{0x01, 0x02, 0x03},
		AuthorityKeyId:        []byte{0x0a, 0x0b, 0x0c},
		DNSNames:              []string{testDNSName, "www." + testDNSName},
		IPAddresses:           []net.IP{net.ParseIP(testIPv4), net.ParseIP(testIPv6)},
		URIs:                  []*url.URL{spiffe},
		EmailAddresses:        []string{testEmail},
		CRLDistributionPoints: []string{testCRL},
		OCSPServer:            []string{testOCSP},
		IssuingCertificateURL: []string{testIssuingURL},
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{testPolicyOID},
		Extensions: []pkix.Extension{
			{
				Id:       oid.ExtensionKeyUsage,
				Critical: true,
				Value:    []byte{0x03, 0x02, 0x01, 0x86},
			},
			{
				Id:       oid.ExtensionExtendedKeyUsage,
				Critical: false,
				Value:    []byte{0x30, 0x0a},
			},
			{
				Id:       oid.ExtensionCertificatePolicies,
				Critical: false,
				Value:    []byte{0x30, 0x00},
			},
			{
				Id:       unknownExtensionOID,
				Critical: false,
				Value:    []byte{0x05, 0x00},
			},
		},
	})
	// A cert with no extensions covers the verbose-but-empty skip.
	certs = append(certs, &x509.Certificate{
		Subject:      pkix.Name{CommonName: testNoExtCN},
		Issuer:       pkix.Name{CommonName: testRootCN},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	})

	wVerbose := bytes.NewBuffer([]byte{})
	print.Certificates(wVerbose, certs, true)
	out := wVerbose.String()
	assert.NotContains(t, out, "ERROR:")
	assert.Contains(t, out, "SKID: ")
	assert.Contains(t, out, "IKID: ")
	assert.Contains(t, out, "Subject: ")
	assert.Contains(t, out, "Serial: 42")
	assert.Contains(t, out, "Issuer: ")
	assert.Contains(t, out, "Issued: ")
	assert.Contains(t, out, "Expires: ")
	assert.Contains(t, out, "CA: true")
	assert.Contains(t, out, "  Basic Constraints Valid: true")
	assert.Contains(t, out, "  Max Path: 2")
	assert.Contains(t, out, "DNS Names:\n")
	assert.Contains(t, out, "  - "+testDNSName+"\n")
	assert.Contains(t, out, "IP Addresses:\n")
	assert.Contains(t, out, "  - "+testIPv4+"\n")
	assert.Contains(t, out, "  - "+testIPv6+"\n")
	assert.Contains(t, out, "URIs:\n")
	assert.Contains(t, out, "  - "+testSPIFFE+"\n")
	assert.Contains(t, out, "Emails:\n")
	assert.Contains(t, out, "  - "+testEmail+"\n")
	assert.Contains(t, out, "CRL Distribution Points:\n")
	assert.Contains(t, out, "  - "+testCRL+"\n")
	assert.Contains(t, out, "OCSP Servers:\n")
	assert.Contains(t, out, "  - "+testOCSP+"\n")
	assert.Contains(t, out, "Issuing Certificates:\n")
	assert.Contains(t, out, "  - "+testIssuingURL+"\n")
	assert.Contains(t, out, "Extensions:\n")
	assert.Contains(t, out, "  oid: "+oid.ExtensionKeyUsage.String()+" (Key Usage)\n")
	assert.Contains(t, out, "  oid: "+oid.ExtensionExtendedKeyUsage.String()+" (Extended KeyUsage)\n")
	assert.Contains(t, out, "  oid: "+oid.ExtensionCertificatePolicies.String()+" (Certificate Policies)\n")
	assert.Contains(t, out, "  oid: "+unknownExtensionOID.String()+"\n")
	assert.Contains(t, out, "  identifiers: "+testPolicyOID.String()+"\n")
	assert.Contains(t, out, "  - signing, cert sign\n")
	assert.Contains(t, out, "  - server auth, client auth\n")
	assert.Contains(t, out, "==================================== 1 ====================================\n")

	wQuiet := bytes.NewBuffer([]byte{})
	print.Certificates(wQuiet, certs, false)
	quiet := wQuiet.String()
	assert.Contains(t, quiet, "SKID: ")
	assert.Contains(t, quiet, testDNSName)
	assert.NotContains(t, quiet, "Extensions:")
}

func Test_PrintCertsRequest(t *testing.T) {
	csrs := []string{
		"testdata/trusty_dev_issuer1_ca.csr",
		"testdata/trusty_dev_peer.csr",
		"testdata/trusty_dev_root_ca.csr",
		"testdata/trusty_untrusted_peer.csr",
	}

	for _, f := range csrs {
		certsRaw, err := os.ReadFile(f)
		require.NoError(t, err)

		block, _ := pem.Decode(certsRaw)
		require.NotNil(t, block)
		require.Equal(t, "CERTIFICATE REQUEST", block.Type)

		csrv, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)

		if len(csrv.DNSNames) == 0 {
			csrv.DNSNames = []string{testDNSName}
		}
		csrv.EmailAddresses = append(csrv.EmailAddresses, testEmail)
		csrv.IPAddresses = append(csrv.IPAddresses, net.ParseIP(testIPv4))
		u, err := url.Parse(testSPIFFE)
		require.NoError(t, err)
		csrv.URIs = append(csrv.URIs, u)
		if len(csrv.Extensions) == 0 {
			csrv.Extensions = []pkix.Extension{
				{Id: oid.ExtensionSubjectAltName},
			}
		}

		w := bytes.NewBuffer([]byte{})
		print.CertificateRequest(w, csrv)

		out := w.String()
		assert.NotContains(t, out, "ERROR:")
		assert.Contains(t, out, "Subject: ")
		assert.Contains(t, out, "DNS Names:\n")
		assert.Contains(t, out, "IP Addresses:\n")
		assert.Contains(t, out, "  - "+testIPv4+"\n")
		assert.Contains(t, out, "URIs:\n")
		assert.Contains(t, out, "  - "+testSPIFFE+"\n")
		assert.Contains(t, out, "Emails:\n")
		assert.Contains(t, out, "  - "+testEmail+"\n")
		assert.Contains(t, out, "Extensions:\n")
	}
}

func Test_CertificateList(t *testing.T) {
	producedAt, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	require.NoError(t, err)
	nextUpdate, err := time.Parse(time.RFC3339, "2012-12-01T22:08:41+00:00")
	require.NoError(t, err)

	sn := big.NewInt(204570238945)
	res := &x509.RevocationList{
		Issuer:     pkix.Name{CommonName: testRootCN},
		ThisUpdate: producedAt,
		NextUpdate: nextUpdate,
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   sn,
				RevocationTime: producedAt,
			},
		},
	}

	w := bytes.NewBuffer([]byte{})
	print.CertificateList(w, res)
	out := w.String()
	assert.Contains(t, out, "Issuer: ")
	assert.Contains(t, out, "Issued: ")
	assert.Contains(t, out, "Expires: ")
	assert.Contains(t, out, "Revoked:\n")
	assert.Contains(t, out, sn.String())
}

func Test_OCSPResponse(t *testing.T) {
	producedAt, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	require.NoError(t, err)
	thisUpdate, err := time.Parse(time.RFC3339, "2012-12-01T22:08:41+00:00")
	require.NoError(t, err)

	sn := big.NewInt(204570238945)
	res := &ocsp.Response{
		ProducedAt:       producedAt,
		ThisUpdate:       thisUpdate,
		NextUpdate:       thisUpdate.Add(24 * time.Hour),
		SerialNumber:     sn,
		Status:           ocsp.Revoked,
		RevocationReason: ocsp.KeyCompromise,
		RevokedAt:        producedAt,
		RawResponderName: []byte{0x30, 0x03, 0x02, 0x01, 0x01},
		ResponderKeyHash: []byte{0xaa, 0xbb},
		Extensions: []pkix.Extension{
			{
				Id:       oid.OCSPNoCheck,
				Critical: false,
				Value:    []byte{0x05, 0x00},
			},
		},
		Certificate: &x509.Certificate{
			Subject:      pkix.Name{CommonName: testOCSPResponderCN},
			Issuer:       pkix.Name{CommonName: testRootCN},
			SerialNumber: big.NewInt(7),
			NotBefore:    producedAt,
			NotAfter:     thisUpdate.Add(24 * time.Hour),
		},
	}

	w := bytes.NewBuffer([]byte{})
	print.OCSPResponse(w, res, true)
	out := w.String()
	assert.Contains(t, out, "Serial: "+sn.String()+"\n")
	assert.Contains(t, out, "Status: revoked\n")
	assert.Contains(t, out, fmt.Sprintf("Revocation reason: %d\n", ocsp.KeyCompromise))
	assert.Contains(t, out, "Revoked: ")
	assert.Contains(t, out, "Responder name hash: ")
	assert.Contains(t, out, "Responder key hash: ")
	assert.Contains(t, out, "Extensions:\n")
	assert.Contains(t, out, "  id: "+oid.OCSPNoCheck.String()+", critical: false\n")
	assert.Contains(t, out, "Certificate:\n")
	assert.Contains(t, out, "Subject: CN="+testOCSPResponderCN)
}

func Test_OCSPResponse_Unknown(t *testing.T) {
	producedAt, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	require.NoError(t, err)

	res := &ocsp.Response{
		ProducedAt:   producedAt,
		ThisUpdate:   producedAt,
		NextUpdate:   producedAt.Add(time.Hour),
		SerialNumber: big.NewInt(1),
		Status:       ocsp.Unknown,
	}

	w := bytes.NewBuffer([]byte{})
	print.OCSPResponse(w, res, true)
	out := w.String()
	assert.Contains(t, out, "Status: unknown\n")
	assert.NotContains(t, out, "Revocation reason:")
	assert.NotContains(t, out, "Responder name hash:")
	assert.NotContains(t, out, "Responder key hash:")
	assert.NotContains(t, out, "Extensions:")
	assert.NotContains(t, out, "Certificate:")
}

func TestCSRandCert(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		csr  []byte
		cert []byte
		want string
	}{
		{
			name: "all",
			key:  []byte("key"),
			csr:  []byte("csr"),
			cert: []byte("cert"),
			want: "{\"cert\":\"cert\",\"csr\":\"csr\",\"key\":\"key\"}\n",
		},
		{
			name: "empty",
			want: "{}\n",
		},
		{
			name: "cert only",
			cert: []byte("cert"),
			want: "{\"cert\":\"cert\"}\n",
		},
		{
			name: "key only",
			key:  []byte("key"),
			want: "{\"key\":\"key\"}\n",
		},
		{
			name: "csr only",
			csr:  []byte("csr"),
			want: "{\"csr\":\"csr\"}\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := bytes.NewBuffer([]byte{})
			print.CertAndKey(w, tc.key, tc.csr, tc.cert)
			assert.Equal(t, tc.want, w.String())
		})
	}
}

func Test_CertificateList_NoNextUpdate(t *testing.T) {
	thisUpdate, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	require.NoError(t, err)

	res := &x509.RevocationList{
		ThisUpdate: thisUpdate,
	}

	w := bytes.NewBuffer([]byte{})
	print.CertificateList(w, res)
	out := w.String()
	assert.Contains(t, out, "Expires: not set\n")
	assert.NotContains(t, out, "0001-01-01")
	assert.NotContains(t, out, "Revoked:")
}

func Test_OCSPResponse_NoNextUpdate(t *testing.T) {
	producedAt, err := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
	require.NoError(t, err)

	res := &ocsp.Response{
		ProducedAt:   producedAt,
		ThisUpdate:   producedAt,
		SerialNumber: big.NewInt(1),
		Status:       ocsp.Good,
	}

	w := bytes.NewBuffer([]byte{})
	print.OCSPResponse(w, res, false)
	out := w.String()
	assert.Contains(t, out, "Expires: not set\n")
	assert.NotContains(t, out, "0001-01-01")
	assert.Contains(t, out, "Status: good\n")
}

func Test_JSON(t *testing.T) {
	v := map[string]string{
		"cert": "cert",
		"csr":  "csr",
		"key":  "key",
	}

	w := bytes.NewBuffer([]byte{})
	print.JSON(w, v)
	out := w.String()
	exp := `{
  "cert": "cert",
  "csr": "csr",
  "key": "key"
}
`
	assert.Equal(t, exp, out)
}

func Test_JSON_MarshalError(t *testing.T) {
	w := bytes.NewBuffer([]byte{})
	print.JSON(w, make(chan int))
	assert.Equal(t, "\n", w.String())
}

func loadCerts(t *testing.T, files ...string) []*x509.Certificate {
	t.Helper()
	var all []*x509.Certificate
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		certs, err := certutil.ParseChainFromPEM(raw)
		require.NoError(t, err)
		require.NotEmpty(t, certs)
		all = append(all, certs...)
	}
	return all
}
