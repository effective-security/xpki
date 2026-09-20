package csr_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
	"time"

	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/oid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestParseCSRConstraints(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	valid, err := asn1.Marshal(csr.BasicConstraints{
		IsCA:       true,
		MaxPathLen: 2,
	})
	require.NoError(t, err)
	zero, err := asn1.Marshal(csr.BasicConstraints{
		IsCA:       true,
		MaxPathLen: 0,
	})
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		value   []byte
		want    string
		pathlen int
	}{
		{"CA", valid, "", 2}, {"zero path", zero, "", 0}, {"invalid", []byte("bad"), "failed to parse BasicConstraints", 0}, {"trailing", append(append([]byte(nil), valid...), 0), "failed to parse BasicConstraints: trailing data", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "CA request"},
				ExtraExtensions: []pkix.Extension{{
					Id:    oid.ExtensionBasicConstraints,
					Value: tc.value,
				}, {
					Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
					Value: []byte{5, 0},
				}},
			}, key)
			require.NoError(t, err)
			template, err := csr.Parse(der)
			if tc.want != "" {
				require.ErrorContains(t, err, tc.want)
				assert.Nil(t, template)
				return
			}
			require.NoError(t, err)
			assert.True(t, template.IsCA)
			assert.True(t, template.BasicConstraintsValid)
			assert.Equal(t, tc.pathlen, template.MaxPathLen)
			assert.Equal(t, tc.pathlen == 0, template.MaxPathLenZero)
			require.Len(t, template.ExtraExtensions, 1)
			assert.Equal(t, asn1.ObjectIdentifier{1, 2, 3, 4}, template.ExtraExtensions[0].Id)
			der[len(der)-1] ^= 1
			_, err = csr.Parse(der)
			require.ErrorContains(t, err, "key mismatch")
		})
	}
	_, err = csr.Parse([]byte("bad"))
	require.ErrorContains(t, err, "failed to parse")
}

func TestGeneralNameParsing(t *testing.T) {
	dn := pkix.Name{
		CommonName:   "Directory",
		Organization: []string{"Example"},
	}.ToRDNSequence()
	dnDER, err := asn1.Marshal(dn)
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		tag  int
		data []byte
		want string
	}{
		{"DNS", 2, []byte("host.example"), ""},
		{"directory", 4, dnDER, ""},
		{"bad directory", 4, []byte("bad"), "asn1"},
		{"email", 1, []byte("user@example.test"), ""},
		{"IPv4", 7, []byte{127, 0, 0, 1}, ""},
		{"IPv6", 7, net.ParseIP("2001:db8::1").To16(), ""},
		{"invalid IP", 7, []byte{1, 2}, "cannot parse IP address"},
		{"URI", 6, []byte("https://host.example.test/path"), ""},
		{"URI without host", 6, []byte("urn:example:resource"), ""},
		{"bad URI escape", 6, []byte("https://%zz"), "cannot parse"},
		{"absolute host", 6, []byte("https://example.test."), "cannot parse"},
		{"empty label", 6, []byte("https://host..test"), "cannot parse"},
		{"non ASCII label", 6, []byte("https://éxample.test"), "cannot parse"},
		{"unknown tag", 8, []byte{1, 2, 3}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := asn1.Marshal(asn1.RawValue{
				Class: asn1.ClassContextSpecific,
				Tag:   tc.tag,
				Bytes: tc.data,
			})
			require.NoError(t, err)
			raw := asn1.RawValue{Bytes: der}
			name := csr.GeneralName{DNSName: "unchanged"}
			err = name.Parse(raw)
			if tc.want != "" {
				require.ErrorContains(t, err, tc.want)
				assert.Equal(t, "unchanged", name.DNSName)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, raw, name.Raw)
			switch tc.tag {
			case 1:
				assert.Equal(t, string(tc.data), name.EmailAddres)
			case 2:
				assert.Equal(t, string(tc.data), name.DNSName)
			case 4:
				assert.Equal(t, dn, name.DirectoryName)
			case 6:
				require.NotNil(t, name.URI)
				assert.Equal(t, string(tc.data), name.URI.String())
			case 7:
				assert.Equal(t, net.IP(tc.data), name.IPAddres)
			}
		})
	}
	var name csr.GeneralName
	require.Error(t, name.Parse(asn1.RawValue{Bytes: []byte("bad")}))
	require.EqualError(t, name.Parse(asn1.RawValue{Bytes: []byte{0x82, 1, 'a', 0}}), "trailing bytes")
}

func TestCSRProviderInvalidRequests(t *testing.T) {
	provider := csr.NewProvider(inmemcrypto.NewProvider())
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, _, _, err = provider.GenerateKeyAndRequest(&csr.CertificateRequest{})
	require.EqualError(t, err, "invalid key request")
	_, _, _, _, err = provider.CreateRequestAndExportKey(&csr.CertificateRequest{Names: []csr.X509Name{{}}})
	require.ErrorContains(t, err, "invalid request")
	_, _, _, _, err = provider.CreateRequestAndExportKey(&csr.CertificateRequest{CommonName: "valid name"})
	require.ErrorContains(t, err, "process request: invalid key request")
	_, err = provider.SignRequest(struct{}{}, &csr.CertificateRequest{CommonName: "test"})
	require.EqualError(t, err, "unable to convert key to crypto.Signer")
	for _, value := range []string{"hex:zz", "base64:%%%"} {
		_, err = provider.SignRequest(key, &csr.CertificateRequest{
			CommonName: "test",
			Extensions: []csr.X509Extension{{
				ID:    csr.OID{1, 2, 3},
				Value: value,
			}},
		})
		require.ErrorContains(t, err, "invalid extensions")
	}
	req := provider.NewSigningCertificateRequest("test", "ecdsa", 256, "test", nil, []string{"https://%zz", "127.0.0.1", "user@example.test", "https://host.example.test/path", "host.example.test"})
	data, err := provider.SignRequest(key, req)
	require.NoError(t, err)
	cert, err := csr.ParsePEM(data)
	require.NoError(t, err)
	assert.Equal(t, []string{"user@example.test"}, cert.EmailAddresses)
	assert.Equal(t, []string{"host.example.test"}, cert.DNSNames)
	require.Len(t, cert.URIs, 1)
	require.Len(t, cert.IPAddresses, 1)
	var duration csr.Duration
	require.Error(t, yaml.Unmarshal([]byte("[]"), &duration))
	require.Error(t, yaml.Unmarshal([]byte("bad duration"), &duration))
	require.NoError(t, yaml.Unmarshal([]byte("1h"), &duration))
	assert.Equal(t, time.Hour, duration.TimeDuration())
	var objectID csr.OID
	require.Error(t, yaml.Unmarshal([]byte("{}"), &objectID))
	require.Error(t, yaml.Unmarshal([]byte("bad.oid"), &objectID))
}
