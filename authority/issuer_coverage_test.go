package authority

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuerProofRoundTrip(t *testing.T) {
	for _, kind := range []string{"ECDSA", "RSA"} {
		t.Run(kind, func(t *testing.T) {
			issuer, _ := ocspTestIssuer(t)
			if kind == "RSA" {
				entity := testca.NewEntity(testca.Subject(pkix.Name{CommonName: "RSA proof"}), testca.Authority, testca.KeyUsage(x509.KeyUsageCertSign))
				var err error
				issuer, err = CreateIssuer(&IssuerConfig{Label: "proof"}, testca.ToPEM(entity.Certificate), nil, nil, entity.PrivateKey)
				require.NoError(t, err)
			}
			data := []byte("proof payload")
			proof, err := issuer.SignProof(data)
			require.NoError(t, err)
			require.NotEmpty(t, proof)
			require.NoError(t, issuer.VerifyProof(data, proof))
			require.Error(t, issuer.VerifyProof([]byte("tampered"), proof))
			require.ErrorContains(t, issuer.VerifyProof(data, "%%%"), "unable to verify proof")
		})
	}
}

func TestIssuerSignExtensions(t *testing.T) {
	extensionID := csr.OID{1, 2, 3, 4}
	allowedID := csr.OID{1, 2, 3, 5}
	for _, tc := range []struct {
		name                                          string
		omit, csrExtension, allowed, profileExtension bool
		value, want                                   string
	}{
		{
			name:    "request allowed",
			allowed: true,
			value:   "hex:0500",
		},
		{
			name:  "request denied",
			value: "hex:0500",
			want:  "extension not allowed: 1.2.3.4",
		},
		{
			name:  "request omitted",
			omit:  true,
			value: "hex:0500",
		},
		{
			name:    "invalid request value",
			allowed: true,
			value:   "hex:zz",
			want:    "failed to decode",
		},
		{
			name:             "invalid profile value",
			allowed:          true,
			profileExtension: true,
			value:            "hex:zz",
			want:             "failed to decode",
		},
		{
			name:             "profile wins",
			allowed:          true,
			profileExtension: true,
			value:            "hex:0500",
		},
		{
			name:         "CSR denied",
			csrExtension: true,
			want:         "extension not allowed: 1.2.3.4",
		},
		{
			name:         "CSR allowed",
			csrExtension: true,
			allowed:      true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer, entity := ocspTestIssuer(t)
			profile := &CertProfile{
				Expiry:            csr.Duration(time.Hour),
				Usage:             []string{"digital signature"},
				AllowedExtensions: []csr.OID{allowedID},
				AllowedCSRFields:  &csr.AllowedFields{Subject: true},
			}
			if tc.allowed {
				profile.AllowedExtensions = append(profile.AllowedExtensions, extensionID)
			}
			extension := csr.X509Extension{
				ID:    extensionID,
				Value: tc.value,
			}
			if tc.profileExtension {
				profile.Extensions = []csr.X509Extension{extension}
			}
			issuer.AddProfile("default", profile)
			assert.Same(t, profile, issuer.Profile("default"))
			assert.Contains(t, issuer.Profiles(), "default")
			issuer.cfg.OmitDisabledExtensions = tc.omit
			template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "signing test"}}
			request := csr.SignRequest{}
			if tc.csrExtension {
				template.ExtraExtensions = []pkix.Extension{{
					Id:    asn1.ObjectIdentifier(extensionID),
					Value: []byte{5, 0},
				}}
			} else {
				requestExtension := extension
				if tc.profileExtension {
					requestExtension.Value = "hex:0400"
				}
				request.Extensions = []csr.X509Extension{requestExtension}
			}
			der, err := x509.CreateCertificateRequest(rand.Reader, template, entity.PrivateKey)
			require.NoError(t, err)
			request.Request = string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE REQUEST",
				Bytes: der,
			}))
			cert, data, err := issuer.Sign(request)
			if tc.want != "" {
				require.ErrorContains(t, err, tc.want)
				assert.Nil(t, cert)
				assert.Nil(t, data)
				return
			}
			require.NoError(t, err)
			require.NoError(t, cert.CheckSignatureFrom(entity.Certificate))
			ext := certutil.FindExtension(cert.Extensions, asn1.ObjectIdentifier(extensionID))
			if tc.omit {
				assert.Nil(t, ext)
			} else {
				require.NotNil(t, ext)
				assert.Equal(t, []byte{5, 0}, ext.Value)
			}
		})
	}
}

func TestIssuerTemplateErrors(t *testing.T) {
	issuer, entity := ocspTestIssuer(t)
	profile := &CertProfile{
		Expiry: csr.Duration(time.Hour),
		Usage:  []string{"digital signature"},
	}
	issuer.AddProfile("default", profile)
	_, _, err := issuer.Sign(csr.SignRequest{Request: "not a CSR"})
	require.ErrorContains(t, err, "failed to parse CSR")
	_, err = CreateIssuer(&IssuerConfig{}, []byte("invalid"), nil, nil, entity.PrivateKey)
	require.ErrorContains(t, err, "failed to create signing CA cert bundle")
	for _, tc := range []struct {
		name    string
		profile CertProfile
		want    string
	}{
		{"missing expiry", CertProfile{Usage: []string{"digital signature"}}, "expiry is not set"},
		{"missing usage", CertProfile{Expiry: csr.Duration(time.Hour)}, "invalid profile: no key usages"},
		{"bad policy", CertProfile{
			Expiry:   csr.Duration(time.Hour),
			Usage:    []string{"digital signature"},
			Policies: []csr.CertificatePolicy{{ID: csr.OID{9}}},
		}, "invalid profile policies"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{PublicKey: entity.PrivateKey.Public()}
			require.ErrorContains(t, issuer.fillTemplate(template, &tc.profile, time.Time{}, time.Time{}), tc.want)
		})
	}
	require.Error(t, issuer.fillTemplate(&x509.Certificate{PublicKey: struct{}{}}, profile, time.Time{}, time.Time{}))
	self := &Issuer{}
	_, err = self.sign(&x509.Certificate{})
	require.EqualError(t, err, "CA template is not specified")
	_, err = issuer.sign(&x509.Certificate{
		PublicKey: struct{}{},
		NotAfter:  entity.Certificate.NotAfter.Add(time.Hour),
	})
	require.ErrorContains(t, err, "create certificate")
	assert.Equal(t, []string{"1.2.3"}, extensionsList(&x509.Certificate{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}}}}))
}
