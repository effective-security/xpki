package certutil_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bundlerCA(t testing.TB, name string, parent *testca.Entity, opts ...testca.Option) *testca.Entity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	opts = append(opts, testca.PrivateKey(key), testca.Subject(pkix.Name{CommonName: name}), testca.Authority, testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign))
	if parent != nil {
		opts = append(opts, testca.Issuer(parent))
	}
	return testca.NewEntity(opts...)
}

func TestBundlerAIA(t *testing.T) {
	const leafName = "service.example.test"
	for _, format := range []string{"der", "pem", "invalid", "truncated", "disabled"} {
		t.Run(format, func(t *testing.T) {
			var requests atomic.Int32
			var intermediate *testca.Entity
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch format {
				case "invalid":
					_, _ = w.Write([]byte("not a certificate"))
				case "truncated":
					w.Header().Set("Content-Length", "1000")
					_, _ = w.Write([]byte("short"))
				case "pem":
					_, _ = w.Write(pem.EncodeToMemory(&pem.Block{
						Type:  "CERTIFICATE",
						Bytes: intermediate.Certificate.Raw,
					}))
				default:
					_, _ = w.Write(intermediate.Certificate.Raw)
				}
			}))
			defer server.Close()
			root := bundlerCA(t, "Root", nil)
			intermediate = bundlerCA(t, "Intermediate CA", root, testca.IssuingCertificateURL(server.URL))
			leaf := intermediate.Issue(testca.Subject(pkix.Name{CommonName: leafName}), testca.DNSName(leafName, "www.example.test"), testca.IssuingCertificateURL(server.URL))
			old := certutil.IntermediateStash
			certutil.IntermediateStash = filepath.Join(t.TempDir(), "stash")
			t.Cleanup(func() { certutil.IntermediateStash = old })
			client := server.Client()
			client.Timeout = time.Second
			b, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil, certutil.WithAIA(format != "disabled"), certutil.WithHTTPClient(client))
			require.NoError(t, err)
			chain, err := b.Bundle([]*x509.Certificate{leaf.Certificate}, leaf.PrivateKey)
			if format == "invalid" || format == "truncated" || format == "disabled" {
				require.ErrorContains(t, err, "unable to verify the certificate chain")
				var unknown x509.UnknownAuthorityError
				require.ErrorAs(t, err, &unknown)
				assert.Nil(t, chain)
				if format == "disabled" {
					assert.Zero(t, requests.Load())
				} else {
					assert.Positive(t, requests.Load())
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []*x509.Certificate{leaf.Certificate, intermediate.Certificate}, chain.Chain)
			assert.Same(t, root.Certificate, chain.Root)
			assert.ElementsMatch(t, []string{leafName, "www.example.test"}, chain.Hostnames)
			assert.True(t, b.KnownIssuers[string(intermediate.Certificate.Signature)])
			files, err := os.ReadDir(certutil.IntermediateStash)
			require.NoError(t, err)
			require.Len(t, files, 1)
			data, err := os.ReadFile(filepath.Join(certutil.IntermediateStash, files[0].Name()))
			require.NoError(t, err)
			saved, err := certutil.ParseFromPEM(data)
			require.NoError(t, err)
			assert.True(t, intermediate.Certificate.Equal(saved))
			before := requests.Load()
			_, err = b.Bundle([]*x509.Certificate{leaf.Certificate}, nil)
			require.NoError(t, err)
			assert.Equal(t, before, requests.Load(), "cached intermediate avoids another fetch")
		})
	}
}

func TestBundlerFilesAndValidation(t *testing.T) {
	root := bundlerCA(t, "Root", nil)
	intermediate := bundlerCA(t, "Intermediate", root)
	leaf := intermediate.Issue(testca.Subject(pkix.Name{CommonName: "leaf.example"}))
	dir := t.TempDir()
	rootFile, intFile := filepath.Join(dir, "root.pem"), filepath.Join(dir, "intermediate.pem")
	certFile, keyFile := filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, root.SaveCertAndKey(rootFile, "", false))
	require.NoError(t, intermediate.SaveCertAndKey(intFile, "", false))
	require.NoError(t, leaf.SaveCertAndKey(certFile, keyFile, true))
	b, err := certutil.LoadBundler(rootFile, intFile, certutil.WithKeyUsages(x509.ExtKeyUsageAny))
	require.NoError(t, err)
	chain, err := b.ChainFromFile(certFile, keyFile, "")
	require.NoError(t, err)
	assert.Same(t, chain.Cert, chain.Chain[0])
	assert.NotNil(t, chain.Key)
	chain, err = b.ChainFromFile(certFile, "", "")
	require.NoError(t, err)
	assert.Nil(t, chain.Key)
	emptyFile := filepath.Join(dir, "empty.pem")
	require.NoError(t, os.WriteFile(emptyFile, nil, 0600))
	for _, tc := range []struct{ name, cert, key, want string }{
		{"missing certificate", dir + "/missing", "", "failed to load bundle"},
		{"missing key", certFile, dir + "/missing", "failed to load private key"},
		{"empty key", certFile, emptyFile, "empty private key"},
		{"certificate as key", certFile, certFile, "private key"},
		{"empty certificate", emptyFile, "", "failed to parse certificates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := b.ChainFromFile(tc.cert, tc.key, "password")
			require.ErrorContains(t, err, tc.want)
			assert.Nil(t, got)
		})
	}
	badFile := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(badFile, []byte("invalid PEM"), 0600))
	for _, tc := range []struct{ name, root, inter, want string }{
		{"missing roots", dir + "/missing", "", "root bundle failed to load"},
		{"missing intermediates", rootFile, dir + "/missing", "intermediate CA bundle failed to load"},
		{"bad roots", badFile, "", "failed to parse root bundle"},
		{"bad intermediates", rootFile, badFile, "failed to parse intermediate bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := certutil.LoadBundler(tc.root, tc.inter)
			require.ErrorContains(t, err, tc.want)
			assert.Nil(t, got)
		})
	}
	_, err = b.ChainFromPEM([]byte("invalid"), nil, "")
	require.Error(t, err)
	bundle, status, err := certutil.LoadAndVerifyBundleFromPEM(certFile, intFile, rootFile)
	require.NoError(t, err)
	assert.False(t, status.IsUntrusted())
	assert.True(t, leaf.Certificate.Equal(bundle.Cert))
	for _, paths := range [][3]string{{dir + "/missing", intFile, rootFile}, {certFile, dir + "/missing", rootFile}, {certFile, intFile, dir + "/missing"}} {
		_, _, err := certutil.LoadAndVerifyBundleFromPEM(paths[0], paths[1], paths[2])
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}

func TestBundlerChainBehavior(t *testing.T) {
	root := bundlerCA(t, "Root", nil)
	intermediate := bundlerCA(t, "Intermediate", root, testca.NotAfter(time.Now().Add(48*time.Hour)))
	leaf := intermediate.Issue(testca.Subject(pkix.Name{CommonName: "leaf"}), testca.NotAfter(time.Now().Add(24*time.Hour)))
	force, err := certutil.NewBundler(nil, nil, certutil.WithBundleFlavor(certutil.Force))
	require.NoError(t, err)
	chain, err := force.Bundle([]*x509.Certificate{root.Certificate, intermediate.Certificate, leaf.Certificate}, leaf.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, leaf.Chain(), chain.Chain)
	assert.True(t, chain.Status.IsExpiring())
	assert.Nil(t, chain.Root)
	assert.Equal(t, leaf.Certificate.NotAfter, chain.Expires)
	assert.Contains(t, chain.Status.Messages[0], "#1 #2")
	assert.Len(t, chain.Status.ExpiringSKIs, 2)
	// XPKI-036: empty input is an error; see TestBundlerEmptyInput.
	chain, err = force.Bundle(nil, nil)
	require.ErrorIs(t, err, certutil.ErrNoCertificates)
	assert.Nil(t, chain)
	_, err = force.Bundle([]*x509.Certificate{leaf.Certificate, root.Certificate}, nil)
	require.EqualError(t, err, "unable to verify the certificate chain")
	optimal, err := certutil.NewBundler([]*x509.Certificate{root.Certificate}, nil)
	require.NoError(t, err)
	_, err = optimal.Bundle([]*x509.Certificate{root.Certificate}, nil)
	require.EqualError(t, err, "self-signed certificate")
	chain, err = optimal.Bundle([]*x509.Certificate{leaf.Certificate, intermediate.Certificate}, nil)
	require.NoError(t, err)
	assert.Len(t, chain.Chain, 2)
	for _, ocsp := range []bool{false, true} {
		t.Run(fmt.Sprint("direct root OCSP ", ocsp), func(t *testing.T) {
			opts := []testca.Option{testca.Subject(pkix.Name{CommonName: "direct"})}
			if ocsp {
				opts = append(opts, testca.OCSPServer("http://ocsp.example.test"))
			}
			direct := root.Issue(opts...)
			chain, err := optimal.Bundle([]*x509.Certificate{direct.Certificate}, nil)
			require.NoError(t, err)
			if ocsp {
				assert.Len(t, chain.Chain, 2)
			} else {
				assert.Len(t, chain.Chain, 1)
			}
		})
	}
	expired := root.Issue(testca.Subject(pkix.Name{CommonName: "expired"}), testca.NotAfter(time.Now().Add(-time.Hour)))
	_, err = optimal.Bundle([]*x509.Certificate{expired.Certificate}, nil)
	require.ErrorContains(t, err, "expired")
	_, edkey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed := root.Issue(testca.Subject(pkix.Name{CommonName: "ed25519"}), testca.PrivateKey(edkey))
	_, err = force.Bundle([]*x509.Certificate{ed.Certificate}, edkey)
	require.EqualError(t, err, "unsupported key")
	_, err = force.Bundle([]*x509.Certificate{ed.Certificate}, nil)
	require.EqualError(t, err, "unsupported key")
	_, err = force.Bundle([]*x509.Certificate{intermediate.Certificate}, leaf.PrivateKey)
	require.EqualError(t, err, "key mismatch")
	other := bundlerCA(t, "Other", nil)
	_, err = force.Bundle([]*x509.Certificate{intermediate.Certificate}, other.PrivateKey)
	require.EqualError(t, err, "key mismatch")
	chain, err = force.Bundle([]*x509.Certificate{intermediate.Certificate}, intermediate.PrivateKey)
	require.NoError(t, err)
	assert.Same(t, intermediate.PrivateKey, chain.Key)
	assert.True(t, certutil.ExpiryTime(nil).IsZero())
	assert.Equal(t, leaf.Certificate.NotAfter, certutil.ExpiryTime([]*x509.Certificate{root.Certificate, leaf.Certificate}))
}
