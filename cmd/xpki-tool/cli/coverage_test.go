package cli_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cmd/xpki-tool/cli"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

type revocationFixture struct {
	root, leaf                    *testca.Entity
	server                        *httptest.Server
	rootFile, leafFile, chainFile string
	ocspDER, crlDER               []byte
}

func newRevocationFixture(t *testing.T, status int) *revocationFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root := testca.NewEntity(testca.Subject(pkix.Name{CommonName: "CLI root"}), testca.PrivateKey(key), testca.Authority, testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign))
	f := &revocationFixture{root: root}
	var expiredOCSP, wrongCRL []byte
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocsp", "/expired":
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/ocsp-request", r.Header.Get("Content-Type"))
			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			request, err := ocsp.ParseRequest(body)
			if assert.NoError(t, err) {
				assert.Equal(t, f.leaf.Certificate.SerialNumber, request.SerialNumber)
			}
			if r.URL.Path == "/expired" {
				_, _ = w.Write(expiredOCSP)
			} else {
				_, _ = w.Write(f.ocspDER)
			}
		case "/crl":
			assert.Equal(t, http.MethodGet, r.Method)
			_, _ = w.Write(f.crlDER)
		case "/wrong-crl":
			_, _ = w.Write(wrongCRL)
		case "/short":
			w.Header().Set("Content-Length", "1000")
			_, _ = w.Write([]byte("short"))
		default:
			_, _ = w.Write([]byte("malformed response"))
		}
	}))
	t.Cleanup(f.server.Close)
	f.leaf = root.Issue(testca.Subject(pkix.Name{CommonName: "CLI leaf"}), testca.PrivateKey(key), testca.NotAfter(time.Now().Add(24*time.Hour)), testca.OCSPServer(f.server.URL+"/ocsp"), testca.CrlDpURL(f.server.URL+"/crl"))
	now := time.Now().UTC().Truncate(time.Second)
	response := ocsp.Response{
		Status:           status,
		SerialNumber:     f.leaf.Certificate.SerialNumber,
		ThisUpdate:       now.Add(-time.Minute),
		NextUpdate:       now.Add(time.Hour),
		RevokedAt:        now.Add(-time.Hour),
		RevocationReason: ocsp.KeyCompromise,
	}
	f.ocspDER, err = ocsp.CreateResponse(root.Certificate, root.Certificate, response, root.PrivateKey)
	require.NoError(t, err)
	response.NextUpdate = now.Add(-time.Second)
	expiredOCSP, err = ocsp.CreateResponse(root.Certificate, root.Certificate, response, root.PrivateKey)
	require.NoError(t, err)
	list := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
	}
	if status == ocsp.Revoked {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{
			SerialNumber:   f.leaf.Certificate.SerialNumber,
			RevocationTime: now.Add(-time.Hour),
			ReasonCode:     ocsp.KeyCompromise,
		}}
	}
	f.crlDER, err = x509.CreateRevocationList(rand.Reader, list, root.Certificate, root.PrivateKey)
	require.NoError(t, err)
	other := testca.NewEntity(testca.Subject(pkix.Name{CommonName: "Other issuer"}), testca.Authority, testca.KeyUsage(x509.KeyUsageCertSign|x509.KeyUsageCRLSign))
	wrongCRL, err = x509.CreateRevocationList(rand.Reader, list, other.Certificate, other.PrivateKey)
	require.NoError(t, err)
	// XPKI-105: the existing CLI suite shares a fixed /tmp directory across
	// processes. Keep these fixtures isolated from other test runs.
	dir := t.TempDir()
	f.rootFile = filepath.Join(dir, "root.pem")
	f.leafFile = filepath.Join(dir, "leaf.pem")
	f.chainFile = filepath.Join(dir, "chain.pem")
	require.NoError(t, root.SaveCertAndKey(f.rootFile, "", false))
	require.NoError(t, f.leaf.SaveCertAndKey(f.leafFile, "", false))
	chain := certutil.JoinPEM(testca.ToPEM(f.leaf.Certificate), testca.ToPEM(root.Certificate))
	require.NoError(t, os.WriteFile(f.chainFile, chain, 0600))
	return f
}

func TestCertificateValidationRevocation(t *testing.T) {
	for _, status := range []int{ocsp.Good, ocsp.Revoked, ocsp.Unknown} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newRevocationFixture(t, status)
			var out bytes.Buffer
			ctx := (&cli.Cli{Timeout: 2}).WithWriter(&out)
			output := filepath.Join(t.TempDir(), "verified.pem")
			command := &cli.CertValidateCmd{
				Cert:       f.leafFile,
				Root:       f.rootFile,
				Out:        output,
				Revocation: true,
			}
			require.NoError(t, command.Run(ctx))
			assert.Contains(t, out.String(), "Revocation Info")
			assert.Contains(t, out.String(), "WARNING: Expiring SKI")
			assert.NotContains(t, out.String(), "ERROR:")
			switch status {
			case ocsp.Good:
				assert.Contains(t, out.String(), "OCSP: good")
				assert.Contains(t, out.String(), "CRL: good")
			case ocsp.Revoked:
				assert.Contains(t, out.String(), "OCSP: revoked")
				assert.Contains(t, out.String(), "CRL: revoked")
			case ocsp.Unknown:
				assert.Contains(t, out.String(), "OCSP: unknown")
				assert.Contains(t, out.String(), "CRL: good")
			}
			if status == ocsp.Revoked {
				assert.Contains(t, out.String(), "Certificate chain is revoked")
			} else {
				assert.NotContains(t, out.String(), "Certificate chain is revoked")
			}
			chain, err := certutil.LoadChainFromPEM(output)
			require.NoError(t, err)
			require.NotEmpty(t, chain)
			assert.True(t, f.leaf.Certificate.Equal(chain[0]))
			command.Out = t.TempDir()
			require.Error(t, command.Run(ctx))
		})
	}
	f := newRevocationFixture(t, ocsp.Good)
	for _, endpoints := range []bool{false, true} {
		t.Run(fmt.Sprint("unavailable endpoints ", endpoints), func(t *testing.T) {
			opts := []testca.Option{testca.Subject(pkix.Name{CommonName: "Unavailable endpoints"})}
			if endpoints {
				opts = append(opts, testca.OCSPServer(f.server.URL+"/bad", f.server.URL+"/short"), testca.CrlDpURL(f.server.URL+"/bad", f.server.URL+"/wrong-crl"))
			}
			leaf := f.root.Issue(opts...)
			var out bytes.Buffer
			ctx := (&cli.Cli{}).WithReader(bytes.NewReader(testca.ToPEM(leaf.Certificate))).WithWriter(&out)
			require.NoError(t, (&cli.CertValidateCmd{
				Cert:       "-",
				Root:       f.rootFile,
				Revocation: true,
			}).Run(ctx))
			if endpoints {
				assert.Contains(t, out.String(), "ERROR:")
				assert.Contains(t, out.String(), "failed to parse")
			} else {
				assert.Contains(t, out.String(), "OCSP server is not present")
				assert.Contains(t, out.String(), "CDP is not present")
			}
		})
	}
}

func TestRevocationValidationFailures(t *testing.T) {
	f := newRevocationFixture(t, ocsp.Good)
	client := f.server.Client()
	client.Timeout = time.Second
	for _, tc := range []struct{ path, want string }{
		{"/bad", "failed to parse OCSP"}, {"/expired", "OCSP response is expired"}, {"/short", "unable to download"}, {"://invalid", "unable to create request"},
	} {
		t.Run("OCSP "+tc.path, func(t *testing.T) {
			address := f.server.URL + tc.path
			if tc.path == "://invalid" {
				address = tc.path
			}
			status, _, err := cli.OCSPValidation(context.Background(), client, f.leaf.Certificate, f.root.Certificate, address)
			require.ErrorContains(t, err, tc.want)
			assert.Equal(t, ocsp.Unknown, status)
		})
	}
	for _, tc := range []struct{ path, want string }{
		{"/bad", "failed to parse CRL"}, {"/wrong-crl", "unable to verify CRL signature"}, {"/short", "unable to download"}, {"://invalid", "unable to create request"},
	} {
		t.Run("CRL "+tc.path, func(t *testing.T) {
			address := f.server.URL + tc.path
			if tc.path == "://invalid" {
				address = tc.path
			}
			status, err := cli.CRLValidation(context.Background(), client, f.leaf.Certificate, f.root.Certificate, address)
			require.ErrorContains(t, err, tc.want)
			assert.Equal(t, ocsp.Unknown, status)
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := cli.OCSPValidation(cancelled, client, f.leaf.Certificate, f.root.Certificate, f.server.URL+"/ocsp")
	require.ErrorIs(t, err, context.Canceled)
	_, err = cli.CRLValidation(cancelled, client, f.leaf.Certificate, f.root.Certificate, f.server.URL+"/crl")
	require.ErrorIs(t, err, context.Canceled)
	_, _, err = cli.OCSPValidation(context.Background(), client, f.leaf.Certificate, &x509.Certificate{}, f.server.URL)
	require.Error(t, err)
	// XPKI-103: nil issuers currently panic in CreateOCSPRequest.
	assert.Panics(t, func() {
		_, _, _ = cli.OCSPValidation(context.Background(), client, f.leaf.Certificate, nil, f.server.URL)
	})
}

func TestRevocationFetchAndInfo(t *testing.T) {
	f := newRevocationFixture(t, ocsp.Revoked)
	var out bytes.Buffer
	ctx := (&cli.Cli{Timeout: 2}).WithWriter(&out)
	dir := t.TempDir()
	for _, all := range []bool{false, true} {
		require.NoError(t, (&cli.CRLFetchCmd{
			Cert:   f.chainFile,
			Output: dir,
			All:    all,
			Print:  true,
		}).Run(ctx))
	}
	crlFile := filepath.Join(dir, certutil.GetIssuerID(f.leaf.Certificate)+".crl")
	data, err := os.ReadFile(crlFile)
	require.NoError(t, err)
	assert.Equal(t, f.crlDER, data)
	require.NoError(t, (&cli.CRLInfoCmd{In: crlFile}).Run(ctx))
	require.ErrorContains(t, (&cli.CRLFetchCmd{
		Cert:   f.leafFile,
		Output: filepath.Join(dir, "missing"),
	}).Run(ctx), "unable to write CRL")
	require.NoError(t, (&cli.OCSPFetchCmd{
		Cert:  f.leafFile,
		CA:    f.rootFile,
		Out:   dir,
		Print: true,
	}).Run(ctx))
	require.NoError(t, (&cli.OCSPFetchCmd{Cert: f.chainFile}).Run(ctx))
	ocspFile := filepath.Join(dir, certutil.GetIssuerID(f.leaf.Certificate)+".ocsp")
	data, err = os.ReadFile(ocspFile)
	require.NoError(t, err)
	assert.Equal(t, f.ocspDER, data)
	require.NoError(t, (&cli.OCSPInfoCmd{
		In:     ocspFile,
		Issuer: f.rootFile,
	}).Run(ctx))
	assert.Contains(t, out.String(), "revoked")
	require.ErrorContains(t, (&cli.OCSPFetchCmd{
		Cert: f.chainFile,
		Out:  filepath.Join(dir, "missing"),
	}).Run(ctx), "unable to write OCSP")
	bad := f.root.Issue(testca.Subject(pkix.Name{CommonName: "Bad endpoints"}), testca.OCSPServer(f.server.URL+"/bad"), testca.CrlDpURL(f.server.URL+"/bad"))
	badFile := filepath.Join(dir, "bad.pem")
	require.NoError(t, bad.SaveCertAndKey(badFile, "", false))
	require.ErrorContains(t, (&cli.CRLFetchCmd{
		Cert:  badFile,
		Print: true,
	}).Run(ctx), "unable to parse CRL")
	// XPKI-102: fetch reports endpoint failure on stdout but returns success.
	out.Reset()
	require.NoError(t, (&cli.OCSPFetchCmd{
		Cert: badFile,
		CA:   f.rootFile,
	}).Run(ctx))
	assert.Contains(t, out.String(), "ERROR: failed to parse OCSP")
}

func TestCertificateInfoFilters(t *testing.T) {
	f := newRevocationFixture(t, ocsp.Good)
	expired := f.root.Issue(testca.Subject(pkix.Name{CommonName: "expired"}), testca.NotAfter(time.Now().Add(-time.Hour)))
	far := f.root.Issue(testca.Subject(pkix.Name{CommonName: "far"}), testca.NotAfter(time.Now().Add(72*time.Hour)))
	data := certutil.JoinPEM(testca.ToPEM(expired.Certificate), certutil.JoinPEM(testca.ToPEM(f.leaf.Certificate), testca.ToPEM(far.Certificate)))
	yes, no := true, false
	for _, tc := range []struct {
		name, after string
		noExpired   *bool
		want        []*x509.Certificate
	}{
		{"all", "", nil, []*x509.Certificate{expired.Certificate, f.leaf.Certificate, far.Certificate}},
		{"explicit false", "", &no, []*x509.Certificate{expired.Certificate, f.leaf.Certificate, far.Certificate}},
		{"valid", "", &yes, []*x509.Certificate{f.leaf.Certificate, far.Certificate}},
		{"soon", "48h", &yes, []*x509.Certificate{f.leaf.Certificate}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			ctx := (&cli.Cli{}).WithReader(bytes.NewReader(data)).WithWriter(&out)
			output := filepath.Join(t.TempDir(), "filtered.pem")
			require.NoError(t, (&cli.CertInfoCmd{
				In:         "-",
				Out:        output,
				NotAfter:   tc.after,
				NoExpired:  tc.noExpired,
				Extensions: true,
			}).Run(ctx))
			got, err := certutil.LoadChainFromPEM(output)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPKICommandInputErrors(t *testing.T) {
	f := newRevocationFixture(t, ocsp.Good)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	bad := filepath.Join(dir, "bad")
	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(bad, []byte("invalid"), 0600))
	require.NoError(t, os.WriteFile(empty, nil, 0600))
	type command interface{ Run(*cli.Cli) error }
	for _, tc := range []struct {
		name string
		cmd  command
		want string
	}{
		{"cert info missing", &cli.CertInfoCmd{In: missing}, "unable to load PEM file"},
		{"cert info malformed", &cli.CertInfoCmd{In: bad}, "unable to parse PEM"},
		{"cert info duration", &cli.CertInfoCmd{
			In:       f.leafFile,
			NotAfter: "bad",
		}, "unable to parse --not-after"},
		{"validate missing", &cli.CertValidateCmd{Cert: missing}, "unable to load cert"},
		{"validate missing CA", &cli.CertValidateCmd{
			Cert: f.leafFile,
			CA:   missing,
		}, "unable to load CA bundle"},
		{"validate missing roots", &cli.CertValidateCmd{
			Cert: f.leafFile,
			Root: missing,
		}, "unable to load Root bundle"},
		// XPKI-041: a root file without certificates must not fall back to Force.
		{"validate empty roots", &cli.CertValidateCmd{
			Cert: f.leafFile,
			Root: empty,
		}, "unable to create bundler: optimal bundle requires trust roots"},
		{"validate malformed CA", &cli.CertValidateCmd{
			Cert: f.leafFile,
			CA:   bad,
			Root: f.rootFile,
		}, "unable to create bundler"},
		{"validate malformed cert", &cli.CertValidateCmd{
			Cert: bad,
			Root: f.rootFile,
		}, "unable to verify certificate"},
		{"validate proxy", &cli.CertValidateCmd{
			Cert:  f.leafFile,
			Proxy: "://",
		}, "unable to parse proxy URL"},
		{"CRL info missing", &cli.CRLInfoCmd{In: missing}, "unable to load CRL file"},
		{"CRL info invalid", &cli.CRLInfoCmd{In: bad}, "unable to parse CRL"},
		{"CRL fetch missing", &cli.CRLFetchCmd{
			Cert:  missing,
			Print: true,
		}, "unable to load PEM file"},
		{"CRL fetch invalid", &cli.CRLFetchCmd{
			Cert:  bad,
			Print: true,
		}, "unable to parse PEM"},
		{"CRL fetch empty", &cli.CRLFetchCmd{
			Cert:  empty,
			Print: true,
		}, "certificate not found in PEM"},
		{"CRL fetch proxy", &cli.CRLFetchCmd{
			Cert:  f.leafFile,
			Print: true,
			Proxy: "://",
		}, "unable to parse proxy URL"},
		{"OCSP info missing", &cli.OCSPInfoCmd{In: missing}, "unable to load OCSP file"},
		{"OCSP info invalid", &cli.OCSPInfoCmd{In: bad}, "unable to parse OCSP"},
		{"OCSP info issuer", &cli.OCSPInfoCmd{
			In:     bad,
			Issuer: bad,
		}, "unable to parse issuer"},
		{"OCSP fetch missing", &cli.OCSPFetchCmd{Cert: missing}, "unable to load PEM file"},
		{"OCSP fetch invalid", &cli.OCSPFetchCmd{Cert: bad}, "unable to parse PEM"},
		{"OCSP fetch empty", &cli.OCSPFetchCmd{Cert: empty}, "certificate not found in PEM"},
		{"OCSP fetch missing CA", &cli.OCSPFetchCmd{
			Cert: f.leafFile,
			CA:   missing,
		}, "unable to load CA bundle"},
		{"OCSP fetch invalid CA", &cli.OCSPFetchCmd{
			Cert: f.leafFile,
			CA:   bad,
		}, "unable to parse issuers PEM"},
		{"OCSP fetch no issuer", &cli.OCSPFetchCmd{Cert: f.leafFile}, "unable to find issuer"},
		{"OCSP fetch proxy", &cli.OCSPFetchCmd{
			Cert:  f.chainFile,
			Proxy: "://",
		}, "unable to parse proxy URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := (&cli.Cli{}).WithWriter(io.Discard)
			require.ErrorContains(t, tc.cmd.Run(ctx), tc.want)
		})
	}
}
