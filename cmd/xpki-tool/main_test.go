package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(t *testing.T) {
	out := bytes.NewBuffer([]byte{})
	errout := bytes.NewBuffer([]byte{})
	rc := 0
	exit := func(c int) {
		rc = c
	}

	realMain([]string{"xpki-tool", "version"}, out, errout, exit)
	assert.Equal(t, 80, rc)
	assert.Equal(t, "xpki-tool: error: unexpected argument version\n", errout.String())
	assert.Empty(t, out.String())
}

// TestMainOCSPFetchFailure checks that `ocsp fetch` exits with status 1 when
// every OCSP endpoint fails (XPKI-102).
func TestMainOCSPFetchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("malformed response"))
	}))
	t.Cleanup(server.Close)
	root := testca.NewEntity(testca.Subject(pkix.Name{CommonName: "exit root"}), testca.Authority, testca.KeyUsage(x509.KeyUsageCertSign))
	leaf := root.Issue(testca.Subject(pkix.Name{CommonName: "exit leaf"}), testca.OCSPServer(server.URL+"/ocsp"))
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.pem")
	leafFile := filepath.Join(dir, "leaf.pem")
	require.NoError(t, root.SaveCertAndKey(rootFile, "", false))
	require.NoError(t, leaf.SaveCertAndKey(leafFile, "", false))

	out := bytes.NewBuffer([]byte{})
	errout := bytes.NewBuffer([]byte{})
	rc := 0
	exit := func(c int) {
		rc = c
	}

	realMain([]string{"xpki-tool", "ocsp", "fetch", leafFile, "--ca", rootFile}, out, errout, exit)
	assert.Equal(t, 1, rc)
	assert.Contains(t, errout.String(), "xpki-tool: error: no valid OCSP response from 1 endpoint(s): "+server.URL+"/ocsp: failed to parse OCSP")
	assert.Contains(t, out.String(), server.URL+"/ocsp : ERROR: failed to parse OCSP")
}
