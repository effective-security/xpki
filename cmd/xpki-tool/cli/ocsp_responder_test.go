package cli_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/xpki/v2/cmd/xpki-tool/cli"
	"github.com/effective-security/xpki/v2/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// TestOCSPValidationResponder accepts a response only from a responder the
// issuer authorized (ROADMAP item 11): the CA itself, or a certificate it
// issued with the OCSP signing extended key usage. Before, any certificate of
// the CA, such as a client certificate, could sign a good status.
func TestOCSPValidationResponder(t *testing.T) {
	t.Parallel()
	ca := testca.NewEntity(
		testca.Subject(pkix.Name{CommonName: "Responder CA"}),
		testca.Authority,
		testca.KeyUsage(x509.KeyUsageCertSign),
	)
	var response atomic.Pointer[[]byte]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(*response.Load())
	}))
	t.Cleanup(server.Close)
	leaf := ca.Issue(testca.Subject(pkix.Name{CommonName: "Responder leaf"}), testca.OCSPServer(server.URL))
	client := server.Client()
	client.Timeout = 5 * time.Second

	now := time.Now().UTC().Truncate(time.Minute)
	for _, tc := range []struct {
		name      string
		responder *testca.Entity
		want      string
	}{
		{
			name:      "CA",
			responder: ca,
		},
		{
			name:      "delegated",
			responder: ca.Issue(testca.ExtKeyUsage(x509.ExtKeyUsageOCSPSigning)),
		},
		{
			name:      "client certificate",
			responder: ca.Issue(testca.ExtKeyUsage(x509.ExtKeyUsageClientAuth)),
			want:      "invalid OCSP response: OCSP responder certificate has no OCSP signing extended key usage",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, err := ocsp.CreateResponse(ca.Certificate, tc.responder.Certificate, ocsp.Response{
				Status:       ocsp.Good,
				SerialNumber: leaf.Certificate.SerialNumber,
				ThisUpdate:   now,
				NextUpdate:   now.Add(time.Hour),
				Certificate:  tc.responder.Certificate,
			}, tc.responder.PrivateKey)
			require.NoError(t, err)
			response.Store(&der)

			status, raw, err := cli.OCSPValidation(context.Background(), client, leaf.Certificate, ca.Certificate, server.URL)
			assert.Equal(t, der, raw)
			if tc.want == "" {
				require.NoError(t, err)
				assert.Equal(t, ocsp.Good, status)
				return
			}
			require.EqualError(t, err, tc.want)
			assert.Equal(t, ocsp.Unknown, status)
		})
	}
}
