package authority

import (
	"crypto/x509"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
)

// GenCert creates certificate and stores key and certs to specified location
func (ca *Issuer) GenCert(crypto cryptoprov.Provider, req *csr.CertificateRequest, profile, certFile, keyFile string) (*x509.Certificate, []byte, error) {
	logger.KV(xlog.INFO,
		"profile", profile,
		"cn", req.CommonName,
		"cert", certFile,
	)
	c := csr.NewProvider(crypto)
	csrPEM, key, _, _, err := c.CreateRequestAndExportKey(req)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "process request")
	}

	crt, certPEM, err := ca.Sign(csr.SignRequest{
		SAN:        req.SAN,
		Request:    string(csrPEM),
		Profile:    profile,
		Extensions: req.Extensions,
		Subject: &csr.X509Subject{
			CommonName:   req.CommonName,
			Names:        req.Names,
			SerialNumber: req.SerialNumber,
		},
	})
	if err != nil {
		return nil, nil, err
	}

	err = os.Rename(certFile, certFile+".bak")
	if err != nil {
		logger.KV(xlog.WARNING, "reason", "move", "file", certFile, "err", err.Error())
	}
	err = os.Rename(keyFile, keyFile+".bak")
	if err != nil {
		logger.KV(xlog.WARNING, "reason", "move", "file", keyFile, "err", err.Error())
	}

	certBundle := strings.TrimSpace(string(certPEM)) + "\n" + ca.PEM()
	err = os.WriteFile(certFile, []byte(certBundle), 0664)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	err = os.WriteFile(keyFile, key, 0600)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	return crt, certPEM, nil
}
