package csr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/mail"
	"net/url"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "csr")

// Provider extends cryptoprov.Crypto functionality to support CSP procesing
// and certificate signing
type Provider struct {
	provider cryptoprov.Provider
}

// NewProvider returns an instance of CSR provider
func NewProvider(provider cryptoprov.Provider) *Provider {
	return &Provider{
		provider: provider,
	}
}

// NewSigningCertificateRequest creates new request for signing certificate
func (c *Provider) NewSigningCertificateRequest(
	keyLabel, algo string, keySize int,
	CN string,
	names []X509Name,
	san []string,
) *CertificateRequest {
	return &CertificateRequest{
		KeyRequest: c.NewKeyRequest(keyLabel, algo, keySize, SigningKey),
		CommonName: CN,
		Names:      names,
		SAN:        san,
	}
}

// CreateRequestAndExportKey takes a certificate request and generates a key and
// CSR from it.
func (c *Provider) CreateRequestAndExportKey(req *CertificateRequest) (csrPEM, key []byte, keyID string, pub crypto.PublicKey, err error) {
	err = req.Validate()
	if err != nil {
		err = errors.WithMessage(err, "invalid request")
		return
	}

	var priv crypto.PrivateKey

	csrPEM, priv, keyID, err = c.GenerateKeyAndRequest(req)
	if err != nil {
		key = nil
		err = errors.WithMessage(err, "process request")
		return
	}

	s, ok := priv.(crypto.Signer)
	if !ok {
		key = nil
		err = errors.Errorf("unable to convert key to crypto.Signer")
		return
	}
	pub = s.Public()

	uri, keyBytes, err := c.provider.ExportKey(keyID)
	if err != nil {
		err = errors.WithMessage(err, "key URI")
		return
	}

	if keyBytes == nil {
		key = []byte(uri)
	} else {
		key = keyBytes
	}

	return
}

// GenerateKeyAndRequest takes a certificate request and generates a key and
// CSR from it.
func (c *Provider) GenerateKeyAndRequest(req *CertificateRequest) (csrPEM []byte, priv crypto.PrivateKey, keyID string, err error) {
	if req.KeyRequest == nil {
		err = errors.New("invalid key request")
		return
	}

	logger.KV(xlog.TRACE, "algo", req.KeyRequest.Algo(), "size", req.KeyRequest.Size())

	priv, err = req.KeyRequest.Generate()
	if err != nil {
		err = errors.WithMessage(err, "generate key")
		return
	}

	var label string
	keyID, label, err = c.provider.IdentifyKey(priv)
	if err != nil {
		err = errors.WithMessage(err, "identify key")
		return
	}
	logger.KV(xlog.TRACE, "key_id", keyID, "label", label)

	csrPEM, err = c.SignRequest(priv, req)
	if err != nil {
		err = errors.WithMessage(err, "failed to sign request")
		return
	}

	return
}

// SignRequest signs a certificate request
func (c *Provider) SignRequest(priv crypto.PrivateKey, req *CertificateRequest) (csrPEM []byte, err error) {
	ext, err := pkixExtentions(req.Extensions)
	if err != nil {
		err = errors.WithMessage(err, "invalid extensions")
		return
	}

	s, ok := priv.(crypto.Signer)
	if !ok {
		err = errors.Errorf("unable to convert key to crypto.Signer")
		return
	}

	var template = x509.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: DefaultSigAlgo(s),
		ExtraExtensions:    ext,
	}

	for _, san := range req.SAN {
		if strings.Contains(san, "://") {
			u, err := url.Parse(san)
			if err != nil {
				logger.KV(xlog.ERROR, "uri", san, "err", err)
			}
			template.URIs = append(template.URIs, u)
		} else if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(san); err == nil && email != nil {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
	logger.KV(xlog.DEBUG,
		"subject", template.Subject.String(),
		"ext", pkixExtentionsIDs(ext),
		"SAN", req.SAN,
	)

	csrPEM, err = x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		err = errors.WithMessage(err, "create CSR")
		return
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrPEM,
	}

	csrPEM = pem.EncodeToMemory(&block)

	return csrPEM, nil
}

func pkixExtentionsIDs(in []pkix.Extension) []string {
	var list []string
	for _, ext := range in {
		list = append(list, ext.Id.String())
	}
	return list
}

func pkixExtentions(in []X509Extension) ([]pkix.Extension, error) {
	var list []pkix.Extension
	for _, ext := range in {
		raw, err := ext.GetValue()
		if err != nil {
			return nil, err
		}
		list = append(list, pkix.Extension{
			Id:       asn1.ObjectIdentifier(ext.ID),
			Critical: ext.Critical,
			Value:    raw,
		})
	}
	return list, nil
}

// DefaultSigAlgo returns an appropriate X.509 signature algorithm given
// the CA's private key.
func DefaultSigAlgo(priv crypto.Signer) x509.SignatureAlgorithm {
	pub := priv.Public()
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		keySize := pub.N.BitLen()
		switch {
		case keySize >= 4096:
			return x509.SHA512WithRSA
		case keySize >= 3072:
			return x509.SHA384WithRSA
		case keySize >= 2048:
			return x509.SHA256WithRSA
		default:
			return x509.SHA1WithRSA
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return x509.ECDSAWithSHA256
		case elliptic.P384():
			return x509.ECDSAWithSHA384
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		default:
			return x509.ECDSAWithSHA1
		}
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
