package authority

import (
	"crypto"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/csr"
)

// NewRoot creates a new root certificate from the certificate request.
func NewRoot(profile string, cfg *Config, provider cryptoprov.Provider, req *csr.CertificateRequest) (certPEM, csrPEM, key []byte, err error) {
	err = req.Validate()
	if err != nil {
		err = errors.WithMessage(err, "invalid request")
		return
	}

	err = cfg.Validate()
	if err != nil {
		err = errors.WithMessage(err, "invalid configuration")
		return
	}

	var (
		gkey  crypto.PrivateKey
		keyID string
		c     = csr.NewProvider(provider)
	)

	csrPEM, gkey, keyID, err = c.GenerateKeyAndRequest(req)
	if err != nil {
		err = errors.WithMessage(err, "process request")
		return
	}

	signer := gkey.(crypto.Signer)
	uri, keyBytes, err := provider.ExportKey(keyID)
	if err != nil {
		err = errors.WithMessage(err, "failed to export key")
		return
	}

	if keyBytes == nil {
		key = []byte(uri)
	} else {
		key = keyBytes
	}

	issuer := &Issuer{
		cfg: IssuerConfig{
			Profiles: cfg.Profiles,
		},
		signer:  signer,
		sigAlgo: csr.DefaultSigAlgo(signer),
	}
	/*
		if cfg.Authority != nil {
			// TODO: AIA to root CA
			// issuer.cfg.AIA = cfg.Authority.DefaultAIA
		}
	*/
	sreq := csr.SignRequest{
		SAN:     req.SAN,
		Request: string(csrPEM),
		Profile: profile,
		Subject: &csr.X509Subject{
			CommonName: req.CommonName,
			Names:      req.Names,
		},
	}

	_, certPEM, err = issuer.Sign(sreq)
	if err != nil {
		err = errors.WithMessage(err, "sign request")
		return
	}
	return
}
