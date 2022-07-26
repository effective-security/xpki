package authority

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

// revocationReasonCodes is a map between string reason codes
// to integers as defined in RFC 5280
var revocationReasonCodes = map[string]int{
	"unspecified":          ocsp.Unspecified,
	"keycompromise":        ocsp.KeyCompromise,
	"cacompromise":         ocsp.CACompromise,
	"affiliationchanged":   ocsp.AffiliationChanged,
	"superseded":           ocsp.Superseded,
	"cessationofoperation": ocsp.CessationOfOperation,
	"certificatehold":      ocsp.CertificateHold,
	"removefromcrl":        ocsp.RemoveFromCRL,
	"privilegewithdrawn":   ocsp.PrivilegeWithdrawn,
	"aacompromise":         ocsp.AACompromise,
}

const (
	// OCSPStatusGood specifies name for good status
	OCSPStatusGood = "good"
	// OCSPStatusRevoked specifies name for revoked status
	OCSPStatusRevoked = "revoked"
	// OCSPStatusUnknown specifies name for unknown status
	OCSPStatusUnknown = "unknown"
)

// OCSPStatusCode is a map between string statuses sent by cli/api
// to ocsp int statuses
var OCSPStatusCode = map[string]int{
	OCSPStatusGood:    ocsp.Good,
	OCSPStatusRevoked: ocsp.Revoked,
	OCSPStatusUnknown: ocsp.Unknown,
}

// OCSPSignRequest represents the desired contents of a
// specific OCSP response.
type OCSPSignRequest struct {
	SerialNumber *big.Int
	Status       string
	Reason       int
	RevokedAt    time.Time
	Extensions   []pkix.Extension
	// IssuerHash is the hashing function used to hash the issuer subject and public key
	// in the OCSP response. Valid values are crypto.SHA1, crypto.SHA256, crypto.SHA384,
	// and crypto.SHA512. If zero, the default is crypto.SHA1.
	IssuerHash crypto.Hash
	// If provided ThisUpdate will override the default usage of time.Now().Truncate(time.Hour)
	ThisUpdate *time.Time
	// If provided NextUpdate will override the default usage of ThisUpdate.Add(signerInterval)
	NextUpdate *time.Time
}

// OCSPReasonStringToCode tries to convert a reason string to an integer code
func OCSPReasonStringToCode(reason string) (reasonCode int, err error) {
	// default to 0
	if reason == "" {
		return 0, nil
	}

	reasonCode, present := revocationReasonCodes[strings.ToLower(reason)]
	if !present {
		reasonCode, err = strconv.Atoi(reason)
		if err != nil {
			return
		}
		if reasonCode > ocsp.AACompromise || reasonCode < ocsp.Unspecified {
			return 0, errors.Errorf("invalid status: %s", reason)
		}
	}

	return
}

// SignOCSP return an OCSP response.
func (i *Issuer) SignOCSP(req *OCSPSignRequest) ([]byte, error) {
	var thisUpdate, nextUpdate time.Time
	if req.ThisUpdate != nil {
		thisUpdate = *req.ThisUpdate
	} else {
		// Round thisUpdate times down to the nearest minute
		thisUpdate = time.Now().Truncate(time.Minute)
	}
	if req.NextUpdate != nil {
		nextUpdate = *req.NextUpdate
	} else {
		nextUpdate = thisUpdate.Add(i.ocspExpiry)
	}

	status, ok := OCSPStatusCode[req.Status]
	if !ok {
		return nil, errors.Errorf("invalid status: %s", req.Status)
	}

	template := ocsp.Response{
		Status:          status,
		SerialNumber:    req.SerialNumber,
		ThisUpdate:      thisUpdate.UTC(),
		NextUpdate:      nextUpdate.UTC(),
		ExtraExtensions: req.Extensions,
		IssuerHash:      req.IssuerHash,
	}

	if status == ocsp.Revoked {
		template.RevokedAt = req.RevokedAt
		template.RevocationReason = req.Reason
	}

	signer, crt, err := i.CreateDelegatedOCSPSigner()
	if err != nil {
		logger.KV(xlog.ERROR, "reason", "delegated_ocsp", "err", err)
		signer = i.signer
	}

	template.Certificate = crt
	res, err := ocsp.CreateResponse(i.bundle.Cert, i.bundle.Cert, template, signer)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return res, nil
}

type responder struct {
	signer crypto.Signer
	crt    *x509.Certificate
}

// CreateDelegatedOCSPSigner create OCSP signing certificate,
// if needed, or returns an existing one.
// if the delegation is not allowed, the CA Signer is returned
func (i *Issuer) CreateDelegatedOCSPSigner() (crypto.Signer, *x509.Certificate, error) {
	if i.cfg.AIA == nil ||
		i.cfg.AIA.DelegatedOCSPProfile == "" {
		return i.signer, nil, nil
	}

	i.lock.Lock()
	defer i.lock.Unlock()
	ocsp := i.responder

	// check if existing cert is valid or needs to be renewed before
	// OCSP validity period
	cutoff := time.Now().Add(i.ocspExpiry).UTC()
	if ocsp != nil &&
		ocsp.crt != nil &&
		cutoff.Before(ocsp.crt.NotAfter.UTC()) {
		logger.KV(xlog.DEBUG,
			"reason", "valid_delegated",
			"valid_for", time.Until(ocsp.crt.NotAfter).Truncate(time.Minute).String(),
			"expires", ocsp.crt.NotAfter,
		)
		return ocsp.signer, ocsp.crt, nil
	}

	inmem := inmemcrypto.NewProvider()
	req := &csr.CertificateRequest{
		CommonName: "OCSP Responder",
		KeyRequest: csr.NewKeyRequest(
			inmem,
			i.cfg.AIA.DelegatedOCSPProfile,
			"ecdsa", 256,
			csr.SigningKey,
		),
	}

	csrPEM, priv, _, err := csr.NewProvider(inmem).GenerateKeyAndRequest(req)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to create CSR")
	}

	s, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, errors.Errorf("unable to convert key to crypto.Signer")
	}

	crt, _, err := i.Sign(csr.SignRequest{
		Request: string(csrPEM),
		Profile: i.cfg.AIA.DelegatedOCSPProfile,
		Subject: &csr.X509Subject{
			CommonName:   req.CommonName,
			Names:        req.Names,
			SerialNumber: req.SerialNumber,
		},
	})
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to sign OCSP responder")
	}
	logger.KV(xlog.NOTICE,
		"reason", "cert_signed",
		"profile", i.cfg.AIA.DelegatedOCSPProfile,
		"type", "delegated_ocsp",
		"cn", crt.Subject.CommonName,
		"expires", crt.NotAfter.UTC().Format(time.RFC3339),
	)

	i.responder = &responder{
		signer: s,
		crt:    crt,
	}

	return s, crt, nil
}
