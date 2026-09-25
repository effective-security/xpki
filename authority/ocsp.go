package authority

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/csr"
	"github.com/effective-security/xpki/metricskey"
	"github.com/effective-security/xpki/oid"
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
func (ca *Issuer) SignOCSP(req *OCSPSignRequest) ([]byte, error) {
	defer metricskey.PerfCAOperation.MeasureSince(time.Now(), ca.label, "sign_ocsp")

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
		nextUpdate = thisUpdate.Add(ca.ocspExpiry)
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

	issuer := ca.bundle.Cert
	responder := ca.caResponder
	if ca.delegatesOCSP() {
		var err error
		responder, err = ca.delegatedResponder(time.Now(), true)
		if err != nil {
			return nil, err
		}

		// A response must not outlive the delegated certificate that verifies it.
		notAfter := responder.Cert.NotAfter
		if !template.ThisUpdate.Before(notAfter) {
			return nil, errors.Errorf("delegated OCSP responder expires at %s, before thisUpdate %s",
				notAfter.UTC().Format(time.RFC3339), template.ThisUpdate.Format(time.RFC3339))
		}
		if template.NextUpdate.After(notAfter) {
			template.NextUpdate = notAfter.UTC()
		}
	}

	if !bytes.Equal(issuer.RawSubject, responder.Cert.RawSubject) {
		logger.KV(xlog.DEBUG,
			"reason", "delegated_ocsp",
			"responder", responder.Cert.Subject.CommonName,
			"issuer", issuer.Subject.CommonName,
		)
		template.Certificate = responder.Cert
	}
	res, err := ocsp.CreateResponse(issuer, responder.Cert, template, responder.Signer)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return res, nil
}

// OCSPResponder is a key and certificate that sign OCSP responses for an
// Issuer: either the CA itself or a delegated OCSP signing certificate.
// It is shared between callers and must not be modified.
type OCSPResponder struct {
	Signer crypto.Signer
	Cert   *x509.Certificate
}

// ocspRenewRetryInterval is how long a still-valid delegated responder is
// used without another renewal attempt after a renewal failed, or after a
// renewal produced a responder that is already due for renewal because the
// CA expires first (XPKI-053).
const ocspRenewRetryInterval = time.Minute

// ocspSigningUsage is the profile usage name of the OCSP signing EKU.
const ocspSigningUsage = "ocsp signing"

// delegatedValidityMargin covers the minute rounding of NotBefore in
// validityWindow (up to 30s) and the issuance time of a delegated responder.
const delegatedValidityMargin = time.Minute

// ocspRenewal is the immutable outcome of the last delegated responder
// issuance attempt, published through Issuer.renewal.
type ocspRenewal struct {
	// retryAt is the earliest next attempt while a valid responder exists.
	retryAt time.Time
	// err is the failure, nil after a successful issuance.
	err error
}

// CreateDelegatedOCSPSigner returns the responder that signs OCSP responses.
// Without a delegated_ocsp_profile it returns the CA key and certificate.
// Otherwise it returns the cached delegated responder, first issuing a new
// one when the cached one expires within the OCSP expiry interval, and
// waiting for a renewal in progress. While renewal is due and the last
// attempt failed, it returns that error, even if the cached responder is
// still valid (SignOCSP keeps using a valid cached responder instead); a new
// attempt is made at most every ocspRenewRetryInterval.
// It is safe for concurrent use.
func (ca *Issuer) CreateDelegatedOCSPSigner() (*OCSPResponder, error) {
	if !ca.delegatesOCSP() {
		return ca.caResponder, nil
	}
	return ca.delegatedResponder(time.Now(), false)
}

// delegatesOCSP reports whether a delegated_ocsp_profile is configured.
func (ca *Issuer) delegatesOCSP() bool {
	return ca.cfg.AIA != nil && ca.cfg.AIA.DelegatedOCSPProfile != ""
}

// validAt reports whether r can sign at now.
func validAt(r *OCSPResponder, now time.Time) bool {
	return r != nil && now.Before(r.Cert.NotAfter)
}

// validFor reports whether r outlives cutoff, so it needs no renewal.
func validFor(r *OCSPResponder, cutoff time.Time) bool {
	return r != nil && cutoff.Before(r.Cert.NotAfter)
}

// delegatedResponder returns the delegated responder to sign with at now.
// Delegated responders are published through ca.delegated and issued under
// ca.renewLock. Lock order: renewLock, then ca.lock (taken by Sign through
// Profile); ca.lock is never held while acquiring renewLock (XPKI-051).
//
// With useValid (SignOCSP), a caller with a still-valid cached responder
// never waits: it takes no lock within the retry interval, and skips the
// renewal when another caller holds renewLock. A renewal failure then falls
// back to that responder. Without a valid responder, the error is returned
// and no other key is used (XPKI-053). Callers that waited for renewLock
// while another caller's attempt failed share that failure instead of
// retrying one after another.
func (ca *Issuer) delegatedResponder(now time.Time, useValid bool) (*OCSPResponder, error) {
	// Renew before a response signed now could outlive the responder.
	cutoff := now.Add(ca.ocspExpiry)
	current := ca.delegated.Load()
	if validFor(current, cutoff) {
		return current, nil
	}

	last := ca.renewal.Load()
	valid := validAt(current, now)
	if valid && useValid {
		if last != nil && now.Before(last.retryAt) {
			return current, nil
		}
		if !ca.renewLock.TryLock() {
			// another caller is renewing
			return current, nil
		}
	} else {
		if ca.renewWaitHook != nil {
			ca.renewWaitHook()
		}
		ca.renewLock.Lock()
	}
	defer ca.renewLock.Unlock()

	// Another caller may have renewed, or failed to, while this one waited.
	current = ca.delegated.Load()
	if validFor(current, cutoff) {
		return current, nil
	}
	valid = validAt(current, now)
	state := ca.renewal.Load()
	switch {
	case state != last && state.err != nil:
		if valid && useValid {
			return current, nil
		}
		return nil, errors.WithStack(state.err)
	case valid && state != nil && now.Before(state.retryAt):
		if state.err != nil && !useValid {
			return nil, errors.WithStack(state.err)
		}
		return current, nil
	}

	started := time.Now()
	r, err := ca.newDelegatedResponder()
	// The attempt can block on the CA signer (KMS/HSM): judge the cached
	// responder and start the retry interval from when it ended.
	done := now.Add(time.Since(started))
	if err != nil {
		err = errors.WithMessage(err, "delegated OCSP responder is not available")
		ca.renewal.Store(&ocspRenewal{
			retryAt: done.Add(ocspRenewRetryInterval),
			err:     err,
		})
		if useValid && validAt(current, done) {
			logger.KV(xlog.ERROR,
				"reason", "delegated_ocsp_renewal",
				"expires", current.Cert.NotAfter.UTC().Format(time.RFC3339),
				"err", err,
			)
			return current, nil
		}
		return nil, err
	}

	next := &ocspRenewal{}
	if !validFor(r, cutoff) {
		next.retryAt = done.Add(ocspRenewRetryInterval)
		logger.KV(xlog.WARNING,
			"reason", "delegated_ocsp_short_lived",
			"expires", r.Cert.NotAfter.UTC().Format(time.RFC3339),
			"ocsp_expiry", ca.ocspExpiry.String(),
		)
	}
	ca.renewal.Store(next)
	ca.delegated.Store(r)
	return r, nil
}

// validateDelegatedOCSPProfile checks that p, the delegated_ocsp_profile
// named name, can issue a responder: it exists, is not a CA profile, the
// certificate's extended key usage includes OCSP signing (from a raw EKU
// extension if the profile has one, since it overrides the usages, otherwise
// from the usages), and a new responder outlives ocspExpiry, so it is not
// immediately due for renewal. validityWindow backdates NotBefore by the
// profile backdate from now rounded to the minute, so the expiry must exceed
// ocspExpiry + backdate + delegatedValidityMargin. It runs in CreateIssuer
// and again before each issuance, on the profile snapshot that is signed with.
func validateDelegatedOCSPProfile(p *CertProfile, name string, ocspExpiry time.Duration) error {
	if p == nil {
		return errors.Errorf("delegated_ocsp_profile %q not found", name)
	}
	if p.CAConstraint.IsCA {
		return errors.Errorf("delegated_ocsp_profile %q must not be a CA profile", name)
	}
	var hasOCSPSigning bool
	if ext := p.FindExtension(oid.ExtensionExtendedKeyUsage); ext != nil {
		der, err := ext.GetValue()
		if err == nil {
			hasOCSPSigning, err = ekuHasOCSPSigning(der)
		}
		if err != nil {
			return errors.WithMessagef(err, "delegated_ocsp_profile %q", name)
		}
	} else {
		_, eku, _ := p.Usages()
		hasOCSPSigning = slices.Contains(eku, x509.ExtKeyUsageOCSPSigning)
	}
	if !hasOCSPSigning {
		return errors.Errorf("delegated_ocsp_profile %q extended key usage must include %q", name, ocspSigningUsage)
	}
	backdate := effectiveBackdate(p)
	if expiry := p.Expiry.TimeDuration(); expiry <= ocspExpiry+backdate+delegatedValidityMargin {
		return errors.Errorf("delegated_ocsp_profile %q expiry %s must exceed ocsp_expiry %s + backdate %s + %s",
			name, expiry, ocspExpiry, backdate, delegatedValidityMargin)
	}
	return nil
}

// newDelegatedResponder generates a key and issues a delegated OCSP
// signing certificate with the delegated_ocsp_profile.
func (ca *Issuer) newDelegatedResponder() (*OCSPResponder, error) {
	profile := ca.cfg.AIA.DelegatedOCSPProfile
	// AddProfile may have replaced the profile since CreateIssuer validated it.
	snapshot := ca.Profile(profile)
	if err := validateDelegatedOCSPProfile(snapshot, profile, ca.ocspExpiry); err != nil {
		return nil, err
	}
	inmem := inmemcrypto.NewProvider()
	req := &csr.CertificateRequest{
		CommonName: "OCSP Responder",
		KeyRequest: csr.NewKeyRequest(
			inmem,
			profile,
			"ecdsa", 256,
			csr.SigningKey,
		),
	}

	csrPEM, priv, _, err := csr.NewProvider(inmem).GenerateKeyAndRequest(req)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create CSR")
	}

	s, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.Errorf("unable to convert key to crypto.Signer")
	}

	crt, _, err := ca.signWithProfile(csr.SignRequest{
		Request: string(csrPEM),
		Profile: profile,
		Subject: &csr.X509Subject{
			CommonName:   req.CommonName,
			Names:        req.Names,
			SerialNumber: req.SerialNumber,
		},
	}, profile, snapshot)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to sign OCSP responder")
	}
	logger.KV(xlog.NOTICE,
		"reason", "cert_signed",
		"profile", profile,
		"type", "delegated_ocsp",
		"cn", crt.Subject.CommonName,
		"expires", crt.NotAfter.UTC().Format(time.RFC3339),
	)

	return &OCSPResponder{
		Signer: s,
		Cert:   crt,
	}, nil
}
