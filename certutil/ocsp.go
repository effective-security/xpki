package certutil

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/ocsp"
)

// CreateOCSPRequest returns the DER encoded OCSP request for crt issued by
// issuer, hashing the issuer key with hash. A nil crt or issuer or an
// unavailable hash returns an error before any work (XPKI-103), and so does
// an issuer whose subject is not crt's issuer name or whose key did not sign
// crt (XPKI-121). The signature check accepts SHA-1 and applies no CA policy.
func CreateOCSPRequest(crt, issuer *x509.Certificate, hash crypto.Hash) ([]byte, error) {
	if crt == nil {
		return nil, errors.New("certificate is nil")
	}
	if issuer == nil {
		return nil, errors.New("issuer certificate is nil")
	}
	if !hash.Available() {
		return nil, errors.Errorf("hash algorithm is not available: %s", hash)
	}
	if !bytes.Equal(crt.RawIssuer, issuer.RawSubject) {
		return nil, errors.Errorf("invalid chain: issuer does not match")
	}
	if err := issuer.CheckSignature(crt.SignatureAlgorithm, crt.RawTBSCertificate, crt.Signature); err != nil {
		return nil, errors.WithMessage(err, "invalid chain: issuer did not sign the certificate")
	}

	// OCSP requires Hash of the Key without Tag:
	/// issuerKeyHash is the hash of the issuer's public key.  The hash
	// shall be calculated over the value (excluding tag and length) of
	// the subject public key field in the issuer's certificate.
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	pub := publicKeyInfo.PublicKey.RightAlign()

	req := ocsp.Request{
		HashAlgorithm: hash,
		SerialNumber:  crt.SerialNumber,
		IssuerKeyHash: Digest(hash, pub),
	}

	der, err := req.Marshal()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return der, nil
}
