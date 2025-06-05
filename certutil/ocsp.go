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

// CreateOCSPRequest returns DER encoded OCSP request
func CreateOCSPRequest(crt, issuer *x509.Certificate, hash crypto.Hash) ([]byte, error) {
	if !bytes.Equal(crt.RawIssuer, issuer.RawSubject) {
		return nil, errors.Errorf("invalid chain: issuer does not match")
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
