package certutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"reflect"

	"github.com/cockroachdb/errors"
	"golang.org/x/crypto/ocsp"
)

// mldsaSignatureOIDs maps the ML-DSA X.509 signature algorithms to their
// OIDs (RFC 9881), which golang.org/x/crypto/ocsp does not know.
var mldsaSignatureOIDs = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
	x509.MLDSA44: {2, 16, 840, 1, 101, 3, 4, 3, 17},
	x509.MLDSA65: {2, 16, 840, 1, 101, 3, 4, 3, 18},
	x509.MLDSA87: {2, 16, 840, 1, 101, 3, 4, 3, 19},
}

// ocspResponseASN1 is the OCSPResponse of RFC 6960 §4.2.1.
type ocspResponseASN1 struct {
	Status   asn1.Enumerated
	Response ocspResponseBytes `asn1:"explicit,tag:0,optional"`
}

// ocspResponseBytes is the ResponseBytes of RFC 6960 §4.2.1.
type ocspResponseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

// basicOCSPResponse is the BasicOCSPResponse of RFC 6960 §4.2.1 with the
// signed data kept as encoded, so it can be signed and verified as is.
type basicOCSPResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// marshal returns the DER encoded OCSPResponse holding basic.
func (r *ocspResponseASN1) marshal(basic *basicOCSPResponse) ([]byte, error) {
	der, err := asn1.Marshal(*basic)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	outer := *r
	outer.Response.Response = der
	der, err = asn1.Marshal(outer)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return der, nil
}

// unsignedOCSPSigner lets ocsp.CreateResponse encode a response for a key
// type it cannot sign with: it selects the ECDSA code path and returns an
// empty signature, which CreateOCSPResponse replaces.
type unsignedOCSPSigner struct{}

// Public implements crypto.Signer; ocsp.CreateResponse reads only the curve.
func (unsignedOCSPSigner) Public() crypto.PublicKey {
	return &ecdsa.PublicKey{Curve: elliptic.P256()}
}

// Sign implements crypto.Signer and returns no signature.
func (unsignedOCSPSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// CreateOCSPResponse returns a DER encoded OCSP response signed by signer,
// the key of responderCert, as ocsp.CreateResponse does: template gives the
// content, and template.Certificate, when set, is embedded. Unlike
// ocsp.CreateResponse it also signs with an ML-DSA key, from any provider:
// the response is encoded by golang.org/x/crypto/ocsp, and the signature over
// its tbsResponseData (RFC 6960 §4.2.1) is pure ML-DSA with an empty context
// and the id-ml-dsa-* algorithm without parameters (RFC 9881).
// template.SignatureAlgorithm is ignored for an ML-DSA key, whose parameter
// set fixes the algorithm. A nil issuer, responderCert or signer, or an
// uninitialized ML-DSA key, is an error.
//
// An ML-DSA response can be read by ParseOCSPResponse and by OpenSSL 3.5, but
// golang.org/x/crypto/ocsp cannot verify it.
func CreateOCSPResponse(issuer, responderCert *x509.Certificate, template ocsp.Response, signer crypto.Signer) ([]byte, error) {
	if issuer == nil {
		return nil, errors.New("issuer certificate is nil")
	}
	if responderCert == nil {
		return nil, errors.New("responder certificate is nil")
	}
	if isNilSigner(signer) {
		return nil, errors.New("signer is nil")
	}
	if !IsPostQuantumKey(signer) {
		der, err := ocsp.CreateResponse(issuer, responderCert, template, signer)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return der, nil
	}

	pub, err := mldsaSignerPublicKey(signer)
	if err != nil {
		return nil, err
	}
	algo, err := mldsaSignatureAlgorithm(pub.Parameters())
	if err != nil {
		return nil, err
	}

	template.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	unsigned, err := ocsp.CreateResponse(issuer, responderCert, template, unsignedOCSPSigner{})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	outer, basic, ok := decodeBasicOCSPResponse(unsigned)
	if !ok {
		return nil, errors.New("unable to decode the OCSP response")
	}

	// the message itself with nil options, the signer contract of every
	// provider (cryptoprov.MLDSASignerOptions)
	signature, err := signer.Sign(rand.Reader, basic.TBSResponseData.FullBytes, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to sign the OCSP response")
	}
	basic.SignatureAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm: mldsaSignatureOIDs[algo],
	}
	basic.Signature = asn1.BitString{
		Bytes:     signature,
		BitLength: len(signature) * 8,
	}
	return outer.marshal(basic)
}

// isNilSigner reports whether signer is nil or a nil pointer, on which
// Public panics.
func isNilSigner(signer crypto.Signer) bool {
	if signer == nil {
		return true
	}
	v := reflect.ValueOf(signer)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// mldsaSignerPublicKey returns the public key of an ML-DSA signer. An
// uninitialized key is an error, since crypto/mldsa panics on one.
func mldsaSignerPublicKey(signer crypto.Signer) (*mldsa.PublicKey, error) {
	if key, ok := signer.(*mldsa.PrivateKey); ok && *key == (mldsa.PrivateKey{}) {
		return nil, errors.New("invalid ML-DSA private key")
	}
	pub, ok := signer.Public().(*mldsa.PublicKey)
	if !ok || pub == nil || *pub == (mldsa.PublicKey{}) {
		return nil, errors.New("invalid ML-DSA public key")
	}
	return pub, nil
}

// mldsaSignatureAlgorithm returns the X.509 signature algorithm of an ML-DSA
// key of params.
func mldsaSignatureAlgorithm(params mldsa.Parameters) (x509.SignatureAlgorithm, error) {
	switch params {
	case mldsa.MLDSA44():
		return x509.MLDSA44, nil
	case mldsa.MLDSA65():
		return x509.MLDSA65, nil
	case mldsa.MLDSA87():
		return x509.MLDSA87, nil
	default:
		return x509.UnknownSignatureAlgorithm, errors.Errorf("unsupported ML-DSA parameter set: %q", params)
	}
}

// decodeBasicOCSPResponse decodes the structure of a response with basic
// response bytes. It reports false for anything else, including malformed
// input and trailing data, which ocsp.ParseResponseForCert reports properly.
func decodeBasicOCSPResponse(der []byte) (*ocspResponseASN1, *basicOCSPResponse, bool) {
	outer := new(ocspResponseASN1)
	rest, err := asn1.Unmarshal(der, outer)
	if err != nil || len(rest) > 0 {
		return nil, nil, false
	}
	basic := new(basicOCSPResponse)
	rest, err = asn1.Unmarshal(outer.Response.Response, basic)
	if err != nil || len(rest) > 0 {
		return nil, nil, false
	}
	return outer, basic, true
}

// ocspMLDSASignatureAlgorithm returns the ML-DSA algorithm of a signature
// algorithm identifier, or false for any other algorithm.
func ocspMLDSASignatureAlgorithm(id pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, bool) {
	for algo, oid := range mldsaSignatureOIDs {
		if id.Algorithm.Equal(oid) {
			return algo, true
		}
	}
	return x509.UnknownSignatureAlgorithm, false
}

// ParseOCSPResponse parses and verifies a DER encoded OCSP response that
// holds one status, as ParseOCSPResponseForCert with no certificate.
func ParseOCSPResponse(der []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	return ParseOCSPResponseForCert(der, nil, issuer)
}

// ParseOCSPResponseForCert parses a DER encoded OCSP response and returns the
// status of cert, as ocsp.ParseResponseForCert does, and also verifies a
// response signed with ML-DSA, which that function cannot. A response with an
// embedded certificate is verified with that certificate's key and, when
// issuer is set, the certificate with the issuer's key; without one, the
// response is verified with the issuer's key when issuer is set. With no
// embedded certificate and no issuer the signature is not checked. A status
// other than successful is an ocsp.ResponseError in the error chain, and a
// signature that does not verify an ocsp.ParseError, for ML-DSA too.
// Response.SignatureAlgorithm is x509.MLDSA44, MLDSA65 or MLDSA87 for an
// ML-DSA response, so Response.CheckSignatureFrom works on it.
//
// Like golang.org/x/crypto/ocsp, it does not check that an embedded certificate
// is authorized to answer for the issuer (the OCSP signing EKU of RFC 6960
// §4.2.2.2) or is within its validity, or that the CertID names the issuer: any
// certificate the issuer signed can sign an accepted response. Those checks are
// left to the service that relies on the result (ROADMAP item 11).
func ParseOCSPResponseForCert(der []byte, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	outer, basic, ok := decodeBasicOCSPResponse(der)
	var algo x509.SignatureAlgorithm
	if ok {
		algo, ok = ocspMLDSASignatureAlgorithm(basic.SignatureAlgorithm)
	}
	if !ok {
		res, err := ocsp.ParseResponseForCert(der, cert, issuer)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return res, nil
	}
	if len(basic.SignatureAlgorithm.Parameters.FullBytes) > 0 {
		return nil, errors.WithStack(ocsp.ParseError("invalid OCSP response: " + algo.String() + " signature algorithm has parameters"))
	}

	// ocsp.ParseResponseForCert verifies with an embedded certificate whatever
	// the issuer, and knows no ML-DSA: it only reads the response, without
	// certificates and with no issuer, and the signature is verified here.
	certs := basic.Certificates
	basic.Certificates = nil
	stripped, err := outer.marshal(basic)
	if err != nil {
		return nil, err
	}
	res, err := ocsp.ParseResponseForCert(stripped, cert, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	res.Raw = der
	res.SignatureAlgorithm = algo

	if len(certs) == 0 {
		if issuer != nil {
			if err := res.CheckSignatureFrom(issuer); err != nil {
				return nil, errors.WithStack(ocsp.ParseError("bad OCSP signature: " + err.Error()))
			}
		}
		return res, nil
	}

	// only the first certificate counts, as in ocsp.ParseResponseForCert
	crt, err := x509.ParseCertificate(certs[0].FullBytes)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to parse the embedded certificate")
	}
	if err := res.CheckSignatureFrom(crt); err != nil {
		return nil, errors.WithStack(ocsp.ParseError("bad signature on embedded certificate: " + err.Error()))
	}
	if issuer != nil {
		if err := issuer.CheckSignature(crt.SignatureAlgorithm, crt.RawTBSCertificate, crt.Signature); err != nil {
			return nil, errors.WithStack(ocsp.ParseError("bad OCSP signature: " + err.Error()))
		}
	}
	res.Certificate = crt
	return res, nil
}

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
