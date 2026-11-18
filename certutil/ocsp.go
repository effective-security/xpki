package certutil

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"reflect"
	"slices"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/internal/signctx"
	"golang.org/x/crypto/ocsp"
)

// mldsaSignatureOIDs maps the ML-DSA X.509 signature algorithms to their
// OIDs (RFC 9881), which golang.org/x/crypto/ocsp does not know.
var mldsaSignatureOIDs = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
	x509.MLDSA44: {2, 16, 840, 1, 101, 3, 4, 3, 17},
	x509.MLDSA65: {2, 16, 840, 1, 101, 3, 4, 3, 18},
	x509.MLDSA87: {2, 16, 840, 1, 101, 3, 4, 3, 19},
}

// ocspHashes maps the CertID hash algorithms golang.org/x/crypto/ocsp reads
// to their hashes, by OID.
var ocspHashes = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

// ocspResponseData is the ResponseData of RFC 6960 §4.2.1, decoded up to the
// CertID of each response; encoding/asn1 ignores the trailing fields.
type ocspResponseData struct {
	Version     int `asn1:"optional,default:0,explicit,tag:0"`
	ResponderID asn1.RawValue
	ProducedAt  asn1.RawValue
	Responses   []ocspSingleResponse
}

// ocspSingleResponse is the SingleResponse of RFC 6960 §4.2.1, decoded up to
// its CertID.
type ocspSingleResponse struct {
	CertID ocspCertID
}

// ocspCertID is the CertID of RFC 6960 §4.1.1.
type ocspCertID struct {
	HashAlgorithm  pkix.AlgorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
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
//
// ctx bounds the signature: a cryptoprov.ContextSigner signs with it
// (SignContext), any other signer is called once ctx is checked.
func CreateOCSPResponse(ctx context.Context, issuer, responderCert *x509.Certificate, template ocsp.Response, signer crypto.Signer) ([]byte, error) {
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
		der, err := ocsp.CreateResponse(issuer, responderCert, template, signctx.Bind(ctx, signer))
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
	signature, err := signctx.Sign(ctx, signer, rand.Reader, basic.TBSResponseData.FullBytes, nil)
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
// certificate the issuer signed can sign an accepted response. A caller that
// relies on the status checks that with VerifyOCSPResponder.
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

// VerifyOCSPResponder checks that res, a response read by ParseOCSPResponse,
// ParseOCSPResponseForCert or golang.org/x/crypto/ocsp, answers for a
// certificate of issuer and was signed by a responder that RFC 6960 §4.2.2.2
// authorizes to answer for it. The parsers check only signatures, so without
// this check any certificate the issuer signed, a client certificate for
// example, can sign a good status for any serial number of the issuer. The
// rules, for classical and ML-DSA responses alike:
//
//   - with no embedded certificate, or one with the issuer's key, the
//     issuer's key must verify the response;
//   - any other embedded certificate (the first, the one the parsers use) is
//     a delegated responder: its issuer name and signature are the issuer's, it
//     has the OCSP signing extended key usage (anyExtendedKeyUsage does not
//     count), it is valid now, and its key must verify the response;
//   - the CertID of the status res reports, the first response for
//     res.SerialNumber, carries the hashes of the issuer's name and key.
//
// The signatures are verified again, so res read without an issuer is
// checked too. A responder is checked against the current time rather than
// ThisUpdate, so the key of an expired responder cannot sign a response
// dated within its validity. The caller still checks the issuer itself (its
// chain, validity and revocation), the revocation of a delegated responder
// that lacks id-pkix-ocsp-nocheck, the freshness of ThisUpdate and
// NextUpdate, and a responder it trusts locally (the first case of
// §4.2.2.2), which this function rejects unless it is the issuer.
func VerifyOCSPResponder(res *ocsp.Response, issuer *x509.Certificate) error {
	if res == nil {
		return errors.New("OCSP response is nil")
	}
	if issuer == nil {
		return errors.New("issuer certificate is nil")
	}

	responder := issuer
	if crt := res.Certificate; crt != nil && !bytes.Equal(crt.RawSubjectPublicKeyInfo, issuer.RawSubjectPublicKeyInfo) {
		if err := checkDelegatedOCSPResponder(crt, issuer, time.Now()); err != nil {
			return err
		}
		responder = crt
	}
	if err := res.CheckSignatureFrom(responder); err != nil {
		return errors.WithMessage(err, "bad OCSP signature")
	}
	return checkOCSPCertID(res, issuer)
}

// checkDelegatedOCSPResponder checks that crt, the certificate embedded in a
// response, is a responder issuer delegated OCSP signing to, valid at now.
func checkDelegatedOCSPResponder(crt, issuer *x509.Certificate, now time.Time) error {
	if !bytes.Equal(crt.RawIssuer, issuer.RawSubject) {
		return errors.New("OCSP responder certificate is not issued by the issuer")
	}
	if len(crt.UnhandledCriticalExtensions) != 0 {
		return errors.Errorf("OCSP responder certificate has unhandled critical extensions: %v", crt.UnhandledCriticalExtensions)
	}
	if !IsOCSPSigner(crt) {
		return errors.New("OCSP responder certificate has no OCSP signing extended key usage")
	}
	if now.Before(crt.NotBefore) || now.After(crt.NotAfter) {
		return errors.Errorf("OCSP responder certificate is not valid now: valid from %s to %s",
			crt.NotBefore.UTC().Format(time.RFC3339), crt.NotAfter.UTC().Format(time.RFC3339))
	}
	// SHA-1 accepted, as by the parsers and CreateOCSPRequest
	if err := issuer.CheckSignature(crt.SignatureAlgorithm, crt.RawTBSCertificate, crt.Signature); err != nil {
		return errors.WithMessage(err, "OCSP responder certificate is not signed by the issuer")
	}
	return nil
}

// checkOCSPCertID checks that the CertID of the status res reports, the first
// response for res.SerialNumber in the signed response data, names issuer.
func checkOCSPCertID(res *ocsp.Response, issuer *x509.Certificate) error {
	if res.SerialNumber == nil {
		return errors.New("OCSP response has no serial number")
	}
	var data ocspResponseData
	rest, err := asn1.Unmarshal(res.TBSResponseData, &data)
	if err != nil {
		return errors.WithMessage(err, "unable to decode the OCSP response data")
	}
	if len(rest) > 0 {
		return errors.New("trailing data in the OCSP response data")
	}
	idx := slices.IndexFunc(data.Responses, func(r ocspSingleResponse) bool {
		return r.CertID.SerialNumber.Cmp(res.SerialNumber) == 0
	})
	if idx < 0 {
		return errors.Errorf("OCSP response has no status for serial number %s", res.SerialNumber)
	}
	certID := data.Responses[idx].CertID
	oid := certID.HashAlgorithm.Algorithm.String()
	hash, ok := ocspHashes[oid]
	if !ok {
		return errors.Errorf("unsupported OCSP CertID hash algorithm: %s", oid)
	}
	nameHash, keyHash, err := ocspIssuerHashes(issuer, hash)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(certID.IssuerNameHash, nameHash) != 1 ||
		subtle.ConstantTimeCompare(certID.IssuerKeyHash, keyHash) != 1 {
		return errors.New("OCSP response CertID does not match the issuer")
	}
	return nil
}

// ocspIssuerHashes returns the CertID hashes of issuer (RFC 6960 §4.1.1):
// the hash of its DER encoded subject name and the hash of the value of its
// subjectPublicKey BIT STRING, without tag, length and unused bits.
func ocspIssuerHashes(issuer *x509.Certificate, hash crypto.Hash) (nameHash, keyHash []byte, err error) {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, nil, errors.WithMessage(err, "unable to decode the issuer public key")
	}
	return Digest(hash, issuer.RawSubject), Digest(hash, publicKeyInfo.PublicKey.RightAlign()), nil
}

// CreateOCSPRequest returns the DER encoded OCSP request for crt issued by
// issuer, hashing the issuer name and key with hash. A nil crt or issuer or an
// unavailable hash returns an error before any work (XPKI-103), and so does
// an issuer whose subject is not crt's issuer name or whose key did not sign
// crt (XPKI-121). The signature check accepts SHA-1 and applies no CA policy.
// The request is the one ocsp.CreateRequest builds, issuerNameHash included,
// which was empty up to v2.0.324 (XPKI-131).
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

	nameHash, keyHash, err := ocspIssuerHashes(issuer, hash)
	if err != nil {
		return nil, err
	}
	req := ocsp.Request{
		HashAlgorithm:  hash,
		IssuerNameHash: nameHash,
		IssuerKeyHash:  keyHash,
		SerialNumber:   crt.SerialNumber,
	}

	der, err := req.Marshal()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return der, nil
}
