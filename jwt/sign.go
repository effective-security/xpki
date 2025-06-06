package jwt

/*
MIT License.

Copyright 2022 Denis Issoupov

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"math/big"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/certutil"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	algHS256 = "HS256"
	algHS384 = "HS384"
	algHS512 = "HS512"
	algRS256 = "RS256"
	algRS384 = "RS384"
	algRS512 = "RS512"
	algES256 = "ES256"
	algES384 = "ES384"
	algES512 = "ES512"
)

type symSigner struct {
	hash crypto.Hash
	algo string
	key  []byte
}

func newSymmetricSigner(algo string, key []byte) (crypto.Signer, error) {
	s := &symSigner{
		algo: algo,
		key:  key,
	}

	switch algo {
	case algHS256:
		s.hash = crypto.SHA256
	case algHS384:
		s.hash = crypto.SHA384
	case algHS512:
		s.hash = crypto.SHA512
	default:
		return nil, errors.Errorf("unsupported algorithm: %s", algo)
	}
	return s, nil
}

// Public implements crypto.Signer
func (s *symSigner) Public() crypto.PublicKey {
	return s
}

// Sign implements crypto.Signer
func (s *symSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	hash := s.hash
	if opts != nil {
		hash = opts.HashFunc()
	}

	h := hmac.New(hash.New, s.key)
	h.Write(digest)

	return h.Sum(nil), nil
}

type hasher struct {
	hash crypto.Hash
}

func (h hasher) HashFunc() crypto.Hash {
	return h.hash
}

// SignerInfo represents JWT signer
type SignerInfo struct {
	hasher  hasher
	keySize int
	algo    string
	signer  crypto.Signer
}

// NewSignerInfo returns *SignerInfo
func NewSignerInfo(signer crypto.Signer) (*SignerInfo, error) {
	si := &SignerInfo{
		signer: signer,
	}

	switch typ := signer.Public().(type) {
	case *symSigner:
		si.keySize = len(typ.key) * 8
		si.algo = typ.algo
		si.hasher.hash = typ.hash
	case *rsa.PublicKey:
		si.keySize = typ.N.BitLen()
		switch {
		case si.keySize >= 4096:
			si.algo = algRS512
			si.hasher.hash = crypto.SHA512
		case si.keySize >= 3072:
			si.algo = algRS384
			si.hasher.hash = crypto.SHA384
		default:
			si.algo = algRS256
			si.hasher.hash = crypto.SHA256
		}
	case *ecdsa.PublicKey:
		switch typ.Curve {
		case elliptic.P521():
			si.algo = algES512
			si.hasher.hash = crypto.SHA512
		case elliptic.P384():
			si.algo = algES384
			si.hasher.hash = crypto.SHA384
		default:
			si.algo = algES256
			si.hasher.hash = crypto.SHA256
		}
		si.keySize = typ.Curve.Params().BitSize
	default:
		return nil, errors.Errorf("public key not supported: %T", typ)
	}
	return si, nil
}

// sign returns signed segment
func sign(signingString string, signer crypto.Signer) ([]byte, error) {
	si, err := NewSignerInfo(signer)
	if err != nil {
		return nil, err
	}
	return si.sign(signingString)
}

func (si *SignerInfo) sign(signingString string) ([]byte, error) {
	if strings.HasPrefix(si.algo, "HS") {
		sig, err := si.signer.Sign(nil, []byte(signingString), nil)
		if err != nil {
			return nil, err
		}
		return sig, nil
	}

	h := si.hasher.hash.New()
	h.Write([]byte(signingString))

	sig, err := si.signer.Sign(rand.Reader, h.Sum(nil), si.hasher)
	if err != nil {
		return nil, err
	}

	switch si.algo {
	case algES256, algES384, algES512:
		// for ECDSA, signature is encoded ASN1{r,s}
		var (
			r, s  = &big.Int{}, &big.Int{}
			inner cryptobyte.String
		)
		input := cryptobyte.String(sig)
		if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1Integer(r) ||
			!inner.ReadASN1Integer(s) ||
			!inner.Empty() {
			return nil, errors.Errorf("unable to decode ECDSA signature")
		}

		curveBits := si.keySize
		keyBytes := curveBits / 8
		if curveBits%8 > 0 {
			keyBytes++
		}

		// We serialize the outputs (r and s) into big-endian byte arrays
		// padded with zeros on the left to make sure the sizes work out.
		// Output must be 2*keyBytes long.
		out := make([]byte, 2*keyBytes)
		r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
		s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.

		return out, nil

	case algRS256, algRS384, algRS512:
		return sig, nil
	}
	return nil, errors.Errorf("unsupported: %s", si.algo)
}

func (si *SignerInfo) signJWT(claims any, headers map[string]any) (string, error) {
	header := map[string]any{
		"jti": certutil.RandomString(8),
		"typ": "JWT",
		"alg": si.algo,
	}
	for k, v := range headers {
		header[k] = v
	}

	jsonHeader, err := json.Marshal(header)
	if err != nil {
		return "", errors.WithStack(err)
	}
	jsonClaims, err := json.Marshal(claims)
	if err != nil {
		return "", errors.WithStack(err)
	}

	sstr := EncodeSegment(jsonHeader) + "." + EncodeSegment(jsonClaims)
	sig, err := si.sign(sstr)
	if err != nil {
		return "", err
	}
	return sstr + "." + EncodeSegment(sig), nil
}

var hashMap = map[string]crypto.Hash{
	algES256: crypto.SHA256,
	algES384: crypto.SHA384,
	algES512: crypto.SHA512,
	algRS256: crypto.SHA256,
	algRS384: crypto.SHA384,
	algRS512: crypto.SHA512,
}

var curveMap = map[string]elliptic.Curve{
	algES256: elliptic.P256(),
	algES384: elliptic.P384(),
	algES512: elliptic.P521(),
}

// VerifySignature returns error if JWT signature is invalid
func VerifySignature(algo, signingString, signature string, key any) error {
	if strings.HasPrefix(algo, "HS") {
		bytes, ok := key.([]byte)
		if !ok {
			return errors.Errorf("invalid key type %T for %s signature", key, algo)
		}

		signer, err := newSymmetricSigner(algo, bytes)
		if err != nil {
			return err
		}
		sig, err := signer.Sign(nil, []byte(signingString), nil)
		if err != nil {
			return err
		}
		if EncodeSegment(sig) != signature {
			return errors.Errorf("invalid signature")
		}
		return nil
	}

	// Decode the signature
	var sig []byte
	var err error
	if sig, err = DecodeSegment(signature); err != nil {
		return errors.Errorf("invalid signature")
	}

	h := hashMap[algo]
	if h == 0 {
		return errors.Errorf("unsupported algorithm")
	}

	hasher := h.New()
	hasher.Write([]byte(signingString))

	switch algo {
	case algES256, algES384, algES512:
		curve := curveMap[algo]
		curveBits := curve.Params().BitSize
		keySize := curveBits / 8
		if curveBits%8 > 0 {
			keySize++
		}
		if len(sig) != 2*keySize {
			return errors.Errorf("invalid ECDSA signature length: %s", algo)
		}
		r := big.NewInt(0).SetBytes(sig[:keySize])
		s := big.NewInt(0).SetBytes(sig[keySize:])
		if ecdsaKey, ok := key.(*ecdsa.PublicKey); ok {
			if !ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s) {
				return errors.Errorf("ecdsa: invalid signature")
			}
			return nil
		}
		return errors.Errorf("invalid key type for ECDSA signature: %T", key)
	case algRS256, algRS384, algRS512:
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			// Verify the signature
			err = rsa.VerifyPKCS1v15(rsaKey, h, hasher.Sum(nil), sig)
			if err != nil {
				return errors.WithStack(err)
			}
			return nil
		}
		return errors.Errorf("invalid key type for RSA signature: %T", key)
	}
	return errors.Errorf("unsupported: %s", algo)
}
