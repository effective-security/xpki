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
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
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
	case "HS256":
		s.hash = crypto.SHA256
	case "HS384":
		s.hash = crypto.SHA384
	case "HS512":
		s.hash = crypto.SHA512
	default:
		return nil, errors.Errorf("unsupported algorithm: " + algo)
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

type signerInfo struct {
	hasher  hasher
	keySize int
	algo    string
	signer  crypto.Signer
}

func newSignerInfo(signer crypto.Signer) (*signerInfo, error) {
	si := &signerInfo{
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
			si.algo = "RS512"
			si.hasher.hash = crypto.SHA512
		case si.keySize >= 3072:
			si.algo = "RS384"
			si.hasher.hash = crypto.SHA384
		default:
			si.algo = "RS256"
			si.hasher.hash = crypto.SHA256
		}
	case *ecdsa.PublicKey:
		switch typ.Curve {
		case elliptic.P521():
			si.algo = "ES512"
			si.hasher.hash = crypto.SHA512
		case elliptic.P384():
			si.algo = "ES384"
			si.hasher.hash = crypto.SHA384
		default:
			si.algo = "ES256"
			si.hasher.hash = crypto.SHA256
		}
		si.keySize = typ.Curve.Params().BitSize
	default:
		return nil, errors.Errorf("public key not supported: %T", typ)
	}
	return si, nil
}

// sign returns signed segment
func sign(signingString string, signer crypto.Signer) (string, error) {
	si, err := newSignerInfo(signer)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return si.sign(signingString)
}

func (si *signerInfo) sign(signingString string) (string, error) {
	if strings.HasPrefix(si.algo, "HS") {
		sig, err := si.signer.Sign(nil, []byte(signingString), nil)
		if err != nil {
			return "", errors.WithStack(err)
		}
		return EncodeSegment(sig), nil
	}

	h := si.hasher.hash.New()
	h.Write([]byte(signingString))

	sig, err := si.signer.Sign(rand.Reader, h.Sum(nil), si.hasher)
	if err != nil {
		return "", errors.WithStack(err)
	}

	switch si.algo {
	case "ES256", "ES384", "ES512":
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
			return "", errors.Errorf("unable to decode ECDSA signature")
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

		return EncodeSegment(out), nil

	case "RS256", "RS384", "RS512":
		return EncodeSegment(sig), nil
	}
	return "", errors.Errorf("unsupported: " + si.algo)
}

func (si *signerInfo) signJWT(claims interface{}, headers map[string]interface{}) (string, error) {
	header := map[string]interface{}{
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
		return "", errors.WithStack(err)
	}
	return sstr + "." + sig, nil
}

// EncodeSegment returns JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}
