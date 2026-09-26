package certutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"

	"github.com/cockroachdb/errors"
)

// pemTypeEncryptedPKCS8 is the PEM block type of an RFC 5958
// EncryptedPrivateKeyInfo.
const pemTypeEncryptedPKCS8 = "ENCRYPTED PRIVATE KEY"

// maxPBKDF2Iterations bounds the PBKDF2 work an encrypted key can request.
// OpenSSL writes 2048 by default; OWASP recommends at most 1,300,000
// (HMAC-SHA1).
const maxPBKDF2Iterations = 10_000_000

var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// pbkdf2PRFs maps the supported PBKDF2 PRF OIDs to their hash.
var pbkdf2PRFs = map[string]func() hash.Hash{
	oidHMACWithSHA1.String():   sha1.New,
	oidHMACWithSHA224.String(): sha256.New224,
	oidHMACWithSHA256.String(): sha256.New,
	oidHMACWithSHA384.String(): sha512.New384,
	oidHMACWithSHA512.String(): sha512.New,
}

// aesCBCKeySizes maps the supported AES-CBC OIDs to their key size in bytes.
var aesCBCKeySizes = map[string]int{
	oidAES128CBC.String(): 16,
	oidAES192CBC.String(): 24,
	oidAES256CBC.String(): 32,
}

// encryptedPrivateKeyInfo is the RFC 5958 EncryptedPrivateKeyInfo.
type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

// pbes2Params is the RFC 8018 PBES2-params.
type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

// pbkdf2Params is the RFC 8018 PBKDF2-params. Salt is a CHOICE; only the
// specified OCTET STRING is supported. A missing PRF means HMAC-SHA1.
type pbkdf2Params struct {
	Salt           asn1.RawValue
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

// errUnsupportedPKCS8 reports an encryption scheme, KDF, PRF or cipher that
// decryptPKCS8 does not implement (XPKI-043).
func errUnsupportedPKCS8(what string, oid asn1.ObjectIdentifier) error {
	return errors.Errorf("unsupported PKCS#8 encryption: %s %s", what, oid)
}

// decryptPKCS8 decrypts an RFC 5958 EncryptedPrivateKeyInfo and returns the
// PKCS#8 PrivateKeyInfo DER. Only PBES2 with PBKDF2 (HMAC-SHA1, -SHA224,
// -SHA256, -SHA384 or -SHA512) and AES-128/192/256-CBC is supported; other
// schemes return an "unsupported PKCS#8 encryption" error. A wrong password
// returns an error that matches x509.IncorrectPasswordError.
func decryptPKCS8(der, password []byte) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		return nil, errors.WithMessage(err, "invalid PKCS#8 encrypted key")
	}
	if len(rest) != 0 {
		return nil, errors.New("invalid PKCS#8 encrypted key: trailing data")
	}
	if !info.Algorithm.Algorithm.Equal(oidPBES2) {
		return nil, errUnsupportedPKCS8("scheme", info.Algorithm.Algorithm)
	}

	var params pbes2Params
	if err = unmarshalParams(info.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, errors.WithMessage(err, "invalid PKCS#8 PBES2 parameters")
	}
	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, errUnsupportedPKCS8("key derivation", params.KeyDerivationFunc.Algorithm)
	}
	cipherOID := params.EncryptionScheme.Algorithm
	keySize, ok := aesCBCKeySizes[cipherOID.String()]
	if !ok {
		return nil, errUnsupportedPKCS8("cipher", cipherOID)
	}

	var kdf pbkdf2Params
	if err = unmarshalParams(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
		return nil, errors.WithMessage(err, "invalid PKCS#8 PBKDF2 parameters")
	}
	if kdf.Salt.Class != asn1.ClassUniversal || kdf.Salt.Tag != asn1.TagOctetString || kdf.Salt.IsCompound {
		return nil, errors.New("unsupported PKCS#8 encryption: PBKDF2 salt source")
	}
	if kdf.IterationCount < 1 || kdf.IterationCount > maxPBKDF2Iterations {
		return nil, errors.Errorf("invalid PKCS#8 PBKDF2 iteration count %d", kdf.IterationCount)
	}
	if kdf.KeyLength != 0 && kdf.KeyLength != keySize {
		return nil, errors.Errorf("invalid PKCS#8 PBKDF2 key length %d for a %d-byte key", kdf.KeyLength, keySize)
	}
	prf := sha1.New
	if len(kdf.PRF.Algorithm) != 0 {
		if prf, ok = pbkdf2PRFs[kdf.PRF.Algorithm.String()]; !ok {
			return nil, errUnsupportedPKCS8("PRF", kdf.PRF.Algorithm)
		}
	}

	var iv []byte
	if err = unmarshalParams(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, errors.WithMessage(err, "invalid PKCS#8 AES-CBC IV")
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.Errorf("invalid PKCS#8 AES-CBC IV length %d", len(iv))
	}
	data := info.EncryptedData
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errors.Errorf("invalid PKCS#8 encrypted data length %d", len(data))
	}

	key, err := pbkdf2.Key(prf, string(password), kdf.Salt.Bytes, kdf.IterationCount, keySize)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to derive PKCS#8 key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create PKCS#8 cipher")
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)

	plain, ok = unpadPKCS7(plain)
	if !ok {
		return nil, errors.WithStack(x509.IncorrectPasswordError)
	}
	// A wrong password leaves valid padding about once in 256 attempts;
	// the result must also be exactly one DER value.
	var value asn1.RawValue
	if rest, err = asn1.Unmarshal(plain, &value); err != nil || len(rest) != 0 {
		return nil, errors.WithStack(x509.IncorrectPasswordError)
	}
	return plain, nil
}

// unmarshalParams decodes an AlgorithmIdentifier parameter that must be
// present and exactly one DER value.
func unmarshalParams(der []byte, v any) error {
	if len(der) == 0 {
		return errors.New("missing parameters")
	}
	rest, err := asn1.Unmarshal(der, v)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}

// unpadPKCS7 removes RFC 5652 padding from a whole number of AES blocks.
func unpadPKCS7(data []byte) ([]byte, bool) {
	n := int(data[len(data)-1])
	if n == 0 || n > aes.BlockSize {
		return nil, false
	}
	pad := data[len(data)-n:]
	want := make([]byte, n)
	for i := range want {
		want[i] = byte(n)
	}
	if subtle.ConstantTimeCompare(pad, want) != 1 {
		return nil, false
	}
	return data[:len(data)-n], true
}
