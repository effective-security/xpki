package certutil_test

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pkcs8Dir      = "testdata/pkcs8"
	pkcs8Password = "xpki-test"
	pkcs8Iter     = 2048
)

var (
	oidTestPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidTestPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidTestPBES1MD5   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
	oidTestScrypt     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	oidTestHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidTestHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidTestHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidTestHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidTestHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidTestHMACMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidTestAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidTestAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidTestAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidTestAES256GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

// readPKCS8Fixture returns the PEM of an OpenSSL-generated key fixture.
func readPKCS8Fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pkcs8Dir, name))
	require.NoError(t, err)
	return data
}

// XPKI-043: PBES2 keys written by OpenSSL decrypt to the same key as the
// unencrypted PKCS#8 fixture.
func TestEncryptedPKCS8OpenSSL(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		encrypted, plain string
	}{
		{encrypted: "rsa-aes256-sha256.pem", plain: "rsa.pem"},
		{encrypted: "ec-aes128-sha1.pem", plain: "ec.pem"},
		{encrypted: "ec-aes192-sha512.pem", plain: "ec.pem"},
		{encrypted: "ed25519-aes256-sha384.pem", plain: "ed25519.pem"},
	} {
		t.Run(tc.encrypted, func(t *testing.T) {
			t.Parallel()
			encrypted := readPKCS8Fixture(t, tc.encrypted)
			plainPEM := readPKCS8Fixture(t, tc.plain)
			plainBlock, _ := pem.Decode(plainPEM)
			require.NotNil(t, plainBlock)
			want, err := certutil.ParsePrivateKeyPEM(plainPEM)
			require.NoError(t, err)

			der, err := certutil.GetKeyDERFromPEM(encrypted, []byte(pkcs8Password))
			require.NoError(t, err)
			assert.Equal(t, plainBlock.Bytes, der)

			key, err := certutil.ParsePrivateKeyPEMWithPassword(encrypted, []byte(pkcs8Password))
			require.NoError(t, err)
			assert.True(t, want.(interface{ Equal(crypto.PrivateKey) bool }).Equal(key))

			_, err = certutil.ParsePrivateKeyPEM(encrypted)
			require.EqualError(t, err, "encrypted private key")
			for _, password := range [][]byte{[]byte("wrong"), {}} {
				_, err = certutil.ParsePrivateKeyPEMWithPassword(encrypted, password)
				require.ErrorIs(t, err, x509.IncorrectPasswordError)
			}
		})
	}
}

// XPKI-043: schemes other than PBES2 with PBKDF2 and AES-CBC are reported as
// unsupported rather than as an unparsable key.
func TestEncryptedPKCS8OpenSSLUnsupported(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file, want string
	}{
		{file: "ec-des3.pem", want: "unsupported PKCS#8 encryption: cipher 1.2.840.113549.3.7"},
		{file: "ec-scrypt.pem", want: "unsupported PKCS#8 encryption: key derivation 1.3.6.1.4.1.11591.4.11"},
		{file: "ec-pkcs12-3des.pem", want: "unsupported PKCS#8 encryption: scheme 1.2.840.113549.1.12.1.3"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			_, err := certutil.ParsePrivateKeyPEMWithPassword(readPKCS8Fixture(t, tc.file), []byte(pkcs8Password))
			require.EqualError(t, err, tc.want)
		})
	}
}

// pbes2Spec describes an EncryptedPrivateKeyInfo built by encryptPKCS8.
type pbes2Spec struct {
	scheme    asn1.ObjectIdentifier
	kdf       asn1.ObjectIdentifier
	prf       asn1.ObjectIdentifier // nil omits the PRF (HMAC-SHA1 default)
	newHash   func() hash.Hash      // PRF used to derive the key
	cipher    asn1.ObjectIdentifier
	keySize   int
	iter      int
	keyLength int    // written when not zero
	salt      any    // []byte, or an AlgorithmIdentifier for otherSource
	iv        []byte // nil generates a random 16-byte IV
	password  string // key derivation password
	pad       func([]byte) []byte
	body      func([]byte) []byte // rewrites the ciphertext
	trailing  []byte              // appended after the structure
}

type testAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type testPBKDF2Params struct {
	Salt      asn1.RawValue
	Iter      int
	KeyLength int           `asn1:"optional"`
	PRF       testAlgorithm `asn1:"optional"`
}

type testPBES2Params struct {
	KDF    testAlgorithm
	Cipher testAlgorithm
}

type testEncryptedKey struct {
	Algorithm testAlgorithm
	Data      []byte
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	require.NoError(t, err)
	return der
}

func pkcs7Pad(data []byte) []byte {
	n := aes.BlockSize - len(data)%aes.BlockSize
	for range n {
		data = append(data, byte(n))
	}
	return data
}

// defaultPBES2 returns an OpenSSL-3-style PBES2 spec: PBKDF2 with
// HMAC-SHA256 and AES-256-CBC.
func defaultPBES2() pbes2Spec {
	return pbes2Spec{
		scheme:   oidTestPBES2,
		kdf:      oidTestPBKDF2,
		prf:      oidTestHMACSHA256,
		newHash:  sha256.New,
		cipher:   oidTestAES256CBC,
		keySize:  32,
		iter:     pkcs8Iter,
		salt:     []byte("0123456789abcdef"),
		password: pkcs8Password,
		pad:      pkcs7Pad,
	}
}

// encryptPKCS8 encrypts plain as a PEM ENCRYPTED PRIVATE KEY per spec.
func encryptPKCS8(t *testing.T, plain []byte, spec pbes2Spec) []byte {
	t.Helper()
	kdfParams := testPBKDF2Params{
		Salt:      asn1.RawValue{FullBytes: mustMarshal(t, spec.salt)},
		Iter:      spec.iter,
		KeyLength: spec.keyLength,
	}
	if spec.prf != nil {
		kdfParams.PRF = testAlgorithm{
			Algorithm:  spec.prf,
			Parameters: asn1.NullRawValue,
		}
	}
	iv := spec.iv
	if iv == nil {
		iv = make([]byte, aes.BlockSize)
		_, err := rand.Read(iv)
		require.NoError(t, err)
	}
	var saltBytes []byte
	if s, ok := spec.salt.([]byte); ok {
		saltBytes = s
	}
	// Invalid counts are rejected before key derivation, so any count works.
	deriveIter := spec.iter
	if deriveIter < 1 || deriveIter > pkcs8Iter {
		deriveIter = 1
	}
	key, err := pbkdf2.Key(spec.newHash, spec.password, saltBytes, deriveIter, spec.keySize)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	data := spec.pad(append([]byte(nil), plain...))
	ciphertext := make([]byte, len(data))
	if len(iv) == aes.BlockSize && len(data)%aes.BlockSize == 0 {
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, data)
	}
	if spec.body != nil {
		ciphertext = spec.body(ciphertext)
	}
	params := testPBES2Params{
		KDF: testAlgorithm{
			Algorithm:  spec.kdf,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, kdfParams)},
		},
		Cipher: testAlgorithm{
			Algorithm:  spec.cipher,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, iv)},
		},
	}
	der := mustMarshal(t, testEncryptedKey{
		Algorithm: testAlgorithm{
			Algorithm:  spec.scheme,
			Parameters: asn1.RawValue{FullBytes: mustMarshal(t, params)},
		},
		Data: ciphertext,
	})
	der = append(der, spec.trailing...)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: der,
	})
}

// XPKI-043: every supported PRF and AES key size round-trips RSA and EC keys.
func TestEncryptedPKCS8RoundTrip(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	prfs := []struct {
		name    string
		oid     asn1.ObjectIdentifier
		newHash func() hash.Hash
	}{
		{name: "default", oid: nil, newHash: sha1.New},
		{name: "sha1", oid: oidTestHMACSHA1, newHash: sha1.New},
		{name: "sha224", oid: oidTestHMACSHA224, newHash: sha256.New224},
		{name: "sha256", oid: oidTestHMACSHA256, newHash: sha256.New},
		{name: "sha384", oid: oidTestHMACSHA384, newHash: sha512.New384},
		{name: "sha512", oid: oidTestHMACSHA512, newHash: sha512.New},
	}
	ciphers := []struct {
		name    string
		oid     asn1.ObjectIdentifier
		keySize int
	}{
		{name: "aes128", oid: oidTestAES128CBC, keySize: 16},
		{name: "aes192", oid: oidTestAES192CBC, keySize: 24},
		{name: "aes256", oid: oidTestAES256CBC, keySize: 32},
	}
	for _, key := range []struct {
		name string
		key  crypto.Signer
	}{
		{name: "rsa", key: rsaKey},
		{name: "ecdsa", key: ecKey},
	} {
		plain, err := x509.MarshalPKCS8PrivateKey(key.key)
		require.NoError(t, err)
		for _, prf := range prfs {
			for _, c := range ciphers {
				for _, withLength := range []bool{false, true} {
					name := key.name + "/" + prf.name + "/" + c.name
					if withLength {
						name += "/keyLength"
					}
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						spec := defaultPBES2()
						spec.prf = prf.oid
						spec.newHash = prf.newHash
						spec.cipher = c.oid
						spec.keySize = c.keySize
						if withLength {
							spec.keyLength = c.keySize
						}
						encrypted := encryptPKCS8(t, plain, spec)
						der, err := certutil.GetKeyDERFromPEM(encrypted, []byte(pkcs8Password))
						require.NoError(t, err)
						assert.Equal(t, plain, der)
						parsed, err := certutil.ParsePrivateKeyPEMWithPassword(encrypted, []byte(pkcs8Password))
						require.NoError(t, err)
						assert.True(t, key.key.(interface{ Equal(crypto.PrivateKey) bool }).Equal(parsed))
					})
				}
			}
		}
	}
}

// XPKI-043: malformed or unsupported parameters return an error and never
// panic.
func TestEncryptedPKCS8Malformed(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	plain, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		modify func(*pbes2Spec)
		want   string
		isPwd  bool
	}{
		{name: "wrong password", modify: func(s *pbes2Spec) { s.password = "other" }, isPwd: true},
		{name: "zero padding byte", modify: func(s *pbes2Spec) {
			s.pad = func(b []byte) []byte {
				p := pkcs7Pad(b)
				p[len(p)-1] = 0
				return p
			}
		}, isPwd: true},
		{name: "inconsistent padding", modify: func(s *pbes2Spec) {
			s.pad = func(b []byte) []byte {
				p := pkcs7Pad(append(b, 1, 2, 3))
				p[len(p)-2] ^= 0xff
				return p
			}
		}, isPwd: true},
		{name: "padding longer than block", modify: func(s *pbes2Spec) {
			s.pad = func(b []byte) []byte {
				p := pkcs7Pad(b)
				p[len(p)-1] = aes.BlockSize + 1
				return p
			}
		}, isPwd: true},
		{name: "valid padding, not DER", modify: func(s *pbes2Spec) {
			s.pad = func([]byte) []byte { return pkcs7Pad([]byte("not a DER key")) }
		}, isPwd: true},
		{name: "valid padding, trailing DER bytes", modify: func(s *pbes2Spec) {
			s.pad = func(b []byte) []byte { return pkcs7Pad(append(b, 0x05, 0x00)) }
		}, isPwd: true},
		{name: "empty ciphertext", modify: func(s *pbes2Spec) {
			s.body = func([]byte) []byte { return nil }
		}, want: "invalid PKCS#8 encrypted data length 0"},
		{name: "partial block", modify: func(s *pbes2Spec) {
			s.body = func(b []byte) []byte { return b[:len(b)-1] }
		}, want: fmt.Sprintf("invalid PKCS#8 encrypted data length %d", len(pkcs7Pad(slices.Clone(plain)))-1)},
		{name: "trailing data", modify: func(s *pbes2Spec) { s.trailing = []byte{0} }, want: "invalid PKCS#8 encrypted key: trailing data"},
		{name: "pbes1", modify: func(s *pbes2Spec) { s.scheme = oidTestPBES1MD5 }, want: "unsupported PKCS#8 encryption: scheme 1.2.840.113549.1.5.3"},
		{name: "scrypt", modify: func(s *pbes2Spec) { s.kdf = oidTestScrypt }, want: "unsupported PKCS#8 encryption: key derivation 1.3.6.1.4.1.11591.4.11"},
		{name: "hmac md5", modify: func(s *pbes2Spec) { s.prf = oidTestHMACMD5 }, want: "unsupported PKCS#8 encryption: PRF 1.2.840.113549.2.5"},
		{name: "aes gcm", modify: func(s *pbes2Spec) { s.cipher = oidTestAES256GCM }, want: "unsupported PKCS#8 encryption: cipher 2.16.840.1.101.3.4.1.46"},
		{name: "zero iterations", modify: func(s *pbes2Spec) { s.iter = 0 }, want: "invalid PKCS#8 PBKDF2 iteration count 0"},
		{name: "negative iterations", modify: func(s *pbes2Spec) { s.iter = -1 }, want: "invalid PKCS#8 PBKDF2 iteration count -1"},
		{name: "too many iterations", modify: func(s *pbes2Spec) { s.iter = certutil.MaxPBKDF2Iterations + 1 }, want: "invalid PKCS#8 PBKDF2 iteration count 10000001"},
		{name: "key length mismatch", modify: func(s *pbes2Spec) { s.keyLength = 16 }, want: "invalid PKCS#8 PBKDF2 key length 16 for a 32-byte key"},
		{name: "other salt source", modify: func(s *pbes2Spec) {
			s.salt = testAlgorithm{Algorithm: oidTestHMACSHA1}
		}, want: "unsupported PKCS#8 encryption: PBKDF2 salt source"},
		{name: "short IV", modify: func(s *pbes2Spec) { s.iv = make([]byte, 8) }, want: "invalid PKCS#8 AES-CBC IV length 8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			spec := defaultPBES2()
			tc.modify(&spec)
			encrypted := encryptPKCS8(t, plain, spec)
			var der []byte
			var err error
			require.NotPanics(t, func() {
				der, err = certutil.GetKeyDERFromPEM(encrypted, []byte(pkcs8Password))
			})
			assert.Nil(t, der)
			if tc.isPwd {
				require.ErrorIs(t, err, x509.IncorrectPasswordError)
				return
			}
			require.EqualError(t, err, tc.want)
		})
	}

	for _, tc := range []struct {
		name string
		der  []byte
		want string
	}{
		{name: "not DER", der: []byte("garbage"), want: "invalid PKCS#8 encrypted key"},
		{name: "not PBES2 params", der: mustMarshal(t, testEncryptedKey{
			Algorithm: testAlgorithm{
				Algorithm:  oidTestPBES2,
				Parameters: asn1.NullRawValue,
			},
			Data: make([]byte, aes.BlockSize),
		}), want: "invalid PKCS#8 PBES2 parameters"},
		{name: "not PBKDF2 params", der: mustMarshal(t, testEncryptedKey{
			Algorithm: testAlgorithm{
				Algorithm: oidTestPBES2,
				Parameters: asn1.RawValue{FullBytes: mustMarshal(t, testPBES2Params{
					KDF: testAlgorithm{
						Algorithm:  oidTestPBKDF2,
						Parameters: asn1.NullRawValue,
					},
					Cipher: testAlgorithm{
						Algorithm:  oidTestAES256CBC,
						Parameters: asn1.RawValue{FullBytes: mustMarshal(t, make([]byte, aes.BlockSize))},
					},
				})},
			},
			Data: make([]byte, aes.BlockSize),
		}), want: "invalid PKCS#8 PBKDF2 parameters"},
		{name: "IV not an octet string", der: mustMarshal(t, testEncryptedKey{
			Algorithm: testAlgorithm{
				Algorithm: oidTestPBES2,
				Parameters: asn1.RawValue{FullBytes: mustMarshal(t, testPBES2Params{
					KDF: testAlgorithm{
						Algorithm: oidTestPBKDF2,
						Parameters: asn1.RawValue{FullBytes: mustMarshal(t, testPBKDF2Params{
							Salt: asn1.RawValue{FullBytes: mustMarshal(t, []byte("salt"))},
							Iter: pkcs8Iter,
						})},
					},
					Cipher: testAlgorithm{
						Algorithm:  oidTestAES256CBC,
						Parameters: asn1.NullRawValue,
					},
				})},
			},
			Data: make([]byte, aes.BlockSize),
		}), want: "invalid PKCS#8 AES-CBC IV"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := pem.EncodeToMemory(&pem.Block{
				Type:  "ENCRYPTED PRIVATE KEY",
				Bytes: tc.der,
			})
			_, err := certutil.GetKeyDERFromPEM(data, []byte(pkcs8Password))
			require.ErrorContains(t, err, tc.want)
		})
	}

	// Without a password an encrypted PKCS#8 key reports the same error as a
	// legacy encrypted PEM block.
	encrypted := encryptPKCS8(t, plain, defaultPBES2())
	_, err = certutil.GetKeyDERFromPEM(encrypted, nil)
	require.EqualError(t, err, "encrypted private key")

	// The unencrypted formats are unchanged.
	for _, file := range []string{"rsa.pem", "ec.pem", "ed25519.pem"} {
		_, err = certutil.ParsePrivateKeyPEMWithPassword(readPKCS8Fixture(t, file), []byte(pkcs8Password))
		require.NoError(t, err, file)
	}
	ecPEM, err := certutil.EncodePrivateKeyToPEM(key)
	require.NoError(t, err)
	parsed, err := certutil.ParsePrivateKeyPEMWithPassword(ecPEM, []byte(pkcs8Password))
	require.NoError(t, err)
	assert.True(t, key.Equal(parsed))
}
