package crypto11

import (
	"crypto"
	"crypto/rsa"
	"io"
	"math/big"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	pkcs11 "github.com/miekg/pkcs11"
)

// PKCS11PrivateKeyRSA contains a reference to a loaded PKCS#11 RSA private key object.
type PKCS11PrivateKeyRSA struct {
	key *PKCS11PrivateKey
	lib *PKCS11Lib
}

// Export the public key corresponding to a private RSA key.
func (lib *PKCS11Lib) exportRSAPublicKey(session pkcs11.SessionHandle, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	logger.KV(xlog.TRACE, "session=0x", session, "obj=0x", pubHandle)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	exported, err := lib.Ctx.GetAttributeValue(session, pubHandle, template)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var modulus = new(big.Int)
	modulus.SetBytes(exported[0].Value)
	var bigExponent = new(big.Int)
	bigExponent.SetBytes(exported[1].Value)
	if bigExponent.BitLen() > 32 {
		return nil, errors.WithStack(errMalformedRSAKey)
	}
	if bigExponent.Sign() < 1 {
		return nil, errors.WithStack(errMalformedRSAKey)
	}
	exponent := int(bigExponent.Uint64())
	result := rsa.PublicKey{
		N: modulus,
		E: exponent,
	}
	if result.E < 2 {
		return nil, errors.WithStack(errMalformedRSAKey)
	}
	return &result, nil
}

// GenerateRSAKeyPair creates an RSA private key of given length.
//
// The key will have a random label and ID.
//
// RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.
func (lib *PKCS11Lib) GenerateRSAKeyPair(bits int, purpose KeyPurpose) (*PKCS11PrivateKeyRSA, error) {
	return lib.GenerateRSAKeyPairOnSlot(lib.Slot.id, nil, nil, bits, purpose)
}

// GenerateRSAKeyPairWithLabel creates an RSA private key of given length.
//
// The key will have a random ID.
//
// RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.
func (lib *PKCS11Lib) GenerateRSAKeyPairWithLabel(label string, bits int, purpose KeyPurpose) (*PKCS11PrivateKeyRSA, error) {
	return lib.GenerateRSAKeyPairOnSlot(lib.Slot.id, nil, []byte(label), bits, purpose)
}

// GenerateRSAKeyPairOnSlot creates a RSA private key on a specified slot
//
// Either or both label and/or id can be nil, in which case a random values will be generated.
func (lib *PKCS11Lib) GenerateRSAKeyPairOnSlot(slot uint, id []byte, label []byte, bits int, purpose KeyPurpose) (*PKCS11PrivateKeyRSA, error) {
	var k *PKCS11PrivateKeyRSA
	var err error
	lib.setupSessions(slot)
	err = lib.withSession(slot, func(session pkcs11.SessionHandle) error {
		k, err = lib.GenerateRSAKeyPairOnSession(session, slot, id, label, bits, purpose)
		return errors.WithStack(err)
	})
	return k, err
}

// GenerateRSAKeyPairOnSession creates an RSA private key of given length, on a specified session.
//
// Either or both label and/or id can be nil, in which case a random values will be generated.
//
// RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.
func (lib *PKCS11Lib) GenerateRSAKeyPairOnSession(
	session pkcs11.SessionHandle, slot uint,
	id []byte,
	label []byte,
	bits int,
	purpose KeyPurpose,
) (*PKCS11PrivateKeyRSA, error) {
	var err error
	var pub crypto.PublicKey

	if len(label) == 0 {
		if label, err = lib.generateKeyLabel(); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	if len(id) == 0 {
		if id, err = lib.generateKeyID(); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	switch purpose {
	case Signing:
		publicKeyTemplate = append(publicKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true))
		privateKeyTemplate = append(privateKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_SIGN, true))
	case Encryption:
		publicKeyTemplate = append(publicKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true))
		privateKeyTemplate = append(privateKeyTemplate, pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true))
	}

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	pubHandle, privHandle, err := lib.Ctx.GenerateKeyPair(session,
		mech,
		publicKeyTemplate,
		privateKeyTemplate)
	if err != nil {
		logger.KV(xlog.ERROR, "reason", "GenerateKeyPair", "pubHandle", pubHandle, "privHandle", privHandle, "err", err)
		return nil, errors.WithStack(err)
	}
	if pub, err = lib.exportRSAPublicKey(session, pubHandle); err != nil {
		logger.KV(xlog.ERROR, "reason", "exportRSAPublicKey", "err", err)
		return nil, errors.WithStack(err)
	}
	priv := PKCS11PrivateKeyRSA{
		key: &PKCS11PrivateKey{PKCS11Object{privHandle, slot}, pub},
		lib: lib,
	}
	return &priv, nil
}

// Decrypt decrypt a message using a RSA key.
//
// This completes the implementation of crypto.Decrypter for PKCS11PrivateKeyRSA.
//
// If options is nil or a *rsa.PKCS1v15DecryptOptions, PKCS#1 v1.5 decryption
// is performed; a non-zero SessionKeyLen is not supported. If options is a
// *rsa.OAEPOptions, OAEP decryption is performed.
//
// The underlying PKCS#11 implementation may impose further restrictions.
func (priv *PKCS11PrivateKeyRSA) Decrypt(rand io.Reader, ciphertext []byte, options crypto.DecrypterOpts) (plaintext []byte, err error) {
	logger.Trace("PKCS11PrivateKeyRSA.Decrypt")

	err = priv.lib.withSession(priv.key.Slot, func(session pkcs11.SessionHandle) error {
		if options == nil {
			plaintext, err = priv.lib.decryptPKCS1v15(session, priv, ciphertext, 0)
		} else {
			switch o := options.(type) {
			case *rsa.PKCS1v15DecryptOptions: //nolint:staticcheck // deprecated in Go 1.26, still accepted for existing PKCS#1 v1.5 callers
				plaintext, err = priv.lib.decryptPKCS1v15(session, priv, ciphertext, o.SessionKeyLen)
			case *rsa.OAEPOptions:
				plaintext, err = priv.lib.decryptOAEP(session, priv, ciphertext, o.Hash, o.Label)
			default:
				err = errors.WithStack(errUnsupportedRSAOptions)
			}
		}
		return err
	})
	return plaintext, err
}

func (lib *PKCS11Lib) decryptPKCS1v15(session pkcs11.SessionHandle, priv *PKCS11PrivateKeyRSA, ciphertext []byte, sessionKeyLen int) ([]byte, error) {
	if sessionKeyLen != 0 {
		return nil, errors.WithStack(errUnsupportedRSAOptions)
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	if err := lib.Ctx.DecryptInit(session, mech, priv.key.Handle); err != nil {
		return nil, errors.WithStack(err)
	}
	return lib.Ctx.Decrypt(session, ciphertext)
}

func (lib *PKCS11Lib) decryptOAEP(session pkcs11.SessionHandle, priv *PKCS11PrivateKeyRSA, ciphertext []byte, hashFunction crypto.Hash, label []byte) ([]byte, error) {
	hMech, mgf, _, err := hashToPKCS11(hashFunction)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// NewOAEPParams copies the label into C memory, so no Go pointer is
	// smuggled through the mechanism parameter.
	params := pkcs11.NewOAEPParams(hMech, mgf, pkcs11.CKZ_DATA_SPECIFIED, label)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)}
	if err = lib.Ctx.DecryptInit(session, mech, priv.key.Handle); err != nil {
		return nil, errors.WithStack(err)
	}
	return lib.Ctx.Decrypt(session, ciphertext)
}

func hashToPKCS11(hashFunction crypto.Hash) (uint, uint, uint, error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil
	default:
		return 0, 0, 0, errors.WithStack(errUnsupportedRSAOptions)
	}
}

func (lib *PKCS11Lib) signPSS(session pkcs11.SessionHandle, priv *PKCS11PrivateKeyRSA, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	logger.KV(xlog.TRACE, "session=0x", session, "obj=0x", priv.key.Handle)

	var hMech, mgf, hLen, sLen uint
	var err error
	if hMech, mgf, hLen, err = hashToPKCS11(opts.Hash); err != nil {
		return nil, errors.WithStack(err)
	}
	switch opts.SaltLength {
	case rsa.PSSSaltLengthAuto:
		// Largest salt that fits, as crypto/rsa computes it:
		// emLen - hLen - 2, where emLen is the octet length of the modulus.
		pub, ok := priv.key.PubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.WithStack(errMalformedRSAKey)
		}
		emLen := (pub.N.BitLen() - 1 + 7) / 8
		maxSalt := emLen - int(hLen) - 2
		if maxSalt < 0 {
			return nil, errors.WithMessagef(errUnsupportedRSAOptions, "key too small for PSS with %s", opts.Hash)
		}
		sLen = uint(maxSalt)
	case rsa.PSSSaltLengthEqualsHash:
		sLen = hLen
	default:
		if opts.SaltLength < 0 {
			return nil, errors.WithStack(errUnsupportedRSAOptions)
		}
		sLen = uint(opts.SaltLength)
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pkcs11.NewPSSParams(hMech, mgf, sLen))}
	if err = lib.Ctx.SignInit(session, mech, priv.key.Handle); err != nil {
		return nil, errors.WithStack(err)
	}
	return lib.Ctx.Sign(session, digest)
}

var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func (lib *PKCS11Lib) signPKCS1v15(session pkcs11.SessionHandle, priv *PKCS11PrivateKeyRSA, digest []byte, hash crypto.Hash) (signature []byte, err error) {
	logger.KV(xlog.TRACE, "session=0x", session, "obj=0x", priv.key.Handle)
	/* Calculate T for EMSA-PKCS1-v1_5. */
	oid, ok := pkcs1Prefix[hash]
	if !ok {
		return nil, errors.WithMessagef(errUnsupportedRSAOptions, "unsupported PKCS#1 v1.5 hash: %s", hash)
	}
	T := make([]byte, len(oid)+len(digest))
	copy(T[0:len(oid)], oid)
	copy(T[len(oid):], digest)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	err = lib.Ctx.SignInit(session, mech, priv.key.Handle)
	if err == nil {
		signature, err = lib.Ctx.Sign(session, T)
		if err != nil {
			err = errors.WithStack(err)
			logger.KV(xlog.TRACE, "session=0x", session, "obj=0x", priv.key.Handle, "err", err)
		}
	}
	return
}

// Sign signs a message using a RSA key.
//
// This completes the implementation of crypto.Signer for PKCS11PrivateKeyRSA.
//
// PKCS#11 expects to pick its own random data where necessary for signatures, so the rand argument is ignored.
//
// For PSS, rsa.PSSSaltLengthAuto uses the largest salt the key allows,
// rsa.PSSSaltLengthEqualsHash uses the hash length, and a positive value is
// used as-is. For PKCS#1 v1.5 the hash must be one of SHA-1, SHA-224,
// SHA-256, SHA-384 or SHA-512; other hashes are rejected. The underlying
// PKCS#11 implementation may impose further restrictions.
func (priv *PKCS11PrivateKeyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	err = priv.lib.withSession(priv.key.Slot, func(session pkcs11.SessionHandle) error {
		switch typ := opts.(type) {
		case *rsa.PSSOptions:
			signature, err = priv.lib.signPSS(session, priv, digest, typ)
		default: /* PKCS1-v1_5 */
			signature, err = priv.lib.signPKCS1v15(session, priv, digest, opts.HashFunc())
		}
		return err
	})
	return signature, err
}

// Public returns the public half of a private key.
//
// This partially implements the go.crypto.Signer and go.crypto.Decrypter interfaces for
// PKCS11PrivateKey. (The remains of the implementation is in the
// key-specific types.)
func (priv *PKCS11PrivateKeyRSA) Public() crypto.PublicKey {
	return priv.key.PubKey
}

// Validate checks an RSA key.
//
// Since the private key material is not normally available only very
// limited validation is possible. (The underlying PKCS#11
// implementation may perform stricter checking.)
func (priv *PKCS11PrivateKeyRSA) Validate() error {
	pub := priv.key.PubKey.(*rsa.PublicKey)
	if pub.E < 2 {
		return errMalformedRSAKey
	}
	// The software implementation actively rejects 'large' public
	// exponents, in order to simplify its own implementation.
	// Here, instead, we expect the PKCS#11 library to enforce its
	// own preferred constraints, whatever they might be.
	return nil
}
