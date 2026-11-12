package crypto11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	pkcs11 "github.com/miekg/pkcs11"
)

// Identify returns the ID and label for a PKCS#11 object.
//
// Either of these values may be used to retrieve the key for later use.
// The object's Handle is used as given; IdentifyKey, given a private key of
// this package, also recovers from a handle invalidated by a logout. ctx
// bounds the wait for a session.
func (lib *PKCS11Lib) Identify(ctx context.Context, object *PKCS11Object) (keyID, label string, err error) {
	return lib.identify(ctx, object, nil)
}

// identify is Identify with the key's identity for handle refreshes.
func (lib *PKCS11Lib) identify(ctx context.Context, object *PKCS11Object, ref *objectRef) (keyID, label string, err error) {
	var a []*pkcs11.Attribute
	if err = lib.withKeyCtx(ctx, object, ref, func(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		// a fresh template per attempt: a failed call returns none
		a, err = lib.Ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		})
		return err
	}); err != nil {
		return "", "", errors.WithStack(err)
	}
	return string(a[0].Value), string(a[1].Value), nil
}

// Find a key object.  For asymmetric keys this only finds one half so
// callers will call it twice.
func (lib *PKCS11Lib) findKey(session pkcs11.SessionHandle, keyID, label string, keyclass uint, keytype uint) (pkcs11.ObjectHandle, error) {
	var err error
	var handles []pkcs11.ObjectHandle
	template := []*pkcs11.Attribute{}
	if keyclass != ^uint(0) {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, keyclass))
	}
	if keytype != ^uint(0) {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keytype))
	}
	if keyID != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)))
	}
	if label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)))
	}
	if err = lib.Ctx.FindObjectsInit(session, template); err != nil {
		return 0, errors.WithStack(err)
	}
	defer func() {
		_ = lib.Ctx.FindObjectsFinal(session)
	}()
	if handles, _, err = lib.Ctx.FindObjects(session, 1); err != nil {
		return 0, errors.WithStack(err)
	}
	if len(handles) == 0 {
		return 0, errors.WithStack(errKeyNotFound)
	}
	return handles[0], nil
}

// findObjectsBatchSize is the maximum number of handles requested from a
// single C_FindObjects call. PKCS#11 allows a call to return fewer than the
// requested maximum while more objects remain, so a search (findObjectsWindow)
// goes on until an empty batch is returned.
const findObjectsBatchSize = 100

// FindKeyPair retrieves a previously created asymmetric key.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
// ctx bounds the wait for a session.
func (lib *PKCS11Lib) FindKeyPair(ctx context.Context, keyID, label string) (crypto.PrivateKey, error) {
	return lib.FindKeyPairOnSlot(ctx, lib.Slot.id, keyID, label)
}

// FindKeyPairOnSlot retrieves a previously created asymmetric key, using a specified slot.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
// ctx bounds the wait for a session.
func (lib *PKCS11Lib) FindKeyPairOnSlot(ctx context.Context, slot uint, keyID, label string) (crypto.PrivateKey, error) {
	var err error
	var k crypto.PrivateKey
	err = lib.withSessionCtx(ctx, slot, func(session pkcs11.SessionHandle) error {
		k, err = lib.findKeyPairOnSession(session, slot, keyID, label)
		return err
	})
	return k, err
}

// FindKeyPairOnSession retrieves a previously created asymmetric key, using a specified session.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
// session is owned by the caller; after Close it returns errClosed.
func (lib *PKCS11Lib) FindKeyPairOnSession(session pkcs11.SessionHandle, slot uint, keyID, label string) (crypto.PrivateKey, error) {
	if err := lib.enter(); err != nil {
		return nil, err
	}
	defer lib.exit()
	return lib.findKeyPairOnSession(session, slot, keyID, label)
}

func (lib *PKCS11Lib) findKeyPairOnSession(session pkcs11.SessionHandle, slot uint, keyID, label string) (crypto.PrivateKey, error) {
	var err error
	var privHandle, pubHandle pkcs11.ObjectHandle
	var pub crypto.PublicKey

	if privHandle, err = lib.findKey(session, keyID, label, pkcs11.CKO_PRIVATE_KEY, ^uint(0)); err != nil {
		return nil, errors.WithStack(err)
	}
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	if attributes, err = lib.Ctx.GetAttributeValue(session, privHandle, attributes); err != nil {
		return nil, errors.WithStack(err)
	}
	keyType, err := bytesToUlong(attributes[0].Value)
	if err != nil {
		return nil, errors.WithMessage(err, "CKA_KEY_TYPE")
	}
	if pubHandle, err = lib.findKey(session, keyID, label, pkcs11.CKO_PUBLIC_KEY, keyType); err != nil {
		return nil, errors.WithStack(err)
	}
	// the CKA_ID is known when the key was found by id; otherwise it is read
	var id []byte
	if keyID != "" {
		id = []byte(keyID)
	}
	obj, ref, err := lib.newPrivateKeyObject(session, privHandle, slot, id)
	if err != nil {
		return nil, err
	}
	switch keyType {
	case pkcs11.CKK_RSA:
		if pub, err = lib.exportRSAPublicKey(session, pubHandle); err != nil {
			return nil, errors.WithMessage(err, "exportRSAPublicKey")
		}
		return &PKCS11PrivateKeyRSA{key: &PKCS11PrivateKey{obj, pub}, lib: lib, ref: ref}, nil
	case pkcs11.CKK_EC:
		if pub, err = lib.exportECDSAPublicKey(session, pubHandle); err != nil {
			return nil, errors.WithMessage(err, "exportECDSAPublicKey")
		}
		return &PKCS11PrivateKeyECDSA{key: &PKCS11PrivateKey{obj, pub}, lib: lib, ref: ref}, nil
	case ckkMLDSA:
		if pub, err = lib.exportMLDSAPublicKey(session, pubHandle); err != nil {
			return nil, errors.WithMessage(err, "exportMLDSAPublicKey")
		}
		return &PKCS11PrivateKeyMLDSA{key: &PKCS11PrivateKey{obj, pub}, lib: lib, ref: ref}, nil
	default:
		return nil, errors.WithMessagef(errUnsupportedKeyType, "key type: %v", keyType)
	}
}

// ConvertToPublic converts a private key interface to crypto.PublicKey type
func ConvertToPublic(priv crypto.PrivateKey) (crypto.PublicKey, error) {
	switch t := priv.(type) {
	case *rsa.PrivateKey:
		return t.Public(), nil
	case *ecdsa.PrivateKey:
		return t.Public(), nil
	case *mldsa.PrivateKey:
		return t.Public(), nil
	case *PKCS11PrivateKeyRSA:
		return t.Public(), nil
	case *PKCS11PrivateKeyECDSA:
		return t.Public(), nil
	case *PKCS11PrivateKeyMLDSA:
		return t.Public(), nil
	case *privateKeyGen:
		// keys returned by GenerateKey wrap the PKCS#11 key
		return ConvertToPublic(t.PrivateKey)
	}
	return nil, errors.WithStack(errUnsupportedKeyType)
}

// GetKey returns the handle of the private key with CKA_ID keyID on the
// token lib is logged in to. A key the token does not have is a wrapped
// cryptoprov.ErrKeyNotFound. ctx bounds the wait for a session.
func (lib *PKCS11Lib) GetKey(ctx context.Context, keyID string) (crypto.PrivateKey, error) {
	key, err := lib.FindKeyPair(ctx, keyID, "")
	if err != nil {
		return nil, keyError(err, "unable to find key %q", keyID)
	}

	return key, err
}

// keyError wraps err with a message, and marks the error of a key the token
// does not have as cryptoprov.ErrKeyNotFound.
func keyError(err error, format string, args ...any) error {
	wrapped := errors.WithMessagef(err, format, args...)
	if errors.Is(err, errKeyNotFound) {
		return cryptoprov.MarkError(wrapped, cryptoprov.ErrKeyNotFound)
	}
	return wrapped
}

// exportKeyAdmitted is a test hook that runs in ExportKey once the operation
// holds its session, before the key lookup.
var exportKeyAdmitted = func() {}

// ExportKey returns PKCS#11 URI for specified key ID.
// It does not return key bytes. A key the token does not have is a wrapped
// cryptoprov.ErrKeyNotFound. ctx bounds the wait for a session.
func (lib *PKCS11Lib) ExportKey(ctx context.Context, keyID string) (string, []byte, error) {
	// the lookup and the token info read are one operation, so a Close
	// that starts in between waits for both instead of rejecting the lookup
	var ti pkcs11.TokenInfo
	err := lib.withSessionCtx(ctx, lib.Slot.id, func(session pkcs11.SessionHandle) error {
		exportKeyAdmitted()
		// ensure that key exists
		if _, err := lib.findKeyPairOnSession(session, lib.Slot.id, keyID, ""); err != nil {
			return keyError(err, "unable to find key %q", keyID)
		}
		var err error
		if ti, err = lib.Ctx.GetTokenInfo(lib.Slot.id); err != nil {
			return errors.WithMessage(err, "token info")
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}

	uri := fmt.Sprintf("pkcs11:manufacturer=%s;model=%s;serial=%s;token=%s;id=%s;type=private",
		lib.Config.Manufacturer(),
		lib.Config.Model(),
		strings.TrimSpace(ti.SerialNumber),
		strings.TrimSpace(ti.Label),
		strings.TrimSpace(keyID),
	)

	return uri, nil, nil
}

// KeyIdentifier interface provides key ID and label
type KeyIdentifier interface {
	KeyID() string
	Label() string
}

// PrivateKeyGen contains a reference to a loaded PKCS#11 private key object.
type privateKeyGen struct {
	id    string
	label string
	*PKCS11PrivateKey
	crypto.PrivateKey
}

func (p *privateKeyGen) KeyID() string {
	return p.id
}

func (p *privateKeyGen) Label() string {
	return p.label
}

func (p *privateKeyGen) Public() crypto.PublicKey {
	return p.PubKey
}

func (p *privateKeyGen) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if signer, ok := p.PrivateKey.(crypto.Signer); ok {
		b, err := signer.Sign(rand, digest, opts)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return b, nil
	}

	return nil, errors.WithStack(errUnsupportedKeyType)
}

// Decrypt decrypts ciphertext with priv.
// If opts is nil or of type *PKCS1v15DecryptOptions then PKCS#1 v1.5 decryption is performed.
// Otherwise opts must have type *OAEPOptions and OAEP decryption is done.
func (p *privateKeyGen) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	if decrypter, ok := p.PrivateKey.(crypto.Decrypter); ok {
		b, err := decrypter.Decrypt(rand, ciphertext, opts)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return b, nil
	}

	return nil, errors.WithStack(errUnsupportedKeyType)
}

// GenerateKey generates the key pair req describes on the token lib is
// logged in to and returns a handle that also reports its key ID and label
// (KeyIdentifier): an RSA key with the permissions of req.Usage (CKA_SIGN
// for cryptoprov.KeyUsageSign, CKA_DECRYPT for cryptoprov.KeyUsageEncrypt,
// or both), an ECDSA key on P-256, P-384 or P-521, or an ML-DSA key, for
// which the token must implement PKCS#11 v3.2 (SoftHSM 2.6 does not and
// fails the key pair generation). A PKCS#11 object has no tags, so req.Tags
// is a wrapped cryptoprov.ErrNotSupported. ctx bounds the wait for a
// session; a generation that has started is not interrupted.
func (lib *PKCS11Lib) GenerateKey(ctx context.Context, req *cryptoprov.GenerateKeyRequest) (crypto.PrivateKey, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if len(req.Tags) > 0 {
		return nil, errors.Wrap(cryptoprov.ErrNotSupported, "a PKCS#11 key has no tags")
	}

	var (
		key *PKCS11PrivateKey
		ref *objectRef
		pvk crypto.PrivateKey
	)
	switch req.Type {
	case certutil.KeyTypeRSA:
		priv, err := lib.GenerateRSAKeyPairWithLabel(ctx, req.Label, req.Size, req.KeyUsage())
		if err != nil {
			return nil, errors.WithStack(err)
		}
		key, ref, pvk = priv.key, priv.ref, priv
	case certutil.KeyTypeECDSA:
		curve, err := cryptoprov.ECDSACurve(req.Size)
		if err != nil {
			return nil, err
		}
		priv, err := lib.GenerateECDSAKeyPairWithLabel(ctx, req.Label, curve)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		key, ref, pvk = priv.key, priv.ref, priv
	default: // certutil.KeyTypeMLDSA, the only other type Validate accepts
		params, err := cryptoprov.MLDSAParameters(req.Size)
		if err != nil {
			return nil, err
		}
		priv, err := lib.GenerateMLDSAKeyPairWithLabel(ctx, req.Label, params)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		key, ref, pvk = priv.key, priv.ref, priv
	}

	id, label, err := lib.identify(ctx, &key.PKCS11Object, ref)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &privateKeyGen{
		id:               id,
		label:            label,
		PKCS11PrivateKey: key,
		PrivateKey:       pvk,
	}, nil
}

// IdentifyKey returns the ID and label for a private key. A key GenerateKey
// returned carries them; for any other key of this package they are read
// from the token, and ctx bounds the wait for a session.
func (lib *PKCS11Lib) IdentifyKey(ctx context.Context, priv crypto.PrivateKey) (keyID, label string, err error) {
	if ki, ok := priv.(KeyIdentifier); ok {
		return ki.KeyID(), ki.Label(), nil
	}

	var (
		p11o *PKCS11Object
		ref  *objectRef
	)
	switch t := priv.(type) {
	case *PKCS11PrivateKeyRSA:
		p11o, ref = &t.key.PKCS11Object, t.ref
	case *PKCS11PrivateKeyECDSA:
		p11o, ref = &t.key.PKCS11Object, t.ref
	case *PKCS11PrivateKeyMLDSA:
		p11o, ref = &t.key.PKCS11Object, t.ref
	default:
		return "", "", errors.WithStack(errUnsupportedKeyType)
	}

	keyID, label, err = lib.identify(ctx, p11o, ref)
	if err != nil {
		return "", "", errors.WithStack(err)
	}
	return keyID, label, nil
}
