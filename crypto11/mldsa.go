package crypto11

import (
	"crypto"
	"crypto/mldsa"
	"io"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov"
	pkcs11 "github.com/miekg/pkcs11"
)

// PKCS#11 v3.2 ML-DSA definitions (pkcs11t.h), which
// github.com/miekg/pkcs11 v1.1.2 (PKCS#11 v2.40) does not declare.
const (
	// ckkMLDSA is the CKA_KEY_TYPE of an ML-DSA key (CKK_ML_DSA).
	ckkMLDSA = 0x0000004A
	// ckaParameterSet is CKA_PARAMETER_SET, the CK_ULONG parameter set of an
	// ML-DSA public or private key.
	ckaParameterSet = 0x0000061D
	// ckpMLDSA44, ckpMLDSA65 and ckpMLDSA87 are the CKA_PARAMETER_SET values
	// CKP_ML_DSA_44, CKP_ML_DSA_65 and CKP_ML_DSA_87.
	ckpMLDSA44 = 0x00000001
	ckpMLDSA65 = 0x00000002
	ckpMLDSA87 = 0x00000003
	// ckmMLDSAKeyPairGen is CKM_ML_DSA_KEY_PAIR_GEN.
	ckmMLDSAKeyPairGen = 0x0000001C
	// ckmMLDSA is CKM_ML_DSA, the pure ML-DSA signature over a message. Its
	// optional CK_SIGN_ADDITIONAL_CONTEXT parameter (hedge variant and
	// context string) is not built: without it the token hedges (D6) and the
	// context is empty, which is what X.509 (RFC 9881), OCSP and JOSE
	// (RFC 9964) need, so no caller in this module has a use for it.
	ckmMLDSA = 0x0000001D
)

var (
	// errMLDSAExternalMu is returned when a μ (crypto.MLDSAMu) is given to
	// a PKCS#11 ML-DSA key: PKCS#11 v3.2 has no external-μ mechanism.
	errMLDSAExternalMu = errors.New("crypto11/mldsa: external μ signing is not supported by the PKCS#11 provider")
	// errMLDSAContext is returned for a non-empty *mldsa.Options context,
	// which needs the CK_SIGN_ADDITIONAL_CONTEXT mechanism parameter this
	// package does not build.
	errMLDSAContext = errors.New("crypto11/mldsa: context strings are not supported by the PKCS#11 provider")
	// errUnsupportedMLDSAParameterSet is returned for a CKA_PARAMETER_SET
	// value or mldsa.Parameters this package does not know.
	errUnsupportedMLDSAParameterSet = errors.New("crypto11/mldsa: unsupported ML-DSA parameter set")
)

// mldsaParameterSets maps the PKCS#11 CKA_PARAMETER_SET values to the Go
// parameter sets.
var mldsaParameterSets = map[uint]mldsa.Parameters{
	ckpMLDSA44: mldsa.MLDSA44(),
	ckpMLDSA65: mldsa.MLDSA65(),
	ckpMLDSA87: mldsa.MLDSA87(),
}

// mldsaParameterSet returns the CKA_PARAMETER_SET value of params.
func mldsaParameterSet(params mldsa.Parameters) (uint, error) {
	for set, p := range mldsaParameterSets {
		if p == params {
			return set, nil
		}
	}
	return 0, errors.Wrapf(errUnsupportedMLDSAParameterSet, "%s", params)
}

// mldsaParameters returns the Go parameter set of a CKA_PARAMETER_SET
// attribute value.
func mldsaParameters(value []byte) (mldsa.Parameters, error) {
	set, err := bytesToUlong(value)
	if err != nil {
		return mldsa.Parameters{}, errors.WithMessage(err, "CKA_PARAMETER_SET")
	}
	params, ok := mldsaParameterSets[set]
	if !ok {
		return mldsa.Parameters{}, errors.Wrapf(errUnsupportedMLDSAParameterSet, "CKA_PARAMETER_SET %d", set)
	}
	return params, nil
}

// mldsaPublicKey decodes an ML-DSA public key from its CKA_PARAMETER_SET
// and CKA_VALUE attribute values.
func mldsaPublicKey(parameterSet, value []byte) (*mldsa.PublicKey, error) {
	params, err := mldsaParameters(parameterSet)
	if err != nil {
		return nil, err
	}
	pub, err := mldsa.NewPublicKey(params, value)
	if err != nil {
		return nil, errors.WithMessage(err, "CKA_VALUE")
	}
	return pub, nil
}

// PKCS11PrivateKeyMLDSA contains a reference to a loaded PKCS#11 ML-DSA
// private key object. It signs messages, not digests (crypto/x509 passes
// the whole TBS with a zero hash); see Sign.
type PKCS11PrivateKeyMLDSA struct {
	key *PKCS11PrivateKey
	lib *PKCS11Lib
	// ref is the identity used to refresh the handle after a logout; nil
	// for a key without CKA_ID (XPKI-110)
	ref *objectRef
}

// Public returns the public half of the key, an *mldsa.PublicKey.
func (priv *PKCS11PrivateKeyMLDSA) Public() crypto.PublicKey {
	return priv.key.PubKey
}

// Sign signs message with the ML-DSA key through CKM_ML_DSA and returns the
// FIPS 204 signature. It accepts the message with nil options, a zero hash
// or an *mldsa.Options without context (cryptoprov.MLDSASignerOptions);
// the token hedges the signature. A digest hash, a μ (crypto.MLDSAMu) and
// a context string are errors, since PKCS#11 v3.2 has no external-μ
// mechanism and this package passes no mechanism parameter. PKCS#11 picks
// its own randomness, so rand is ignored.
func (priv *PKCS11PrivateKeyMLDSA) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	mu, context, err := cryptoprov.MLDSASignerOptions(opts)
	if err != nil {
		return nil, err
	}
	if mu {
		return nil, errors.WithStack(errMLDSAExternalMu)
	}
	if context != "" {
		return nil, errors.WithStack(errMLDSAContext)
	}

	var sig []byte
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmMLDSA, nil)}
	err = priv.lib.withKey(&priv.key.PKCS11Object, priv.ref, func(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		if err := priv.lib.Ctx.SignInit(session, mech, handle); err != nil {
			return err
		}
		var err error
		sig, err = priv.lib.Ctx.Sign(session, message)
		return err
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return sig, nil
}

// mldsaKeyMeta returns the KeyInfo.Meta of an ML-DSA key object: its parameter
// set name under cryptoprov.MetaParameterSet (design decision D3).
func (lib *PKCS11Lib) mldsaKeyMeta(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (map[string]string, error) {
	attributes, err := lib.Ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(ckaParameterSet, nil),
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	params, err := mldsaParameters(attributes[0].Value)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		cryptoprov.MetaParameterSet: params.String(),
	}, nil
}

// exportMLDSAPublicKey reads the public key of an ML-DSA public key object
// from its CKA_PARAMETER_SET and CKA_VALUE attributes.
func (lib *PKCS11Lib) exportMLDSAPublicKey(session pkcs11.SessionHandle, pubHandle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(ckaParameterSet, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attributes, err := lib.Ctx.GetAttributeValue(session, pubHandle, template)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return mldsaPublicKey(attributes[0].Value, attributes[1].Value)
}

// GenerateMLDSAKeyPairWithLabel creates an ML-DSA key pair of params with
// label and a random ID on the configured slot.
func (lib *PKCS11Lib) GenerateMLDSAKeyPairWithLabel(label string, params mldsa.Parameters) (*PKCS11PrivateKeyMLDSA, error) {
	return lib.GenerateMLDSAKeyPairOnSlot(lib.Slot.id, nil, []byte(label), params)
}

// GenerateMLDSAKeyPairOnSlot creates an ML-DSA key pair of params on slot
// with CKM_ML_DSA_KEY_PAIR_GEN, which needs a PKCS#11 v3.2 token. label
// and/or id can be nil, in which case random values are generated.
func (lib *PKCS11Lib) GenerateMLDSAKeyPairOnSlot(slot uint, id []byte, label []byte, params mldsa.Parameters) (*PKCS11PrivateKeyMLDSA, error) {
	var k *PKCS11PrivateKeyMLDSA
	var err error
	err = lib.withSession(slot, func(session pkcs11.SessionHandle) error {
		k, err = lib.generateMLDSAKeyPairOnSession(session, slot, id, label, params)
		return err
	})
	return k, unwrapNoRetry(err)
}

func (lib *PKCS11Lib) generateMLDSAKeyPairOnSession(session pkcs11.SessionHandle, slot uint, id []byte, label []byte, params mldsa.Parameters) (*PKCS11PrivateKeyMLDSA, error) {
	set, err := mldsaParameterSet(params)
	if err != nil {
		return nil, err
	}
	if len(label) == 0 {
		if label, err = lib.generateKeyLabel(session); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	if len(id) == 0 {
		if id, err = lib.generateKeyID(session); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(ckkMLDSA)),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(ckaParameterSet, set),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmMLDSAKeyPairGen, nil)}
	pubHandle, privHandle, err := lib.Ctx.GenerateKeyPair(session, mech, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		logger.KV(xlog.ERROR, "reason", "GenerateKeyPair", "mechanism", "CKM_ML_DSA_KEY_PAIR_GEN", "err", err)
		return nil, errors.WithStack(err)
	}
	// The pair now exists on the token: a failure from here on must not
	// make withSession run the generation again (noRetry), and the pair
	// is destroyed so the attempt leaves no orphan.
	pub, err := lib.exportMLDSAPublicKey(session, pubHandle)
	if err != nil {
		logger.KV(xlog.ERROR, "reason", "exportMLDSAPublicKey", "err", err)
		lib.discardGeneratedPair(session, pubHandle, privHandle)
		return nil, noRetry(errors.WithStack(err))
	}
	obj, ref, err := lib.newPrivateKeyObject(session, privHandle, slot, id)
	if err != nil {
		lib.discardGeneratedPair(session, pubHandle, privHandle)
		return nil, noRetry(err)
	}
	return &PKCS11PrivateKeyMLDSA{
		key: &PKCS11PrivateKey{obj, pub},
		lib: lib,
		ref: ref,
	}, nil
}

// GenerateMLDSAKey generates an ML-DSA key pair of params and returns a
// signer that also reports its key ID and label (KeyIdentifier). The token
// must implement PKCS#11 v3.2 ML-DSA; SoftHSM 2.6 does not and fails the
// key pair generation.
func (lib *PKCS11Lib) GenerateMLDSAKey(label string, params mldsa.Parameters) (crypto.PrivateKey, error) {
	priv, err := lib.GenerateMLDSAKeyPairWithLabel(label, params)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	id, l, err := lib.identify(&priv.key.PKCS11Object, priv.ref)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	k := &privateKeyGen{
		id:               id,
		label:            l,
		PKCS11PrivateKey: priv.key,
		PrivateKey:       priv,
	}

	return k, nil
}
