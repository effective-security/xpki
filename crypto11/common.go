package crypto11

import (
	"C"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/pkcs11"
)

// AttributeNames maps PKCS11 attribute to string
var AttributeNames = map[uint]string{
	pkcs11.CKA_ID:       "ID",
	pkcs11.CKA_LABEL:    "Label",
	pkcs11.CKA_KEY_TYPE: "Key type",
	pkcs11.CKA_CLASS:    "Class",
}

// ObjectClassNames maps PKCS11 object class to string
var ObjectClassNames = map[uint]string{
	pkcs11.CKO_DATA:        "Data",
	pkcs11.CKO_CERTIFICATE: "Certificate",
	pkcs11.CKO_PUBLIC_KEY:  "Public key",
	pkcs11.CKO_PRIVATE_KEY: "Private key",
	pkcs11.CKO_SECRET_KEY:  "Secret key",
}

// KeyTypeNames maps PKCS11 key type to string
var KeyTypeNames = map[uint]string{
	pkcs11.CKK_RSA: "RSA",
	pkcs11.CKK_DSA: "DSA",
	pkcs11.CKK_DH:  "DH",
	pkcs11.CKK_EC:  "ECDSA",
}

// ulongSize is the width in bytes of a PKCS#11 CK_ULONG (C unsigned long)
// on this platform: 8 on LP64 unix, 4 on Windows and 32-bit platforms.
const ulongSize = int(C.sizeof_ulong)

// unavailableInformation is CK_UNAVAILABLE_INFORMATION, the PKCS#11 value
// for an attribute that cannot be read; BytesToUlong returns it for
// malformed input.
const unavailableInformation = ^uint(0)

// UlongToBytes encodes n as a native CK_ULONG attribute value (host byte
// order, ulongSize bytes). Where CK_ULONG is 32 bits, only the low 32 bits
// of n are kept.
func UlongToBytes(n uint) []byte {
	bs := make([]byte, ulongSize)
	if ulongSize == 8 {
		binary.NativeEndian.PutUint64(bs, uint64(n))
	} else {
		binary.NativeEndian.PutUint32(bs, uint32(n))
	}
	return bs
}

// BytesToUlong decodes a native CK_ULONG attribute value, such as
// CKA_KEY_TYPE or CKA_CLASS. It returns CK_UNAVAILABLE_INFORMATION (^uint(0))
// when bs is not exactly one CK_ULONG long, including a nil value for an
// attribute the token could not return.
//
// Deprecated: BytesToUlong cannot report malformed input; check the length
// and decode the value with encoding/binary.NativeEndian instead.
func BytesToUlong(bs []byte) uint {
	n, err := bytesToUlong(bs)
	if err != nil {
		return unavailableInformation
	}
	return n
}

// bytesToUlong decodes a native CK_ULONG attribute value and returns
// errMalformedUlong unless bs is exactly ulongSize bytes (XPKI-011).
func bytesToUlong(bs []byte) (uint, error) {
	if len(bs) != ulongSize {
		return 0, errors.Wrapf(errMalformedUlong, "length %d, expected %d", len(bs), ulongSize)
	}
	if ulongSize == 8 {
		return uint(binary.NativeEndian.Uint64(bs)), nil
	}
	return uint(binary.NativeEndian.Uint32(bs)), nil
}

// keyTypeAndClass returns the names of the CKA_KEY_TYPE and CKA_CLASS
// attribute values; unknown values give empty names.
func keyTypeAndClass(keyType, class *pkcs11.Attribute) (string, string, error) {
	t, err := bytesToUlong(keyType.Value)
	if err != nil {
		return "", "", errors.WithMessage(err, "CKA_KEY_TYPE")
	}
	c, err := bytesToUlong(class.Value)
	if err != nil {
		return "", "", errors.WithMessage(err, "CKA_CLASS")
	}
	return KeyTypeNames[t], ObjectClassNames[c], nil
}

// Representation of a *DSA signature
type dsaSignature struct {
	R, S *big.Int
}

// Populate a dsaSignature from a raw byte sequence
func (sig *dsaSignature) unmarshalBytes(sigBytes []byte) error {
	if len(sigBytes) == 0 || len(sigBytes)%2 != 0 {
		return errMalformedSignature
	}
	n := len(sigBytes) / 2
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(sigBytes[:n])
	sig.S.SetBytes(sigBytes[n:])
	return nil
}

// Populate a dsaSignature from DER encoding
func (sig *dsaSignature) unmarshalDER(sigDER []byte) error {
	if rest, err := asn1.Unmarshal(sigDER, sig); err != nil {
		return err
	} else if len(rest) > 0 {
		return errMalformedDER
	}
	return nil
}

// Return the DER encoding of a dsaSignature
func (sig *dsaSignature) marshalDER() ([]byte, error) {
	return asn1.Marshal(*sig)
}

// randomOnSession returns n random bytes generated on session.
// Key generation uses it on the session it already holds, since borrowing
// a second pooled session could wait forever at the session limit.
func (lib *PKCS11Lib) randomOnSession(session pkcs11.SessionHandle, n int) ([]byte, error) {
	raw, err := lib.Ctx.GenerateRandom(session, n)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(raw) < n {
		return nil, errors.WithStack(errCannotGetRandomData)
	}
	return raw, nil
}

// Pick a random label for a key
func (lib *PKCS11Lib) generateKeyLabel(session pkcs11.SessionHandle) ([]byte, error) {
	const labelSize = 32
	rawLabel, err := lib.randomOnSession(session, labelSize)
	if err != nil {
		return nil, err
	}

	t := time.Now().UTC()
	label := fmt.Sprintf("%04d%02d%02d%02d%02d%02d_%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), hex.EncodeToString(rawLabel))
	return []byte(label[:32]), nil
}

// Pick a random ID for a key
func (lib *PKCS11Lib) generateKeyID(session pkcs11.SessionHandle) ([]byte, error) {
	const labelSize = 32
	rawLabel, err := lib.randomOnSession(session, labelSize)
	if err != nil {
		return nil, err
	}

	label := hex.EncodeToString(rawLabel)
	return []byte(label[:32]), nil
}

// Compute DSA/ECDSA signature and marshal the result in DER form
func (lib *PKCS11Lib) dsaGeneric(slot uint, key pkcs11.ObjectHandle, mechanism uint, digest []byte) ([]byte, error) {
	var err error
	var sigBytes []byte
	var sig dsaSignature
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}
	err = lib.withSession(slot, func(session pkcs11.SessionHandle) error {
		if err = lib.Ctx.SignInit(session, mech, key); err != nil {
			return err
		}
		sigBytes, err = lib.Ctx.Sign(session, digest)
		return err
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if err = sig.unmarshalBytes(sigBytes); err != nil {
		return nil, errors.WithStack(err)
	}
	return sig.marshalDER()
}
