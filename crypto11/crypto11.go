package crypto11

import (
	"crypto"
	"sync"

	"github.com/cockroachdb/errors"
	pkcs11 "github.com/miekg/pkcs11"
)

// errTokenNotFound represents the failure to find the requested PKCS#11 token
var errTokenNotFound = errors.New("crypto11: could not find PKCS#11 token")

// errKeyNotFound represents the failure to find the requested PKCS#11 key
var errKeyNotFound = errors.New("crypto11: could not find PKCS#11 key")

// errCannotOpenPKCS11 is returned when the PKCS#11 library cannot be opened
var errCannotOpenPKCS11 = errors.New("crypto11: could not open PKCS#11")

// errCannotGetRandomData is returned when the PKCS#11 library fails to return enough random data
var errCannotGetRandomData = errors.New("crypto11: cannot get random data from PKCS#11")

// errUnsupportedKeyType is returned when the PKCS#11 library returns a key type that isn't supported
var errUnsupportedKeyType = errors.New("crypto11: unrecognized key type")

// errMalformedRSAKey is returned when an RSA key is not in a suitable form.
//
// Currently this means that the public exponent is either bigger than
// 32 bits, or less than 2.
var errMalformedRSAKey = errors.New("crypto11/rsa: malformed RSA key")

// errUnsupportedRSAOptions is returned when an unsupported RSA option is requested.
//
// Currently this means a nontrivial SessionKeyLen when decrypting; or
// an unsupported hash function; or crypto.rsa.PSSSaltLengthAuto was
// requested.
var errUnsupportedRSAOptions = errors.New("crypto11/rsa: unsupported RSA option value")

// errMalformedDER represents a failure to decode an ASN.1-encoded message
var errMalformedDER = errors.New("crypto11: malformed DER message")

// errMalformedSignature represents a failure to decode a signature.  This
// means the PKCS#11 library has returned an empty or odd-length byte
// string.
var errMalformedSignature = errors.New("crypto11: malformed signature")

// errUnsupportedEllipticCurve is returned when an elliptic curve
// unsupported by crypto11 is specified.  Note that the error behavior
// for an elliptic curve unsupported by the underlying PKCS#11
// implementation will be different.
var errUnsupportedEllipticCurve = errors.New("crypto11/ecdsa: unsupported elliptic curve")

// errMalformedPoint is returned when crypto.elliptic.Unmarshal cannot
// decode a point.
var errMalformedPoint = errors.New("crypto11/ecdsa: malformed elliptic curve point")

// SlotInfo provides information about a slot.
type SlotInfo pkcs11.SlotInfo

// TokenInfo provides information about a token.
type TokenInfo pkcs11.TokenInfo

// SlotTokenInfo provides info about Token on slot
type SlotTokenInfo struct {
	id           uint
	description  string
	label        string
	manufacturer string
	model        string
	serial       string
	flags        uint
}

// SlotID is ID of the slot
func (s *SlotTokenInfo) SlotID() uint {
	return s.id
}

// Description of the slot
func (s *SlotTokenInfo) Description() string {
	return s.description
}

// Label of the token
func (s *SlotTokenInfo) Label() string {
	return s.label
}

// Manufacturer of the token
func (s *SlotTokenInfo) Manufacturer() string {
	return s.manufacturer
}

// Model of the token
func (s *SlotTokenInfo) Model() string {
	return s.model
}

// SerialNumber of the token
func (s *SlotTokenInfo) SerialNumber() string {
	return s.serial
}

// PKCS11Lib contains a reference to an open PKCS#11 slot and configuration
type PKCS11Lib struct {
	Ctx     *pkcs11.Ctx
	Config  TokenConfig
	Session pkcs11.SessionHandle
	Slot    *SlotTokenInfo

	// Map of slot IDs to session pools
	sessionPools map[uint]chan pkcs11.SessionHandle

	// Mutex protecting SessionPools
	sessionPoolMutex sync.Mutex
}

// PKCS11Object contains a reference to a loaded PKCS#11 object.
type PKCS11Object struct {
	// The PKCS#11 object handle.
	Handle pkcs11.ObjectHandle

	// The PKCS#11 slot number.
	//
	// This is used internally to find a session handle that can
	// access this object.
	Slot uint
}

// PKCS11PrivateKey contains a reference to a loaded PKCS#11 private key object.
type PKCS11PrivateKey struct {
	PKCS11Object

	// The corresponding public key
	PubKey crypto.PublicKey
}

// Public returns the public half of a private key.
//
// This partially implements the go.crypto.Signer and go.crypto.Decrypter interfaces for
// PKCS11PrivateKey. (The remains of the implementation is in the
// key-specific types.)
func (p PKCS11PrivateKey) Public() crypto.PublicKey {
	return p.PubKey
}

// Manufacturer returns manufacturer for the calling library
func (lib *PKCS11Lib) Manufacturer() string {
	return lib.Config.Manufacturer()
}

// Model returns model for the calling library
func (lib *PKCS11Lib) Model() string {
	return lib.Config.Model()
}

// Close releases allocated resources
func (lib *PKCS11Lib) Close() {
	if lib.Ctx != nil {
		lib.Ctx.Destroy()
		_ = lib.Ctx.Finalize()
		lib.Ctx = nil
	}
}
