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

// errNoTokenSelector is returned by Init when the configuration names
// neither a token serial nor a token label.
var errNoTokenSelector = errors.New("crypto11: token serial or token label is required")

// errMalformedUlong is returned when a CK_ULONG attribute value does not
// have the native CK_ULONG width.
var errMalformedUlong = errors.New("crypto11: malformed CK_ULONG attribute value")

// errCannotOpenPKCS11 is returned when the PKCS#11 library cannot be opened
var errCannotOpenPKCS11 = errors.New("crypto11: could not open PKCS#11")

// errClosed is returned by operations on a PKCS11Lib after Close
var errClosed = errors.New("crypto11: PKCS#11 library is closed")

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

// PKCS11Lib contains a reference to an open PKCS#11 slot and configuration.
//
// Every PKCS11Lib opened on the same library path shares one loaded module:
// the first Init initializes it and the last Close finalizes it. Each
// PKCS11Lib owns its own session pools and login session. It is safe for
// concurrent use; after Close its operations return an error.
type PKCS11Lib struct {
	// Ctx is the shared module context. It is nil after Close.
	Ctx    *pkcs11.Ctx
	Config TokenConfig
	// Session is the login session on Slot, opened by Init and closed by
	// Close. It keeps the token logged in while pooled sessions are opened
	// and closed; do not close it or use it concurrently.
	Session pkcs11.SessionHandle
	Slot    *SlotTokenInfo

	module      *module
	maxSessions int
	ops         sessionOps

	// closeOnce runs close; closeErr is its result
	closeOnce sync.Once
	closeErr  error

	// mu protects pools, closed and active
	mu sync.Mutex
	// drained is signalled when active drops to zero after Close
	drained sync.Cond
	// pools maps slot IDs to session pools
	pools  map[uint]*sessionPool
	closed bool
	// active counts operations in flight
	active int
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

// Close releases the resources of lib. New operations fail at once, and
// Close waits for the operations in flight to return their sessions. It
// then closes the sessions of lib, including the login session, and
// releases the module; the last PKCS11Lib on a module calls C_Finalize
// (unless the module was initialized outside this package) and unloads it.
// Close is idempotent: every call, including concurrent ones, waits for
// the first to finish and returns its result.
//
// Close must not be called from inside an operation of lib, which it would
// wait for forever. Sessions a caller opened with NewSession, and the
// *OnSession methods that use them, are not tracked: close those sessions
// and stop using them before Close.
func (lib *PKCS11Lib) Close() error {
	lib.closeOnce.Do(func() {
		lib.closeErr = lib.close()
	})
	return lib.closeErr
}

func (lib *PKCS11Lib) close() error {
	lib.mu.Lock()
	lib.closed = true
	pools := lib.pools
	lib.mu.Unlock()

	var errs []error
	for _, pool := range pools {
		errs = append(errs, pool.close())
	}

	lib.mu.Lock()
	for lib.active > 0 {
		lib.drained.Wait()
	}
	lib.mu.Unlock()
	// sessions returned after pool.close were closed by put
	for _, pool := range pools {
		errs = append(errs, pool.returnedErrs()...)
	}

	if lib.Session != 0 {
		if err := lib.ops.close(lib.Session); err != nil {
			errs = append(errs, errors.WithMessage(err, "close login session"))
		}
		lib.Session = 0
	}
	if lib.module != nil {
		errs = append(errs, lib.module.release())
		lib.module = nil
	}
	lib.Ctx = nil
	return errors.Join(errs...)
}
