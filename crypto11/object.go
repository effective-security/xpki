package crypto11

import (
	"slices"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	pkcs11 "github.com/miekg/pkcs11"
)

// objectRef identifies a private object independently of its handle. A
// logout invalidates every private object handle for good (PKCS#11 §5.7.2),
// including after the application logs in again, so operations on a key
// look the object up again by class and CKA_ID when its handle is rejected
// (XPKI-110).
type objectRef struct {
	class uint
	id    []byte

	mu     sync.Mutex
	handle pkcs11.ObjectHandle
}

func (r *objectRef) current() pkcs11.ObjectHandle {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.handle
}

// newPrivateKeyObject builds the PKCS11Object of the private key handle on
// slot and its identity for handle refreshes. id is its CKA_ID when the
// caller knows it; otherwise it is read on session. The identity is nil,
// and the handle is never refreshed, when the id is empty: a lookup by
// class alone could bind the object to another key without an id. The
// identity is kept by the private key types (PKCS11PrivateKeyRSA,
// PKCS11PrivateKeyECDSA), not by the exported PKCS11Object, whose shape is
// part of the API.
func (lib *PKCS11Lib) newPrivateKeyObject(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle, slot uint, id []byte) (PKCS11Object, *objectRef, error) {
	if id == nil {
		attrs, err := lib.Ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil {
			return PKCS11Object{}, nil, errors.WithMessage(err, "CKA_ID")
		}
		id = attrs[0].Value
	}
	obj := PKCS11Object{
		Handle: handle,
		Slot:   slot,
	}
	var ref *objectRef
	if len(id) > 0 {
		ref = &objectRef{
			class:  pkcs11.CKO_PRIVATE_KEY,
			id:     slices.Clone(id), // the caller may reuse its slice
			handle: handle,
		}
	}
	return obj, ref, nil
}

// staleKeyHandleErrors are the results a token returns for an object
// handle that is no longer valid: CKR_OBJECT_HANDLE_INVALID in general, and
// CKR_KEY_HANDLE_INVALID from the signing and decryption functions.
var staleKeyHandleErrors = []pkcs11.Error{
	pkcs11.CKR_OBJECT_HANDLE_INVALID,
	pkcs11.CKR_KEY_HANDLE_INVALID,
}

// withKey runs f with a pooled session on the slot of obj and the current
// handle of obj (the refreshed one from ref when it is not nil). When f
// fails with a staleKeyHandleErrors code and ref is not nil, the handle is
// looked up again on the same session and f runs once more; while the
// token is logged out the lookup finds nothing, withSession logs in again
// and this repeats on the retry. Any other failure of f is returned as is.
// With the retries of withSession, f can run up to six times for one call;
// every run is a fresh single PKCS#11 operation on the key, so this is safe
// for Sign, Decrypt and Identify.
func (lib *PKCS11Lib) withKey(obj *PKCS11Object, ref *objectRef, f func(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error) error {
	return lib.withSession(obj.Slot, func(session pkcs11.SessionHandle) error {
		handle := obj.Handle
		if ref != nil {
			handle = ref.current()
		}
		err := f(session, handle)
		if ref == nil || !isP11Error(err, staleKeyHandleErrors) {
			return err
		}
		if rerr := lib.refreshHandle(session, ref, handle); rerr != nil {
			logger.KV(xlog.DEBUG, "reason", "refresh_handle", "slot", obj.Slot, "err", rerr)
			return err
		}
		return f(session, ref.current())
	})
}

// refreshHandle replaces the handle of ref when it still is stale, looking
// the object up by class and CKA_ID on session. A concurrent refresh of the
// same handle is done once.
func (lib *PKCS11Lib) refreshHandle(session pkcs11.SessionHandle, ref *objectRef, stale pkcs11.ObjectHandle) error {
	ref.mu.Lock()
	defer ref.mu.Unlock()
	if ref.handle != stale {
		return nil
	}
	handle, err := lib.ops.find(session, ref.class, ref.id)
	if err != nil {
		return err
	}
	logger.KV(xlog.DEBUG, "reason", "handle_refreshed", "old", stale, "new", handle)
	ref.handle = handle
	return nil
}

// discardGeneratedPair destroys a key pair whose generation succeeded but
// whose public key or CKA_ID could not be read afterwards, so the failed
// attempt leaves no orphan on the token when withSession runs the
// generation again after a re-login. Failures are logged: the handles are
// invalid when the token was logged out or removed, and the pair is then
// unreachable anyway.
func (lib *PKCS11Lib) discardGeneratedPair(session pkcs11.SessionHandle, pubHandle, privHandle pkcs11.ObjectHandle) {
	for _, h := range []pkcs11.ObjectHandle{privHandle, pubHandle} {
		if err := lib.Ctx.DestroyObject(session, h); err != nil {
			logger.KV(xlog.WARNING, "reason", "discard_generated_key", "handle", h, "err", err)
		}
	}
}
