package crypto11

import (
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	pkcs11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakePIN = "1234"

var (
	errNotLoggedIn   = pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN)
	errStaleHandle   = pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
	errPINIncorrect  = pkcs11.Error(pkcs11.CKR_PIN_INCORRECT)
	errDeviceError   = pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
	errFunctionFails = pkcs11.Error(pkcs11.CKR_FUNCTION_FAILED)
)

// newFakeLoginLib is newFakeLib on a token that requires a login, with a
// login session the way Init leaves it.
func newFakeLoginLib(t *testing.T, maxSessions int) (*PKCS11Lib, *fakeSessions) {
	t.Helper()
	lib, f := newFakeLib(maxSessions)
	lib.Slot = &SlotTokenInfo{id: testSlot, flags: pkcs11.CKF_LOGIN_REQUIRED}
	lib.Config = &config{Pwd: fakePIN}
	session, err := lib.ops.open(testSlot)
	require.NoError(t, err)
	require.NoError(t, lib.ops.login(session, fakePIN))
	lib.Session = session
	f.mu.Lock()
	f.logins = 0
	f.mu.Unlock()
	return lib, f
}

// failNTimes returns a callback that fails with err on its first n calls
// and records every call.
func failNTimes(n int, err error) (f func(pkcs11.SessionHandle) error, calls *[]pkcs11.SessionHandle) {
	calls = &[]pkcs11.SessionHandle{}
	return func(session pkcs11.SessionHandle) error {
		*calls = append(*calls, session)
		if len(*calls) <= n {
			return err
		}
		return nil
	}, calls
}

// idleSessions borrows n sessions at once and returns them, so the pool
// holds n idle sessions.
func idleSessions(t *testing.T, lib *PKCS11Lib, n int) []pkcs11.SessionHandle {
	t.Helper()
	release := make(chan struct{})
	sessions := make([]pkcs11.SessionHandle, 0, n)
	dones := make([]<-chan error, 0, n)
	for i := 0; i < n; i++ {
		s, done := holdSession(t, lib, testSlot, release)
		sessions = append(sessions, s)
		dones = append(dones, done)
	}
	close(release)
	for _, done := range dones {
		require.NoError(t, waitErr(t, done))
	}
	return sessions
}

// CKR_USER_NOT_LOGGED_IN on a login token re-logs in once with the
// configured PIN, replaces the login session and runs the callback again.
func TestWithSession_ReloginRetries(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	old := lib.Session
	f.logout()
	cb, calls := failNTimes(1, errNotLoggedIn)

	require.NoError(t, lib.withSession(testSlot, cb))
	assert.Len(t, *calls, 2)
	assert.Equal(t, 1, f.loginCount())
	assert.Equal(t, fakePIN, f.loginPIN)
	assert.NotEqual(t, old, lib.Session, "login session must be replaced")
	assert.False(t, f.isLive(old), "old login session must be closed")
	assert.True(t, f.isLive(lib.Session))
	assert.Equal(t, uint64(1), lib.loginGen.Load())
	_, _, live, _ := f.counts()
	assert.Equal(t, 2, live, "login session and one idle pooled session")
}

// The re-login retry happens once: a callback that keeps failing returns
// its error after the second attempt.
func TestWithSession_ReloginOnce(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	f.logout()
	cb, calls := failNTimes(3, errNotLoggedIn)

	err := lib.withSession(testSlot, cb)
	assert.ErrorIs(t, err, errNotLoggedIn)
	assert.Len(t, *calls, 2)
	assert.Equal(t, 1, f.loginCount())
}

// Without CKF_LOGIN_REQUIRED there is nothing to log in to: the error is
// returned at once.
func TestWithSession_NoReloginWithoutLoginRequired(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	lib.Slot.flags = 0
	f.logout()
	cb, calls := failNTimes(1, errNotLoggedIn)

	err := lib.withSession(testSlot, cb)
	assert.ErrorIs(t, err, errNotLoggedIn)
	assert.Len(t, *calls, 1)
	assert.Equal(t, 0, f.loginCount())
}

// CKR_USER_NOT_LOGGED_IN from a token that is still logged in (a key with
// CKA_ALWAYS_AUTHENTICATE) is not a logout: no re-login, no retry.
func TestWithSession_NotLoggedInWhileLoggedIn(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	old := lib.Session
	cb, calls := failNTimes(1, errNotLoggedIn)

	err := lib.withSession(testSlot, cb)
	assert.ErrorIs(t, err, errNotLoggedIn)
	assert.Len(t, *calls, 1)
	assert.Equal(t, 0, f.loginCount())
	assert.Equal(t, old, lib.Session)
}

// A logged-out failure on a slot other than the login slot is returned:
// only the token Init selected is logged in again.
func TestWithSession_NoReloginOnOtherSlot(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	f.logout()
	cb, calls := failNTimes(1, errNotLoggedIn)

	err := lib.withSession(testSlot+1, cb)
	assert.ErrorIs(t, err, errNotLoggedIn)
	assert.Len(t, *calls, 1)
	assert.Equal(t, 0, f.loginCount())
	assert.Equal(t, uint64(0), lib.loginGen.Load())
}

// A re-login by another caller while the callback ran explains its
// login-sensitive failure even though the session state is already a user
// one again: the callback is retried without a second login.
func TestWithSession_RetryAfterConcurrentRelogin(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	f.logout()

	var calls int
	require.NoError(t, lib.withSession(testSlot, func(pkcs11.SessionHandle) error {
		calls++
		if calls == 1 {
			// another caller logs in again before this one reports its failure
			require.NoError(t, lib.relogin(lib.loginGen.Load()))
			return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
		}
		return nil
	}))
	assert.Equal(t, 2, calls)
	assert.Equal(t, 1, f.loginCount())
	assert.Equal(t, uint64(1), lib.loginGen.Load())
}

// Other errors are neither retried nor a reason to log in again; device
// errors still discard the session.
func TestWithSession_NoRetryOnOtherErrors(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	for _, tc := range []struct {
		name      string
		err       error
		discarded bool
	}{
		{"function failed", errFunctionFails, false},
		{"device removed", pkcs11.Error(pkcs11.CKR_DEVICE_REMOVED), true},
		{"stale fresh session", errStaleHandle, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, closedBefore, _, _ := f.counts()
			cb, calls := failNTimes(1, tc.err)
			err := lib.withSession(testSlot, cb)
			assert.ErrorIs(t, err, tc.err)
			assert.Len(t, *calls, 1)
			_, closedAfter, _, _ := f.counts()
			if tc.discarded {
				assert.Equal(t, closedBefore+1, closedAfter)
			} else {
				assert.Equal(t, closedBefore, closedAfter)
			}
		})
	}
	assert.Equal(t, 0, f.loginCount())
}

// A PIN failure is returned with the login error, leaves the login session
// in place and is not retried; a transient failure is retried by the next
// operation.
func TestWithSession_ReloginFailure(t *testing.T) {
	t.Parallel()
	t.Run("pin is sticky", func(t *testing.T) {
		lib, f := newFakeLoginLib(t, 4)
		old := lib.Session
		f.logout()
		f.setLoginErr(errPINIncorrect)

		cb, calls := failNTimes(9, errNotLoggedIn)
		err := lib.withSession(testSlot, cb)
		assert.ErrorIs(t, err, errPINIncorrect)
		assert.ErrorContains(t, err, "re-login after ")
		assert.Len(t, *calls, 1)
		assert.Equal(t, 1, f.loginCount())
		assert.Equal(t, old, lib.Session)
		assert.True(t, f.isLive(old))
		_, _, live, _ := f.counts()
		assert.Equal(t, 2, live, "the failed login session is closed")

		f.setLoginErr(nil)
		err = lib.withSession(testSlot, cb)
		assert.ErrorIs(t, err, errPINIncorrect)
		assert.Len(t, *calls, 2)
		assert.Equal(t, 1, f.loginCount(), "a PIN failure is not retried")
		assert.Equal(t, uint64(0), lib.loginGen.Load())
	})
	t.Run("transient is retried", func(t *testing.T) {
		lib, f := newFakeLoginLib(t, 4)
		f.logout()
		f.setLoginErr(errDeviceError)

		cb, calls := failNTimes(1, errNotLoggedIn)
		err := lib.withSession(testSlot, cb)
		assert.ErrorIs(t, err, errDeviceError)
		assert.Len(t, *calls, 1)
		assert.Equal(t, 1, f.loginCount())

		f.setLoginErr(nil)
		cb, calls = failNTimes(1, errNotLoggedIn)
		require.NoError(t, lib.withSession(testSlot, cb))
		assert.Len(t, *calls, 2)
		assert.Equal(t, 2, f.loginCount())
		assert.Equal(t, uint64(1), lib.loginGen.Load())
	})
	t.Run("open fails", func(t *testing.T) {
		lib, f := newFakeLoginLib(t, 4)
		idleSessions(t, lib, 1)
		f.logout()
		f.setOpenErr(errDeviceError)

		cb, calls := failNTimes(1, errNotLoggedIn)
		err := lib.withSession(testSlot, cb)
		assert.ErrorIs(t, err, errDeviceError)
		assert.ErrorContains(t, err, "open login session")
		assert.Len(t, *calls, 1)
		assert.Equal(t, 0, f.loginCount())
	})
}

// An idle session whose handle went stale is replaced, together with the
// other idle sessions of the slot, and the callback runs on a new one.
func TestWithSession_StaleIdleSessionRetried(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	stale := idleSessions(t, lib, 2)
	opened, _, _, _ := f.counts()

	var calls []pkcs11.SessionHandle
	require.NoError(t, lib.withSession(testSlot, func(session pkcs11.SessionHandle) error {
		calls = append(calls, session)
		for _, s := range stale {
			if s == session {
				return errStaleHandle
			}
		}
		return nil
	}))
	require.Len(t, calls, 2)
	assert.Contains(t, stale, calls[0])
	assert.NotContains(t, stale, calls[1])
	for _, s := range stale {
		assert.False(t, f.isLive(s), "stale idle sessions must be closed")
	}
	openedAfter, _, live, _ := f.counts()
	assert.Equal(t, opened+1, openedAfter)
	assert.Equal(t, 2, live, "login session and the new idle session")
	assert.Equal(t, 0, f.loginCount())
}

// The stale retry happens once even when the replacement is stale too.
func TestWithSession_StaleRetryOnce(t *testing.T) {
	t.Parallel()
	lib, _ := newFakeLoginLib(t, 4)
	idleSessions(t, lib, 1)
	cb, calls := failNTimes(9, errStaleHandle)

	err := lib.withSession(testSlot, cb)
	assert.ErrorIs(t, err, errStaleHandle)
	assert.Len(t, *calls, 2)
}

// After a token reinsertion the idle session is stale and the token is
// logged out: one call recovers from both, running the callback three times.
func TestWithSession_StaleThenNotLoggedIn(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	stale := idleSessions(t, lib, 1)[0]
	f.logout()

	var calls []pkcs11.SessionHandle
	require.NoError(t, lib.withSession(testSlot, func(session pkcs11.SessionHandle) error {
		calls = append(calls, session)
		if session == stale {
			return errStaleHandle
		}
		if lib.loginGen.Load() == 0 {
			return errNotLoggedIn
		}
		return nil
	}))
	assert.Len(t, calls, 3)
	assert.Equal(t, 1, f.loginCount())
	assert.Equal(t, uint64(1), lib.loginGen.Load())
}

// Concurrent callers that observe the same logout share one re-login.
func TestWithSession_ConcurrentReloginOnce(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	f.logout()
	const workers = 16
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- lib.withSession(testSlot, func(pkcs11.SessionHandle) error {
				if lib.loginGen.Load() == 0 {
					return errNotLoggedIn
				}
				return nil
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, 1, f.loginCount())
	assert.Equal(t, uint64(1), lib.loginGen.Load())
}

// Close waits for a re-login in flight and then closes the new login
// session; the retried operation fails with errClosed.
func TestClose_DuringRelogin(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	f.logout()
	gate := make(chan struct{})
	loggingIn := make(chan struct{}, 1)
	f.mu.Lock()
	f.loginGate, f.loggingIn = gate, loggingIn
	f.mu.Unlock()

	cb, calls := failNTimes(1, errNotLoggedIn)
	opDone := make(chan error, 1)
	go func() { opDone <- lib.withSession(testSlot, cb) }()
	select {
	case <-loggingIn:
	case err := <-opDone:
		require.FailNow(t, "operation returned before logging in", "%v", err)
	case <-time.After(testDeadline):
		require.FailNow(t, "re-login did not start")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- lib.Close() }()
	assertBlocked(t, closeDone)

	close(gate)
	assert.ErrorIs(t, waitErr(t, opDone), errClosed)
	require.NoError(t, waitErr(t, closeDone))
	assert.Len(t, *calls, 1)
	assert.Equal(t, 1, f.loginCount())
	assert.Zero(t, lib.Session)
	_, _, live, _ := f.counts()
	assert.Equal(t, 0, live, "no session may survive Close")
}

// newFakeKeyObject returns a private key object and the identity through
// which its handle can be looked up again by CKA_ID.
func newFakeKeyObject(f *fakeSessions, id string, handle pkcs11.ObjectHandle) (*PKCS11Object, *objectRef) {
	f.setObject(id, handle)
	return &PKCS11Object{Handle: handle, Slot: testSlot},
		&objectRef{class: pkcs11.CKO_PRIVATE_KEY, id: []byte(id), handle: handle}
}

// After a logout a private key handle is invalid for good: the operation
// logs the token in again, looks the key up by CKA_ID and runs on the new
// handle, while Handle keeps the original value.
func TestWithKey_RefreshAfterLogout(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	obj, ref := newFakeKeyObject(f, "key-1", 100)
	f.logout()
	f.setObject("key-1", 200)

	var handles []pkcs11.ObjectHandle
	require.NoError(t, lib.withKey(obj, ref, func(_ pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		handles = append(handles, handle)
		if handle == 100 {
			return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
		}
		return nil
	}))
	assert.Equal(t, []pkcs11.ObjectHandle{100, 100, 200}, handles)
	assert.Equal(t, 1, f.loginCount())
	assert.Equal(t, pkcs11.ObjectHandle(200), ref.current())
	assert.Equal(t, pkcs11.ObjectHandle(100), obj.Handle, "the exported handle is not rewritten")

	// later operations use the new handle without another lookup
	finds := f.findCount()
	require.NoError(t, lib.withKey(obj, ref, func(_ pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		assert.Equal(t, pkcs11.ObjectHandle(200), handle)
		return nil
	}))
	assert.Equal(t, finds, f.findCount())
}

// An invalid handle while logged in is refreshed without a login; a key
// that is gone returns the original error, and an object without identity
// is not refreshed.
func TestWithKey_RefreshWhileLoggedIn(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	obj, ref := newFakeKeyObject(f, "key-2", 100)
	f.setObject("key-2", 300)

	cb, calls := failNTimes(1, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID))
	require.NoError(t, lib.withKey(obj, ref, func(_ pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
		return cb(pkcs11.SessionHandle(handle))
	}))
	assert.Equal(t, []pkcs11.SessionHandle{100, 300}, *calls)
	assert.Equal(t, 0, f.loginCount())

	gone, goneRef := newFakeKeyObject(f, "gone", 400)
	f.mu.Lock()
	delete(f.objects, "gone")
	f.mu.Unlock()
	err := lib.withKey(gone, goneRef, func(pkcs11.SessionHandle, pkcs11.ObjectHandle) error {
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	})
	assert.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID))
	assert.Equal(t, pkcs11.ObjectHandle(400), goneRef.current())

	// an object without identity (built outside the package, or without a
	// CKA_ID) is not refreshed
	plain := &PKCS11Object{Handle: 500, Slot: testSlot}
	finds := f.findCount()
	err = lib.withKey(plain, nil, func(pkcs11.SessionHandle, pkcs11.ObjectHandle) error {
		return pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	})
	assert.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID))
	assert.Equal(t, finds, f.findCount())
	assert.Equal(t, 0, f.loginCount())
}

// errKeyNotFound from a logged-out session (private objects are invisible)
// triggers a re-login and a retry; while logged in it is final, and a
// failing state query means no re-login.
func TestWithSession_KeyNotFoundWhenLoggedOut(t *testing.T) {
	t.Parallel()
	t.Run("logged out", func(t *testing.T) {
		lib, f := newFakeLoginLib(t, 4)
		f.logout()
		var calls int
		require.NoError(t, lib.withSession(testSlot, func(pkcs11.SessionHandle) error {
			calls++
			if lib.loginGen.Load() == 0 {
				return errors.WithStack(errKeyNotFound)
			}
			return nil
		}))
		assert.Equal(t, 2, calls)
		assert.Equal(t, 1, f.loginCount())
	})
	t.Run("logged in", func(t *testing.T) {
		lib, f := newFakeLoginLib(t, 4)
		cb, calls := failNTimes(1, errors.WithStack(errKeyNotFound))
		err := lib.withSession(testSlot, cb)
		assert.ErrorIs(t, err, errKeyNotFound)
		assert.Len(t, *calls, 1)
		assert.Equal(t, 0, f.loginCount())
	})
	t.Run("state unknown", func(t *testing.T) {
		lib, f := newFakeLoginLib(t, 4)
		f.logout()
		f.mu.Lock()
		f.stateErr = errDeviceError
		f.mu.Unlock()
		cb, calls := failNTimes(1, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID))
		err := lib.withSession(testSlot, cb)
		assert.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID))
		assert.Len(t, *calls, 1)
		assert.Equal(t, 0, f.loginCount())
	})
}

// A callback that changed the token before failing returns its error
// wrapped by noRetry: withSession neither logs in again nor runs it again,
// and the caller sees the unwrapped error.
func TestWithSession_NoRetryAfterCommit(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLoginLib(t, 4)
	f.logout()
	idleSessions(t, lib, 1)

	var calls int
	err := lib.withSession(testSlot, func(pkcs11.SessionHandle) error {
		calls++
		return noRetry(errNotLoggedIn)
	})
	assert.ErrorIs(t, err, errNotLoggedIn)
	var nr *noRetryError
	assert.False(t, errors.As(err, &nr), "the marker is removed")
	assert.Equal(t, errNotLoggedIn, err)
	assert.Equal(t, 1, calls)
	assert.Equal(t, 0, f.loginCount())
	assert.Nil(t, noRetry(nil))
	assert.Equal(t, errStaleHandle, unwrapNoRetry(noRetry(errStaleHandle)))
}

// The identity keeps its own copy of a caller-supplied CKA_ID, and a key
// without CKA_ID gets no identity.
func TestNewPrivateKeyObject_Identity(t *testing.T) {
	t.Parallel()
	lib, _ := newFakeLoginLib(t, 4)
	id := []byte("caller-id")
	obj, ref, err := lib.newPrivateKeyObject(0, 7, testSlot, id)
	require.NoError(t, err)
	assert.Equal(t, PKCS11Object{Handle: 7, Slot: testSlot}, obj)
	require.NotNil(t, ref)
	id[0] = 'X'
	assert.Equal(t, []byte("caller-id"), ref.id, "the caller's slice is copied")
	assert.Equal(t, pkcs11.ObjectHandle(7), ref.current())

	_, ref, err = lib.newPrivateKeyObject(0, 8, testSlot, []byte{})
	require.NoError(t, err)
	assert.Nil(t, ref, "no identity without a CKA_ID")
}

// C_Sign/C_Decrypt report a stale key handle as CKR_KEY_HANDLE_INVALID: it
// is refreshed like CKR_OBJECT_HANDLE_INVALID while logged in, and after a
// logout it triggers the re-login and the refresh.
func TestWithKey_KeyHandleInvalid(t *testing.T) {
	t.Parallel()
	errKeyHandle := pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID)
	t.Run("logged in", func(t *testing.T) {
		lib, f := newFakeLoginLib(t, 4)
		obj, ref := newFakeKeyObject(f, "key-3", 100)
		f.setObject("key-3", 300)
		var handles []pkcs11.ObjectHandle
		require.NoError(t, lib.withKey(obj, ref, func(_ pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
			handles = append(handles, handle)
			if handle == 100 {
				return errKeyHandle
			}
			return nil
		}))
		assert.Equal(t, []pkcs11.ObjectHandle{100, 300}, handles)
		assert.Equal(t, 0, f.loginCount())
	})
	t.Run("logged out", func(t *testing.T) {
		lib, f := newFakeLoginLib(t, 4)
		obj, ref := newFakeKeyObject(f, "key-4", 100)
		f.logout()
		f.setObject("key-4", 400)
		var handles []pkcs11.ObjectHandle
		require.NoError(t, lib.withKey(obj, ref, func(_ pkcs11.SessionHandle, handle pkcs11.ObjectHandle) error {
			handles = append(handles, handle)
			if handle == 100 {
				return errKeyHandle
			}
			return nil
		}))
		assert.Equal(t, []pkcs11.ObjectHandle{100, 100, 400}, handles)
		assert.Equal(t, 1, f.loginCount())
		assert.Equal(t, pkcs11.ObjectHandle(400), ref.current())
	})
}
