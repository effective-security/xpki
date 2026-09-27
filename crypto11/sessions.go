package crypto11

import (
	"slices"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	pkcs11 "github.com/miekg/pkcs11"
)

const sessionFlags = pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION

// unusableSessionErrors are PKCS#11 results after which a session is closed
// instead of being returned to its pool.
var unusableSessionErrors = []pkcs11.Error{
	pkcs11.CKR_SESSION_HANDLE_INVALID,
	pkcs11.CKR_SESSION_CLOSED,
	pkcs11.CKR_OPERATION_ACTIVE,
	pkcs11.CKR_DEVICE_ERROR,
	pkcs11.CKR_DEVICE_REMOVED,
	pkcs11.CKR_TOKEN_NOT_PRESENT,
}

// staleSessionErrors are PKCS#11 results that mean the session handle is no
// longer valid, as after a token was removed and reinserted. An idle pooled
// session that fails with one of them is replaced and the operation is
// retried once on a new session (XPKI-110).
var staleSessionErrors = []pkcs11.Error{
	pkcs11.CKR_SESSION_HANDLE_INVALID,
	pkcs11.CKR_SESSION_CLOSED,
}

// stickyLoginErrors are C_Login results caused by the PIN. A re-login that
// fails with one of them is not attempted again by this PKCS11Lib, so a
// changed PIN cannot lock the token through repeated operations; a new Init
// is needed (XPKI-110).
var stickyLoginErrors = []pkcs11.Error{
	pkcs11.CKR_PIN_INCORRECT,
	pkcs11.CKR_PIN_INVALID,
	pkcs11.CKR_PIN_LEN_RANGE,
	pkcs11.CKR_PIN_EXPIRED,
	pkcs11.CKR_PIN_LOCKED,
}

// sessionOps opens, closes, logs in and inspects sessions and looks objects
// up; tests replace it to exercise pools, re-login and handle refresh
// without a PKCS#11 module.
type sessionOps struct {
	open  func(slot uint) (pkcs11.SessionHandle, error)
	close func(session pkcs11.SessionHandle) error
	login func(session pkcs11.SessionHandle, pin string) error
	// state returns the CKS_* session state
	state func(session pkcs11.SessionHandle) (uint, error)
	// find returns the single object of class with CKA_ID id, errKeyNotFound
	// when there is none, or errAmbiguousObject when there are several
	find func(session pkcs11.SessionHandle, class uint, id []byte) (pkcs11.ObjectHandle, error)
}

func ctxSessionOps(ctx *pkcs11.Ctx) sessionOps {
	return sessionOps{
		open: func(slot uint) (pkcs11.SessionHandle, error) {
			return ctx.OpenSession(slot, sessionFlags)
		},
		close: ctx.CloseSession,
		login: func(session pkcs11.SessionHandle, pin string) error {
			return ctx.Login(session, pkcs11.CKU_USER, pin)
		},
		state: func(session pkcs11.SessionHandle) (uint, error) {
			info, err := ctx.GetSessionInfo(session)
			if err != nil {
				return 0, err
			}
			return info.State, nil
		},
		find: func(session pkcs11.SessionHandle, class uint, id []byte) (pkcs11.ObjectHandle, error) {
			template := []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
				pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			}
			if err := ctx.FindObjectsInit(session, template); err != nil {
				return 0, errors.WithStack(err)
			}
			defer func() {
				_ = ctx.FindObjectsFinal(session)
			}()
			handles, _, err := ctx.FindObjects(session, 2)
			if err != nil {
				return 0, errors.WithStack(err)
			}
			switch len(handles) {
			case 0:
				return 0, errors.WithStack(errKeyNotFound)
			case 1:
				return handles[0], nil
			default:
				return 0, errors.WithStack(errAmbiguousObject)
			}
		},
	}
}

// loggedOutErrors are results of an operation on a private object that a
// logged-out token also produces, since private objects are invisible and
// their handles invalid without a login: the session state decides whether
// a re-login is due (XPKI-110). C_Sign/C_Decrypt report a stale key handle
// as CKR_KEY_HANDLE_INVALID.
var loggedOutErrors = []pkcs11.Error{
	pkcs11.CKR_OBJECT_HANDLE_INVALID,
	pkcs11.CKR_KEY_HANDLE_INVALID,
}

// sessionPool bounds the sessions open on one slot. A session is either
// idle or borrowed; live counts both and never exceeds max.
type sessionPool struct {
	slot uint
	max  int
	ops  sessionOps

	mu     sync.Mutex
	cond   sync.Cond
	idle   []pkcs11.SessionHandle
	live   int
	closed bool
	// errs holds failures closing sessions returned after close
	errs []error
}

func newSessionPool(slot uint, maxSessions int, ops sessionOps) *sessionPool {
	p := &sessionPool{
		slot: slot,
		max:  maxSessions,
		ops:  ops,
	}
	p.cond.L = &p.mu
	return p
}

// get borrows an idle session, opens one while below max, or waits for a
// session to be returned. It fails once the pool is closed. reused reports
// whether the session was taken from the idle list rather than opened now.
func (p *sessionPool) get() (session pkcs11.SessionHandle, reused bool, err error) {
	p.mu.Lock()
	for {
		if p.closed {
			p.mu.Unlock()
			return 0, false, errors.WithStack(errClosed)
		}
		if n := len(p.idle); n > 0 {
			session = p.idle[n-1]
			p.idle = p.idle[:n-1]
			p.mu.Unlock()
			return session, true, nil
		}
		if p.live < p.max {
			break
		}
		p.cond.Wait()
	}
	p.live++
	p.mu.Unlock()

	session, err = p.ops.open(p.slot)
	if err != nil {
		p.mu.Lock()
		p.live--
		p.cond.Signal()
		p.mu.Unlock()
		return 0, false, errors.WithMessagef(err, "open session on slot %d", p.slot)
	}
	return session, false, nil
}

// purgeIdle closes every idle session. It is called when an idle session
// turned out to be stale: the handles of one slot are invalidated together
// (token removal, C_CloseAllSessions), so the other idle sessions are
// replaced too instead of failing the next operations one by one. Close
// errors are logged; a stale handle cannot be closed anyway.
func (p *sessionPool) purgeIdle() {
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	for _, session := range idle {
		if err := p.ops.close(session); err != nil {
			logger.KV(xlog.DEBUG, "reason", "close_stale_session", "slot", p.slot, "err", err)
		}
	}

	p.mu.Lock()
	p.live -= len(idle)
	p.cond.Broadcast()
	p.mu.Unlock()
}

// put returns a borrowed session. The session is closed instead when
// discard is set or the pool is closed; its capacity stays reserved until
// CloseSession returns, so a waiter never opens a replacement while it is
// still open. A failed close releases the capacity too, since the handle
// can not be closed again. A failure to close a session returned after
// close is kept for returnedErrs; otherwise it is logged.
func (p *sessionPool) put(session pkcs11.SessionHandle, discard bool) {
	p.mu.Lock()
	if !discard && !p.closed {
		p.idle = append(p.idle, session)
		p.cond.Signal()
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()

	err := p.ops.close(session)

	p.mu.Lock()
	p.live--
	p.cond.Signal()
	closed := p.closed
	if err != nil && closed {
		p.errs = append(p.errs, errors.WithMessagef(err, "close session on slot %d", p.slot))
	}
	p.mu.Unlock()

	if err != nil && !closed {
		logger.KV(xlog.WARNING, "reason", "close_session", "slot", p.slot, "err", err)
	}
}

// returnedErrs returns the failures to close sessions returned after close.
func (p *sessionPool) returnedErrs() []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.errs
}

// close fails waiting and later borrowers and closes the idle sessions.
// Borrowed sessions are closed when they are returned.
func (p *sessionPool) close() error {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.live -= len(idle)
	p.cond.Broadcast()
	p.mu.Unlock()

	var errs []error
	for _, session := range idle {
		if err := p.ops.close(session); err != nil {
			errs = append(errs, errors.WithMessagef(err, "close session on slot %d", p.slot))
		}
	}
	return errors.Join(errs...)
}

// sessionUnusable reports whether err leaves the session unfit for reuse.
func sessionUnusable(err error) bool {
	return isP11Error(err, unusableSessionErrors)
}

// isP11Error reports whether err wraps a PKCS#11 result in codes.
func isP11Error(err error, codes []pkcs11.Error) bool {
	if err == nil {
		return false
	}
	var p11err pkcs11.Error
	if !errors.As(err, &p11err) {
		return false
	}
	return slices.Contains(codes, p11err)
}

// NewSession opens a new RW session on slot. The caller owns the session
// and must close it with Ctx.CloseSession before Close is called.
func (lib *PKCS11Lib) NewSession(slot uint) (pkcs11.SessionHandle, error) {
	if err := lib.enter(); err != nil {
		return 0, err
	}
	defer lib.exit()

	session, err := lib.Ctx.OpenSession(slot, sessionFlags)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	return session, nil
}

// withSession runs f with a session borrowed from the pool of slot,
// creating the pool on first use. It waits while the slot already has
// maxSessions sessions borrowed, and fails once Close has been called.
//
// Two failures are recovered (XPKI-110), each at most once per call, so f
// runs at most three times: an idle session whose handle went stale
// (staleSessionErrors, as after a token was removed and reinserted) is
// replaced together with the other idle sessions and f runs again on a new
// session; and a logged-out login slot (the token was logged out or
// reinserted) triggers relogin and runs f again. The token is logged out
// when f fails with a login-sensitive error (loginSensitiveError:
// CKR_USER_NOT_LOGGED_IN, CKR_OBJECT_HANDLE_INVALID, CKR_KEY_HANDLE_INVALID
// or errKeyNotFound,
// since a private object is invisible and its handles invalid without a
// login) and the session state is a public one, or when another caller
// logged in again while f ran (the login generation advanced), in which
// case f is simply run again. Only the slot selected by Init is logged in;
// on another slot the error is returned. Any other error, and the error of
// the last attempt, is returned as is. f must therefore be safe to run
// again after such a failure, which leaves no PKCS#11 operation active; a
// callback that has already changed the token returns its error wrapped by
// noRetry, which withSession returns unwrapped without another run.
//
// f must not call withSession itself: a nested borrow can wait forever
// for a session held by its caller.
func (lib *PKCS11Lib) withSession(slot uint, f func(session pkcs11.SessionHandle) error) error {
	pool, err := lib.acquirePool(slot)
	if err != nil {
		return err
	}
	defer lib.exit()

	loginSlot := lib.isLoginSlot(slot)
	var retriedStale, retriedLogin bool
	for {
		gen := lib.loginGen.Load()
		reused, loggedOut, err := lib.runOnPooledSession(pool, loginSlot, f)
		// a re-login by another caller during f explains a login-sensitive
		// failure as well as a public session state does
		reloggedIn := loginSlot && lib.loginGen.Load() != gen && loginSensitiveError(err)
		var nr *noRetryError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &nr):
			// f changed the token before it failed; running it again would
			// repeat the change
			return nr.err
		case !retriedStale && reused && isP11Error(err, staleSessionErrors):
			retriedStale = true
			logger.KV(xlog.DEBUG, "reason", "stale_session", "slot", slot, "err", err)
			pool.purgeIdle()
		case !retriedLogin && (loggedOut || reloggedIn):
			retriedLogin = true
			logger.KV(xlog.DEBUG, "reason", "not_logged_in", "slot", slot, "err", err)
			// a no-op when the generation advanced meanwhile
			if rerr := lib.relogin(gen); rerr != nil {
				return errors.WithMessagef(rerr, "re-login after %v", err)
			}
		default:
			return err
		}
	}
}

// noRetryError marks a failure that withSession must not recover from by
// running the callback again: the callback already changed the token (a
// key pair was generated) and a second run would repeat that change. It is
// transparent for errors.Is/As and unwrapped before it is returned.
type noRetryError struct {
	err error
}

func (e *noRetryError) Error() string { return e.err.Error() }
func (e *noRetryError) Unwrap() error { return e.err }

// noRetry wraps err so that withSession returns it without a retry.
func noRetry(err error) error {
	if err == nil {
		return nil
	}
	return &noRetryError{err: err}
}

// unwrapNoRetry removes the noRetry marker from err.
func unwrapNoRetry(err error) error {
	var nr *noRetryError
	if errors.As(err, &nr) {
		return nr.err
	}
	return err
}

// loginSensitiveError reports whether err is one a logged-out token
// produces for an operation on a private object.
func loginSensitiveError(err error) bool {
	return isP11Error(err, []pkcs11.Error{pkcs11.CKR_USER_NOT_LOGGED_IN}) ||
		isP11Error(err, loggedOutErrors) || errors.Is(err, errKeyNotFound)
}

// isLoginSlot reports whether slot is the token Init selected and logged
// in to. Only that slot is logged in again; an operation on another
// login-protected slot fails as before.
func (lib *PKCS11Lib) isLoginSlot(slot uint) bool {
	return lib.loginRequired() && lib.Slot.id == slot
}

// runOnPooledSession borrows a session from pool, runs f and returns it.
// reused reports whether the session was idle before the call; loggedOut
// whether f failed because the login slot is logged out (never set when
// loginSlot is false).
func (lib *PKCS11Lib) runOnPooledSession(pool *sessionPool, loginSlot bool, f func(session pkcs11.SessionHandle) error) (reused, loggedOut bool, err error) {
	session, reused, err := pool.get()
	if err != nil {
		return reused, false, err
	}
	// a panic in f leaves discard set, so the session is not reused
	discard := true
	defer func() {
		pool.put(session, discard)
	}()
	err = f(session)
	discard = sessionUnusable(err)
	if err != nil && loginSlot {
		loggedOut = lib.sessionLoggedOut(session, err)
	}
	return reused, loggedOut, err
}

// sessionLoggedOut reports whether err, returned by an operation on
// session, means the token is logged out: for a loginSensitiveError the
// session state is asked, since a key with CKA_ALWAYS_AUTHENTICATE returns
// CKR_USER_NOT_LOGGED_IN on a logged-in token too, and a re-login would
// not help it.
func (lib *PKCS11Lib) sessionLoggedOut(session pkcs11.SessionHandle, err error) bool {
	if !loginSensitiveError(err) {
		return false
	}
	state, serr := lib.ops.state(session)
	if serr != nil {
		return false
	}
	return state == pkcs11.CKS_RO_PUBLIC_SESSION || state == pkcs11.CKS_RW_PUBLIC_SESSION
}

// loginRequired reports whether the selected token needs C_Login.
func (lib *PKCS11Lib) loginRequired() bool {
	return lib.Slot != nil && lib.Slot.flags&pkcs11.CKF_LOGIN_REQUIRED != 0
}

// relogin replaces the login session and logs in again after the token was
// logged out, for example when it was removed and reinserted. observed is
// the login generation the caller read before its operation; when it has
// advanced, another caller re-logged in meanwhile and nothing is done.
// Concurrent callers are serialized by loginMu, so one logout costs one
// C_Login. A PIN failure (stickyLoginErrors) is kept in loginErr and
// returned by every later call without touching the token, so a changed PIN
// cannot lock the token; a new Init is needed. Other failures are retried by
// the next operation. relogin runs inside an operation registered by
// acquirePool or enter, so Close waits for it and then closes the current
// login session.
func (lib *PKCS11Lib) relogin(observed uint64) error {
	lib.loginMu.Lock()
	defer lib.loginMu.Unlock()
	if lib.loginGen.Load() != observed {
		return nil
	}
	if lib.loginErr != nil {
		return lib.loginErr
	}
	lib.mu.Lock()
	closed := lib.closed
	lib.mu.Unlock()
	if closed {
		return errors.WithStack(errClosed)
	}

	slot := lib.Slot.id
	session, err := lib.ops.open(slot)
	if err != nil {
		return errors.WithMessagef(err, "open login session on slot %d", slot)
	}
	err = lib.ops.login(session, lib.Config.Pin())
	if err != nil && !errors.Is(err, pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN)) {
		if cerr := lib.ops.close(session); cerr != nil {
			logger.KV(xlog.DEBUG, "reason", "close_login_session", "slot", slot, "err", cerr)
		}
		err = errors.WithMessage(err, "login into PKCS#11 token")
		if isP11Error(err, stickyLoginErrors) {
			lib.loginErr = err
		}
		return err
	}

	// the old session is closed after the login so the slot never has zero
	// sessions, which would log the token out again on some modules
	old := lib.Session
	lib.Session = session
	lib.loginGen.Add(1)
	if old != 0 {
		if cerr := lib.ops.close(old); cerr != nil {
			logger.KV(xlog.DEBUG, "reason", "close_stale_login_session", "slot", slot, "err", cerr)
		}
	}
	logger.KV(xlog.INFO, "reason", "relogin", "slot", slot, "generation", lib.loginGen.Load())
	return nil
}

// acquirePool registers an operation and returns the pool for slot.
// The caller must call exit when it is done.
func (lib *PKCS11Lib) acquirePool(slot uint) (*sessionPool, error) {
	lib.mu.Lock()
	defer lib.mu.Unlock()
	if lib.closed {
		return nil, errors.WithStack(errClosed)
	}
	pool, ok := lib.pools[slot]
	if !ok {
		pool = newSessionPool(slot, lib.maxSessions, lib.ops)
		lib.pools[slot] = pool
	}
	lib.active++
	return pool, nil
}

// enter registers an operation that uses Ctx directly.
// The caller must call exit when it is done.
func (lib *PKCS11Lib) enter() error {
	lib.mu.Lock()
	defer lib.mu.Unlock()
	if lib.closed {
		return errors.WithStack(errClosed)
	}
	lib.active++
	return nil
}

// exit ends an operation registered by enter or acquirePool.
func (lib *PKCS11Lib) exit() {
	lib.mu.Lock()
	defer lib.mu.Unlock()
	lib.active--
	if lib.active == 0 && lib.closed {
		lib.drained.Broadcast()
	}
}
