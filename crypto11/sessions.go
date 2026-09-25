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
// instead of being returned to its pool. The login session (PKCS11Lib.Session)
// is not reopened after a device or token error, so a reinserted token stays
// logged out until a new Init (XPKI-110).
var unusableSessionErrors = []pkcs11.Error{
	pkcs11.CKR_SESSION_HANDLE_INVALID,
	pkcs11.CKR_SESSION_CLOSED,
	pkcs11.CKR_OPERATION_ACTIVE,
	pkcs11.CKR_DEVICE_ERROR,
	pkcs11.CKR_DEVICE_REMOVED,
	pkcs11.CKR_TOKEN_NOT_PRESENT,
}

// sessionOps opens and closes sessions; tests replace it to exercise pools
// without a PKCS#11 module.
type sessionOps struct {
	open  func(slot uint) (pkcs11.SessionHandle, error)
	close func(session pkcs11.SessionHandle) error
}

func ctxSessionOps(ctx *pkcs11.Ctx) sessionOps {
	return sessionOps{
		open: func(slot uint) (pkcs11.SessionHandle, error) {
			return ctx.OpenSession(slot, sessionFlags)
		},
		close: ctx.CloseSession,
	}
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
// session to be returned. It fails once the pool is closed.
func (p *sessionPool) get() (pkcs11.SessionHandle, error) {
	p.mu.Lock()
	for {
		if p.closed {
			p.mu.Unlock()
			return 0, errors.WithStack(errClosed)
		}
		if n := len(p.idle); n > 0 {
			session := p.idle[n-1]
			p.idle = p.idle[:n-1]
			p.mu.Unlock()
			return session, nil
		}
		if p.live < p.max {
			break
		}
		p.cond.Wait()
	}
	p.live++
	p.mu.Unlock()

	session, err := p.ops.open(p.slot)
	if err != nil {
		p.mu.Lock()
		p.live--
		p.cond.Signal()
		p.mu.Unlock()
		return 0, errors.WithMessagef(err, "open session on slot %d", p.slot)
	}
	return session, nil
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
	if err == nil {
		return false
	}
	var p11err pkcs11.Error
	if !errors.As(err, &p11err) {
		return false
	}
	return slices.Contains(unusableSessionErrors, p11err)
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
// f must not call withSession itself: a nested borrow can wait forever
// for a session held by its caller.
func (lib *PKCS11Lib) withSession(slot uint, f func(session pkcs11.SessionHandle) error) error {
	pool, err := lib.acquirePool(slot)
	if err != nil {
		return err
	}
	defer lib.exit()

	session, err := pool.get()
	if err != nil {
		return err
	}
	// a panic in f leaves discard set, so the session is not reused
	discard := true
	defer func() {
		pool.put(session, discard)
	}()
	err = f(session)
	discard = sessionUnusable(err)
	return err
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
