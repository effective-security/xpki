package crypto11

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	pkcs11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSlot = uint(7)
	// testDeadline bounds every wait so a regression fails instead of hanging.
	testDeadline = 5 * time.Second
	// testBlocked is how long a blocked call must stay blocked.
	testBlocked = 100 * time.Millisecond
)

// fakeSessions implements sessionOps without a PKCS#11 module and records
// the sessions it opened and closed.
type fakeSessions struct {
	mu       sync.Mutex
	next     pkcs11.SessionHandle
	live     map[pkcs11.SessionHandle]uint
	opened   int
	closed   int
	maxLive  int
	openErr  error
	closeErr error
	// closeGate, when set, blocks close until it is closed; closing is
	// signalled when a close starts
	closeGate chan struct{}
	closing   chan struct{}
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{
		live: map[pkcs11.SessionHandle]uint{},
	}
}

func (f *fakeSessions) ops() sessionOps {
	return sessionOps{
		open: func(slot uint) (pkcs11.SessionHandle, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.openErr != nil {
				return 0, f.openErr
			}
			f.next++
			f.opened++
			f.live[f.next] = slot
			f.maxLive = max(f.maxLive, len(f.live))
			return f.next, nil
		},
		close: func(session pkcs11.SessionHandle) error {
			f.mu.Lock()
			gate, closing := f.closeGate, f.closing
			f.mu.Unlock()
			if gate != nil {
				closing <- struct{}{}
				<-gate
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.live[session]; !ok {
				return errors.Errorf("session %d is not open", session)
			}
			delete(f.live, session)
			f.closed++
			return f.closeErr
		},
	}
}

func (f *fakeSessions) counts() (opened, closed, live, maxLive int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opened, f.closed, len(f.live), f.maxLive
}

func (f *fakeSessions) setOpenErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openErr = err
}

func newFakeLib(maxSessions int) (*PKCS11Lib, *fakeSessions) {
	f := newFakeSessions()
	return newPKCS11Lib(nil, nil, maxSessions, f.ops()), f
}

// holdSession borrows a session on slot until release is closed. It returns
// once the session is borrowed, and done receives the withSession result.
func holdSession(t *testing.T, lib *PKCS11Lib, slot uint, release <-chan struct{}) (pkcs11.SessionHandle, <-chan error) {
	t.Helper()
	borrowed := make(chan pkcs11.SessionHandle, 1)
	done := make(chan error, 1)
	go func() {
		done <- lib.withSession(slot, func(session pkcs11.SessionHandle) error {
			borrowed <- session
			<-release
			return nil
		})
	}()
	select {
	case s := <-borrowed:
		return s, done
	case err := <-done:
		require.FailNow(t, "withSession returned before borrowing", "%v", err)
	case <-time.After(testDeadline):
		require.FailNow(t, "withSession did not borrow a session")
	}
	return 0, nil
}

func waitErr(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(testDeadline):
		require.FailNow(t, "call did not return")
		return nil
	}
}

func assertBlocked(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		require.FailNow(t, "call returned while it should wait", "%v", err)
	case <-time.After(testBlocked):
	}
}

func TestWithSession_ReusesIdle(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(DefaultMaxSessions)

	var first, second pkcs11.SessionHandle
	require.NoError(t, lib.withSession(testSlot, func(s pkcs11.SessionHandle) error {
		first = s
		return nil
	}))
	require.NoError(t, lib.withSession(testSlot, func(s pkcs11.SessionHandle) error {
		second = s
		return nil
	}))
	assert.Equal(t, first, second)
	opened, closed, live, _ := f.counts()
	assert.Equal(t, 1, opened)
	assert.Equal(t, 0, closed)
	assert.Equal(t, 1, live)

	require.NoError(t, lib.Close())
	opened, closed, live, _ = f.counts()
	assert.Equal(t, 1, opened)
	assert.Equal(t, 1, closed)
	assert.Equal(t, 0, live)
}

// XPKI-003: a slot without a pool used to block forever returning the
// session to a nil channel; pools are now created on first use.
func TestWithSession_PoolCreatedOnFirstUse(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(DefaultMaxSessions)

	done := make(chan error, 1)
	go func() {
		done <- lib.withSession(testSlot+1, func(pkcs11.SessionHandle) error { return nil })
	}()
	require.NoError(t, waitErr(t, done))

	lib.mu.Lock()
	pool := lib.pools[testSlot+1]
	lib.mu.Unlock()
	require.NotNil(t, pool)
	assert.Equal(t, DefaultMaxSessions, pool.max)
	_, _, live, _ := f.counts()
	assert.Equal(t, 1, live)
	require.NoError(t, lib.Close())
}

// XPKI-005: live sessions are bounded; a borrower waits for a returned
// session instead of opening more, and a return never blocks.
func TestWithSession_Bounded(t *testing.T) {
	t.Parallel()
	const maxSessions = 2
	lib, f := newFakeLib(maxSessions)

	release := make(chan struct{})
	s1, done1 := holdSession(t, lib, testSlot, release)
	s2, done2 := holdSession(t, lib, testSlot, release)
	assert.NotEqual(t, s1, s2)

	waiter := make(chan error, 1)
	var got pkcs11.SessionHandle
	go func() {
		waiter <- lib.withSession(testSlot, func(s pkcs11.SessionHandle) error {
			got = s
			return nil
		})
	}()
	assertBlocked(t, waiter)
	opened, _, _, _ := f.counts()
	assert.Equal(t, maxSessions, opened)

	close(release)
	require.NoError(t, waitErr(t, done1))
	require.NoError(t, waitErr(t, done2))
	require.NoError(t, waitErr(t, waiter))
	assert.Contains(t, []pkcs11.SessionHandle{s1, s2}, got)

	opened, closed, live, maxLive := f.counts()
	assert.Equal(t, maxSessions, opened)
	assert.Equal(t, 0, closed)
	assert.Equal(t, maxSessions, live)
	assert.Equal(t, maxSessions, maxLive)
	require.NoError(t, lib.Close())
}

func TestWithSession_Contention(t *testing.T) {
	t.Parallel()
	const (
		maxSessions = 3
		workers     = 32
		iterations  = 50
	)
	lib, f := newFakeLib(maxSessions)

	var inUse, peak atomic.Int32
	var wg sync.WaitGroup
	done := make(chan error, workers)
	for range workers {
		wg.Go(func() {
			for range iterations {
				err := lib.withSession(testSlot, func(pkcs11.SessionHandle) error {
					n := inUse.Add(1)
					for {
						p := peak.Load()
						if n <= p || peak.CompareAndSwap(p, n) {
							break
						}
					}
					inUse.Add(-1)
					return nil
				})
				if err != nil {
					done <- err
					return
				}
			}
		})
	}
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(testDeadline):
		require.FailNow(t, "borrowers did not complete")
	}
	close(done)
	for err := range done {
		require.NoError(t, err)
	}

	opened, closed, live, maxLive := f.counts()
	assert.LessOrEqual(t, int(peak.Load()), maxSessions)
	assert.LessOrEqual(t, maxLive, maxSessions)
	assert.Equal(t, opened, live)
	assert.Equal(t, 0, closed)
	require.NoError(t, lib.Close())
	_, _, live, _ = f.counts()
	assert.Equal(t, 0, live)
}

func TestWithSession_Disposal(t *testing.T) {
	t.Parallel()
	errPlain := errors.New("plain failure")
	type disposalCase struct {
		name    string
		err     error
		discard bool
	}
	tcs := []disposalCase{
		{name: "success", err: nil},
		{name: "plain error", err: errPlain},
		{name: "key handle invalid", err: pkcs11.Error(pkcs11.CKR_KEY_HANDLE_INVALID)},
		{name: "wrapped operation active", err: errors.WithStack(pkcs11.Error(pkcs11.CKR_OPERATION_ACTIVE)), discard: true},
	}
	for _, code := range unusableSessionErrors {
		tcs = append(tcs, disposalCase{
			name:    code.Error(),
			err:     errors.WithMessage(code, "op"),
			discard: true,
		})
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lib, f := newFakeLib(1)

			err := lib.withSession(testSlot, func(pkcs11.SessionHandle) error { return tc.err })
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				assert.Equal(t, tc.err, err)
			}
			assert.Equal(t, tc.discard, sessionUnusable(err))

			opened, closed, live, _ := f.counts()
			assert.Equal(t, 1, opened)
			if tc.discard {
				assert.Equal(t, 1, closed)
				assert.Equal(t, 0, live)
			} else {
				assert.Equal(t, 0, closed)
				assert.Equal(t, 1, live)
			}

			// the pool of one still serves the next borrower
			require.NoError(t, lib.withSession(testSlot, func(pkcs11.SessionHandle) error { return nil }))
			require.NoError(t, lib.Close())
			_, _, live, _ = f.counts()
			assert.Equal(t, 0, live)
		})
	}
}

// A discarded session keeps its capacity until CloseSession returns, so a
// waiter does not open a replacement while it is still open.
func TestWithSession_DiscardHoldsCapacity(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(1)
	gate := make(chan struct{})
	f.mu.Lock()
	f.closeGate = gate
	f.closing = make(chan struct{}, 1)
	f.mu.Unlock()

	failed := make(chan error, 1)
	go func() {
		failed <- lib.withSession(testSlot, func(pkcs11.SessionHandle) error {
			return pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID)
		})
	}()
	select {
	case <-f.closing:
	case <-time.After(testDeadline):
		require.FailNow(t, "discarded session was not closed")
	}

	waiter := make(chan error, 1)
	go func() {
		waiter <- lib.withSession(testSlot, func(pkcs11.SessionHandle) error { return nil })
	}()
	assertBlocked(t, waiter)
	opened, _, _, _ := f.counts()
	assert.Equal(t, 1, opened)

	f.mu.Lock()
	f.closeGate = nil
	f.mu.Unlock()
	close(gate)
	require.ErrorIs(t, waitErr(t, failed), pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID))
	require.NoError(t, waitErr(t, waiter))

	opened, closed, live, maxLive := f.counts()
	assert.Equal(t, 2, opened)
	assert.Equal(t, 1, closed)
	assert.Equal(t, 1, live)
	assert.Equal(t, 1, maxLive)
	require.NoError(t, lib.Close())
}

func TestWithSession_PanicDiscards(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(1)

	assert.PanicsWithValue(t, "boom", func() {
		_ = lib.withSession(testSlot, func(pkcs11.SessionHandle) error { panic("boom") })
	})
	opened, closed, live, _ := f.counts()
	assert.Equal(t, 1, opened)
	assert.Equal(t, 1, closed)
	assert.Equal(t, 0, live)

	done := make(chan error, 1)
	go func() {
		done <- lib.withSession(testSlot, func(pkcs11.SessionHandle) error { return nil })
	}()
	require.NoError(t, waitErr(t, done))
	require.NoError(t, lib.Close())
}

func TestWithSession_OpenErrorReleasesSlot(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(1)
	errOpen := pkcs11.Error(pkcs11.CKR_SESSION_COUNT)
	f.setOpenErr(errOpen)

	called := false
	err := lib.withSession(testSlot, func(pkcs11.SessionHandle) error {
		called = true
		return nil
	})
	require.ErrorIs(t, err, errOpen)
	assert.Contains(t, err.Error(), "open session on slot 7")
	assert.False(t, called)

	f.setOpenErr(nil)
	done := make(chan error, 1)
	go func() {
		done <- lib.withSession(testSlot, func(pkcs11.SessionHandle) error { return nil })
	}()
	require.NoError(t, waitErr(t, done))
	require.NoError(t, lib.Close())
}

// XPKI-001: Close fails new and queued borrowers, waits for borrowed
// sessions, and closes every session exactly once.
func TestClose_WaitsForBorrowed(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(1)

	release := make(chan struct{})
	held, holder := holdSession(t, lib, testSlot, release)

	waiter := make(chan error, 1)
	go func() {
		waiter <- lib.withSession(testSlot, func(pkcs11.SessionHandle) error { return nil })
	}()
	assertBlocked(t, waiter)

	closed := make(chan error, 1)
	go func() { closed <- lib.Close() }()

	require.ErrorIs(t, waitErr(t, waiter), errClosed)
	assertBlocked(t, closed)

	err := lib.withSession(testSlot, func(pkcs11.SessionHandle) error { return nil })
	require.ErrorIs(t, err, errClosed)
	assert.Equal(t, "crypto11: PKCS#11 library is closed", err.Error())
	_, err = lib.NewSession(testSlot)
	require.ErrorIs(t, err, errClosed)
	_, err = lib.TokensInfo()
	require.ErrorIs(t, err, errClosed)

	f.mu.Lock()
	_, stillOpen := f.live[held]
	f.mu.Unlock()
	assert.True(t, stillOpen, "a borrowed session is not closed under its borrower")

	close(release)
	require.NoError(t, waitErr(t, holder))
	require.NoError(t, waitErr(t, closed))

	opened, closedCount, live, _ := f.counts()
	assert.Equal(t, 1, opened)
	assert.Equal(t, 1, closedCount)
	assert.Equal(t, 0, live)

	// idempotent
	require.NoError(t, lib.Close())
	_, closedCount, _, _ = f.counts()
	assert.Equal(t, 1, closedCount)
}

func TestClose_ReportsSessionErrors(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(2)
	release := make(chan struct{})
	_, done1 := holdSession(t, lib, testSlot, release)
	_, done2 := holdSession(t, lib, testSlot+1, release)
	close(release)
	require.NoError(t, waitErr(t, done1))
	require.NoError(t, waitErr(t, done2))

	f.mu.Lock()
	f.closeErr = pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
	f.mu.Unlock()

	err := lib.Close()
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_DEVICE_ERROR))
	assert.Contains(t, err.Error(), "close session on slot 7")
	assert.Contains(t, err.Error(), "close session on slot 8")
	_, closed, live, _ := f.counts()
	assert.Equal(t, 2, closed)
	assert.Equal(t, 0, live)
	// every later Close returns the first result
	assert.Equal(t, err, lib.Close())
}

// XPKI-002: pools are created and looked up under the lock; run with -race.
func TestWithSession_ConcurrentPoolsAndClose(t *testing.T) {
	t.Parallel()
	const (
		slots   = 8
		workers = 8
	)
	lib, f := newFakeLib(2)

	start := make(chan struct{})
	var wg sync.WaitGroup
	var succeeded, rejected atomic.Int32
	for slot := range uint(slots) {
		for range workers {
			wg.Go(func() {
				<-start
				err := lib.withSession(slot, func(pkcs11.SessionHandle) error { return nil })
				switch {
				case err == nil:
					succeeded.Add(1)
				case errors.Is(err, errClosed):
					rejected.Add(1)
				default:
					t.Errorf("slot %d: %v", slot, err)
				}
			})
		}
	}
	wg.Go(func() {
		<-start
		assert.NoError(t, lib.Close())
	})
	close(start)
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(testDeadline):
		require.FailNow(t, "borrowers did not complete")
	}

	assert.Equal(t, int32(slots*workers), succeeded.Load()+rejected.Load())
	opened, closed, live, _ := f.counts()
	assert.Equal(t, opened, closed)
	assert.Equal(t, 0, live)
}

func TestInit_InvalidMaxSessions(t *testing.T) {
	t.Parallel()
	lib, err := Init(&config{Dir: "/nonexistent/libpkcs11.so"}, nil)
	require.Error(t, err)
	assert.Equal(t, "crypto11: nil option", err.Error())
	assert.Nil(t, lib)

	for _, n := range []int{0, -1} {
		lib, err := Init(&config{Dir: "/nonexistent/libpkcs11.so"}, WithMaxSessions(n))
		require.Error(t, err)
		assert.Equal(t, "crypto11: invalid max sessions: "+strconv.Itoa(n), err.Error())
		assert.Nil(t, lib)
	}
}
