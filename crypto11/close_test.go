package crypto11

import (
	"crypto/elliptic"
	"os"
	"path/filepath"
	"testing"

	pkcs11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Methods that take a caller session, and ExportKey, fail with errClosed
// after Close instead of dereferencing the nil Ctx.
func TestClose_SessionMethodsReturnErrClosed(t *testing.T) {
	t.Parallel()
	lib, _ := newFakeLib(1)
	// Init always sets the slot; ExportKey and EnumTokens(true) read it
	lib.Slot = &SlotTokenInfo{id: testSlot}
	require.NoError(t, lib.Close())
	const session = pkcs11.SessionHandle(1)

	calls := map[string]func() error{
		"ListKeys": func() error {
			_, err := lib.ListKeys(session, pkcs11.CKO_PRIVATE_KEY, ^uint(0))
			return err
		},
		"FindKeys": func() error {
			_, err := lib.FindKeys(session, "label", pkcs11.CKO_PRIVATE_KEY, ^uint(0))
			return err
		},
		"FindKeyPairOnSession": func() error {
			_, err := lib.FindKeyPairOnSession(session, testSlot, "id", "")
			return err
		},
		"GenerateRSAKeyPairOnSession": func() error {
			_, err := lib.GenerateRSAKeyPairOnSession(session, testSlot, nil, nil, 2048, Signing)
			return err
		},
		"GenerateECDSAKeyPairOnSession": func() error {
			_, err := lib.GenerateECDSAKeyPairOnSession(session, testSlot, nil, nil, elliptic.P256())
			return err
		},
		"ExportKey": func() error {
			_, _, err := lib.ExportKey("id")
			return err
		},
		"EnumTokens(current)": func() error {
			_, err := lib.EnumTokens(true)
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			var err error
			require.NotPanics(t, func() { err = call() })
			assert.ErrorIs(t, err, errClosed)
		})
	}
}

// A Close that starts once ExportKey is admitted waits for its lookup and
// token info read. Before the first fix Close finished and GetTokenInfo ran
// on the nil Ctx; before the second, the nested lookup returned errClosed.
// Not parallel: it sets the exportKeyAdmitted hook.
func TestExportKey_CloseWhileAdmitted(t *testing.T) {
	requireP11(t)
	priv, err := p11lib.GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)
	keyID := string(mustKeyID(t, priv))
	t.Cleanup(func() { _ = p11lib.DestroyKeyPairOnSlot(p11lib.Slot.id, keyID) })

	lib2, err := Init(loadTestConfig(t))
	require.NoError(t, err)

	closed := make(chan error, 1)
	exportKeyAdmitted = func() {
		go func() { closed <- lib2.Close() }()
		// give Close time to finish if it does not wait for ExportKey
		assertBlocked(t, closed)
	}
	t.Cleanup(func() { exportKeyAdmitted = func() {} })

	var uri string
	require.NotPanics(t, func() {
		uri, _, err = lib2.ExportKey(keyID)
	})
	require.NoError(t, err)
	assert.Contains(t, uri, "id="+keyID)
	require.NoError(t, waitErr(t, closed))

	_, _, err = lib2.ExportKey(keyID)
	assert.ErrorIs(t, err, errClosed)
}

// XPKI-001 review: a concurrent Close waits for the first one, and both
// report the failure to close a session that was borrowed during Close.
func TestClose_ConcurrentCallsShareResult(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(1)
	release := make(chan struct{})
	_, holder := holdSession(t, lib, testSlot, release)

	f.mu.Lock()
	f.closeErr = pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
	f.mu.Unlock()

	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- lib.Close() }()
	go func() { second <- lib.Close() }()
	assertBlocked(t, first)
	assertBlocked(t, second)

	close(release)
	require.NoError(t, waitErr(t, holder))
	err1 := waitErr(t, first)
	err2 := waitErr(t, second)
	require.ErrorIs(t, err1, pkcs11.Error(pkcs11.CKR_DEVICE_ERROR))
	assert.Equal(t, err1, err2)
	assert.Equal(t, err1, lib.Close())
}

// A failure closing a session returned after Close started is reported by
// Close, as for idle sessions; before the fix it was only logged.
func TestClose_ReportsReturnedSessionErrors(t *testing.T) {
	t.Parallel()
	lib, f := newFakeLib(1)
	release := make(chan struct{})
	held, holder := holdSession(t, lib, testSlot, release)

	closed := make(chan error, 1)
	go func() { closed <- lib.Close() }()
	assertBlocked(t, closed)

	f.mu.Lock()
	f.closeErr = pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
	f.mu.Unlock()
	close(release)
	require.NoError(t, waitErr(t, holder))

	err := waitErr(t, closed)
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_DEVICE_ERROR))
	assert.Contains(t, err.Error(), "close session on slot 7")
	f.mu.Lock()
	_, open := f.live[held]
	f.mu.Unlock()
	assert.False(t, open)
}

func TestModuleID(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "libtest.so")
	require.NoError(t, os.WriteFile(lib, []byte("lib"), 0o600))
	other := filepath.Join(dir, "libother.so")
	require.NoError(t, os.WriteFile(other, []byte("lib"), 0o600))
	link := filepath.Join(dir, "liblink.so")
	require.NoError(t, os.Symlink(lib, link))
	hard := filepath.Join(dir, "libhard.so")
	require.NoError(t, os.Link(lib, hard))
	missing := filepath.Join(dir, "libmissing.so")

	id := newModuleID(lib)
	assert.True(t, id.same(newModuleID(lib)))
	assert.True(t, id.same(newModuleID(link)), "symlink")
	assert.True(t, id.same(newModuleID(hard)), "hardlink")
	assert.True(t, id.same(newModuleID(filepath.Join(dir, ".", "libtest.so"))), "unclean path")
	assert.False(t, id.same(newModuleID(other)), "different file")
	assert.True(t, newModuleID(missing).same(newModuleID(missing)))
	assert.False(t, newModuleID(missing).same(id))

	// a bare name is resolved by the loader, not the working directory
	sub1 := filepath.Join(dir, "a")
	sub2 := filepath.Join(dir, "b")
	require.NoError(t, os.Mkdir(sub1, 0o700))
	require.NoError(t, os.Mkdir(sub2, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(sub1, "libtest.so"), []byte("a"), 0o600))
	t.Chdir(sub1)
	bare1 := newModuleID("libtest.so")
	t.Chdir(sub2)
	bare2 := newModuleID("libtest.so")
	assert.Nil(t, bare1.info)
	assert.True(t, bare1.same(bare2), "bare name from two directories")
	assert.False(t, bare1.same(id), "bare name is not matched to a path")
}

// A symlink to the loaded library shares its module.
func TestInit_SymlinkSharesModule(t *testing.T) {
	requireP11(t)
	cfg := loadTestConfig(t)
	link := filepath.Join(t.TempDir(), "libpkcs11.so")
	require.NoError(t, os.Symlink(cfg.Path(), link))
	refs := moduleRefs(cfg.Path())

	lib2, err := Init(&config{
		Dir:   link,
		Label: cfg.TokenLabel(),
		Pwd:   cfg.Pin(),
	})
	require.NoError(t, err)
	assert.Same(t, p11lib.Ctx, lib2.Ctx)
	assert.Equal(t, refs+1, moduleRefs(link))
	closeLib(t, lib2)
	assert.Equal(t, refs, moduleRefs(cfg.Path()))
}
