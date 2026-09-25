package crypto11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	pkcs11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// moduleRefs returns the open references to the module at path.
func moduleRefs(path string) int {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	if m := findModule(newModuleID(path), loadedHandle(path)); m != nil {
		return m.refs
	}
	return 0
}

// badTokenConfig overrides the token selection of a valid config.
type badTokenConfig struct {
	TokenConfig
	label string
	pin   string
}

func (c *badTokenConfig) TokenLabel() string {
	if c.label != "" {
		return c.label
	}
	return c.TokenConfig.TokenLabel()
}

func (c *badTokenConfig) TokenSerial() string {
	if c.label != "" {
		return "no-such-serial"
	}
	return c.TokenConfig.TokenSerial()
}

func (c *badTokenConfig) Pin() string {
	if c.pin != "" {
		return c.pin
	}
	return c.TokenConfig.Pin()
}

func loadTestConfig(t *testing.T) TokenConfig {
	t.Helper()
	cfg, err := LoadTokenConfig(SoftHSMConfig)
	require.NoError(t, err)
	return cfg
}

// XPKI-001: wrappers on one path share the module; closing one releases
// only its own resources, and a closed wrapper returns errClosed.
func TestInit_SharedModule(t *testing.T) {
	requireP11(t)
	cfg := loadTestConfig(t)
	refs := moduleRefs(cfg.Path())
	require.GreaterOrEqual(t, refs, 1)

	lib2, err := Init(cfg)
	require.NoError(t, err)
	assert.Same(t, p11lib.Ctx, lib2.Ctx)
	assert.Equal(t, refs+1, moduleRefs(cfg.Path()))
	assert.NotZero(t, lib2.Session)

	// a new wrapper has no pools yet; the first operation creates one
	buf := make([]byte, benchRandomSize)
	n, err := lib2.GenRandom(buf)
	require.NoError(t, err)
	assert.Equal(t, benchRandomSize, n)

	priv, err := lib2.GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)
	keyID := string(mustKeyID(t, priv))
	t.Cleanup(func() { _ = p11lib.DestroyKeyPairOnSlot(p11lib.Slot.id, keyID) })
	digest := sha256.Sum256([]byte("shared module"))

	closeLib(t, lib2)
	assert.Equal(t, refs, moduleRefs(cfg.Path()))
	assert.Nil(t, lib2.Ctx)
	assert.Zero(t, lib2.Session)
	closeLib(t, lib2) // idempotent
	assert.Equal(t, refs, moduleRefs(cfg.Path()))

	// the remaining wrapper still works and the key is still on the token
	key, err := p11lib.FindKeyPair(keyID, "")
	require.NoError(t, err)
	sig, err := key.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(priv.Public().(*ecdsa.PublicKey), digest[:], sig))

	// every operation of the closed wrapper fails with errClosed
	slot := p11lib.Slot.id
	_, err = priv.Sign(rand.Reader, digest[:], crypto.SHA256)
	assert.ErrorIs(t, err, errClosed)
	_, err = lib2.GenRandom(buf)
	assert.ErrorIs(t, err, errClosed)
	_, err = lib2.TokensInfo()
	assert.ErrorIs(t, err, errClosed)
	_, err = lib2.EnumTokens(false)
	assert.ErrorIs(t, err, errClosed)
	_, err = lib2.EnumKeys(slot, "")
	assert.ErrorIs(t, err, errClosed)
	_, err = lib2.KeyInfo(slot, keyID, true)
	assert.ErrorIs(t, err, errClosed)
	_, err = lib2.FindKeyPair(keyID, "")
	assert.ErrorIs(t, err, errClosed)
	_, err = lib2.NewSession(slot)
	assert.ErrorIs(t, err, errClosed)
	assert.ErrorIs(t, lib2.DestroyKeyPairOnSlot(slot, keyID), errClosed)
}

// XPKI-001/005: Close closes every session the wrapper opened, including
// the login session; previously each Init/Close cycle leaked them.
func TestClose_ClosesAllSessions(t *testing.T) {
	requireP11(t)
	cfg := loadTestConfig(t)
	priv, err := p11lib.GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)
	keyID := string(mustKeyID(t, priv))
	t.Cleanup(func() { _ = p11lib.DestroyKeyPairOnSlot(p11lib.Slot.id, keyID) })
	digest := sha256.Sum256([]byte("close"))

	before := probeSessionHandle(t)
	lib2, err := Init(cfg, WithMaxSessions(4))
	require.NoError(t, err)
	key, err := lib2.FindKeyPair(keyID, "")
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 5 {
				_, err := key.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
				assert.NoError(t, err)
				_, err = lib2.GenRandom(make([]byte, benchRandomSize))
				assert.NoError(t, err)
			}
		})
	}
	wg.Wait()

	lib2.mu.Lock()
	pool := lib2.pools[lib2.Slot.id]
	lib2.mu.Unlock()
	pool.mu.Lock()
	live := pool.live
	pool.mu.Unlock()
	assert.LessOrEqual(t, live, 4)
	assert.Positive(t, live)

	mid := probeSessionHandle(t)
	// pooled sessions plus the login session
	assert.Equal(t, live+1, liveSessions(before, mid))

	closeLib(t, lib2)
	after := probeSessionHandle(t)
	assert.Equal(t, 0, liveSessions(before, after))
}

// XPKI-001: Close waits for a borrowed session on real SoftHSM and closes
// it once it is returned.
func TestClose_ActiveOperation(t *testing.T) {
	requireP11(t)
	lib2, err := Init(loadTestConfig(t))
	require.NoError(t, err)

	release := make(chan struct{})
	held, holder := holdSession(t, lib2, lib2.Slot.id, release)

	closed := make(chan error, 1)
	go func() { closed <- lib2.Close() }()
	assertBlocked(t, closed)

	_, err = lib2.GenRandom(make([]byte, benchRandomSize))
	require.ErrorIs(t, err, errClosed)
	_, err = p11lib.Ctx.GetSessionInfo(held)
	require.NoError(t, err, "the borrowed session stays open under its borrower")

	close(release)
	require.NoError(t, waitErr(t, holder))
	require.NoError(t, waitErr(t, closed))
	_, err = p11lib.Ctx.GetSessionInfo(held)
	assert.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_SESSION_HANDLE_INVALID))
}

// XPKI-007: a failed Init releases its module reference and sessions.
func TestInit_FailureReleases(t *testing.T) {
	requireP11(t)
	cfg := loadTestConfig(t)
	refs := moduleRefs(cfg.Path())

	const missing = "/nonexistent/libpkcs11.so"
	lib, err := Init(&config{Dir: missing})
	require.ErrorIs(t, err, errCannotOpenPKCS11)
	assert.Equal(t, "/nonexistent/libpkcs11.so: crypto11: could not open PKCS#11", err.Error())
	assert.Nil(t, lib)
	assert.Zero(t, moduleRefs(missing))

	before := probeSessionHandle(t)
	lib, err = Init(&badTokenConfig{TokenConfig: cfg, label: "no-such-token"})
	require.ErrorIs(t, err, errTokenNotFound)
	assert.Nil(t, lib)
	assert.Equal(t, refs, moduleRefs(cfg.Path()))

	lib, err = ConfigureFromFile("testdata/missing.json")
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Nil(t, lib)

	after := probeSessionHandle(t)
	assert.Equal(t, 0, liveSessions(before, after))

	// the live wrapper is unaffected
	_, err = p11lib.GenRandom(make([]byte, benchRandomSize))
	require.NoError(t, err)
}

// runChild re-executes the test binary to run name in a process where no
// module is loaded yet, so C_Initialize and C_Finalize can be observed.
func runChild(t *testing.T, name string, env ...string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+name+"$", "-test.count=1", "-test.v")
	cmd.Env = append(append(os.Environ(), childEnv+"=1"), env...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	require.Contains(t, string(out), "--- PASS: "+name)
}

func TestLifecycle_FreshProcess(t *testing.T) {
	requireP11(t)
	runChild(t, "TestLifecycleChild")
}

// assertFinalized proves nothing holds the library initialized: a fresh
// C_Initialize succeeds instead of returning CKR_CRYPTOKI_ALREADY_INITIALIZED.
func assertFinalized(t *testing.T, path string) {
	t.Helper()
	modulesMu.Lock()
	assert.Empty(t, modules)
	modulesMu.Unlock()

	ctx := pkcs11.New(path)
	require.NotNil(t, ctx)
	defer ctx.Destroy()
	require.NoError(t, ctx.Initialize())
	require.NoError(t, ctx.Finalize())
}

// TestLifecycleChild runs only inside runChild.
func TestLifecycleChild(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		t.Skip("runs in a child process started by TestLifecycle_FreshProcess")
	}
	cfg := loadTestConfig(t)
	path := cfg.Path()
	assertFinalized(t, path)

	// XPKI-007: every failure after the module is loaded unwinds it
	_, err := Init(&badTokenConfig{TokenConfig: cfg, label: "no-such-token"})
	require.ErrorIs(t, err, errTokenNotFound)
	assertFinalized(t, path)

	_, err = Init(&badTokenConfig{TokenConfig: cfg, pin: "wrong-pin"})
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_PIN_INCORRECT))
	assert.Contains(t, err.Error(), "login into PKCS#11 token")
	assertFinalized(t, path)

	// a retry after the failures succeeds; two wrappers share the module
	lib1, err := Init(cfg)
	require.NoError(t, err)
	lib2, err := Init(cfg)
	require.NoError(t, err)
	assert.Same(t, lib1.Ctx, lib2.Ctx)
	assert.Equal(t, 2, moduleRefs(path))

	priv, err := lib1.GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)
	keyID := string(mustKeyIDOn(t, lib1, priv))
	key, err := lib2.FindKeyPair(keyID, "")
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("child"))

	// XPKI-001: closing one wrapper leaves the other working and logged in
	closeLib(t, lib1)
	assert.Equal(t, 1, moduleRefs(path))
	sig, err := key.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(priv.Public().(*ecdsa.PublicKey), digest[:], sig))
	require.NoError(t, lib2.DestroyKeyPairOnSlot(lib2.Slot.id, keyID))

	// the last Close finalizes and unloads the module
	closeLib(t, lib2)
	assertFinalized(t, path)

	// and the module can be initialized again
	lib3, err := Init(cfg)
	require.NoError(t, err)
	_, err = lib3.GenRandom(make([]byte, benchRandomSize))
	require.NoError(t, err)
	closeLib(t, lib3)
	assertFinalized(t, path)
}

// An externally initialized module is shared but never finalized here.
func TestLifecycleChild_ExternalInit(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		t.Skip("runs in a child process started by TestLifecycle_ExternalInit")
	}
	cfg := loadTestConfig(t)
	ext := pkcs11.New(cfg.Path())
	require.NotNil(t, ext)
	require.NoError(t, ext.Initialize())

	lib, err := Init(cfg)
	require.NoError(t, err)
	modulesMu.Lock()
	finalize := findModule(newModuleID(cfg.Path()), loadedHandle(cfg.Path())).finalize
	modulesMu.Unlock()
	assert.False(t, finalize)
	closeLib(t, lib)

	// the external owner is still initialized and finalizes it itself
	err = ext.Initialize()
	assert.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED))
	require.NoError(t, ext.Finalize())
	ext.Destroy()
	assertFinalized(t, cfg.Path())
}

func TestLifecycle_ExternalInit(t *testing.T) {
	requireP11(t)
	runChild(t, "TestLifecycleChild_ExternalInit")
}

func mustKeyIDOn(tb testing.TB, lib *PKCS11Lib, priv *PKCS11PrivateKeyECDSA) []byte {
	tb.Helper()
	id, _, err := lib.Identify(&priv.key.PKCS11Object)
	require.NoError(tb, err)
	return []byte(id)
}

// A bare library name and a path to the same library share one module, so
// closing the wrapper opened by path does not finalize under the other.
// The child finds the bare name through the loader search path.
func TestLifecycle_BareNameAlias(t *testing.T) {
	requireP11(t)
	dir := filepath.Dir(loadTestConfig(t).Path())
	runChild(t, "TestLifecycleChild_BareNameAlias",
		"LD_LIBRARY_PATH="+dir, "DYLD_LIBRARY_PATH="+dir)
}

func TestLifecycleChild_BareNameAlias(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		t.Skip("runs in a child process started by TestLifecycle_BareNameAlias")
	}
	cfg := loadTestConfig(t)
	bare := &config{
		Dir:   filepath.Base(cfg.Path()),
		Label: cfg.TokenLabel(),
		Pwd:   cfg.Pin(),
	}

	byPath, err := Init(cfg)
	require.NoError(t, err)
	byName, err := Init(bare)
	require.NoError(t, err)
	assert.Same(t, byPath.Ctx, byName.Ctx)
	assert.Equal(t, 2, moduleRefs(cfg.Path()))

	closeLib(t, byPath)
	_, err = byName.GenRandom(make([]byte, benchRandomSize))
	require.NoError(t, err, "the module was finalized under the bare-name wrapper")
	closeLib(t, byName)
	assertFinalized(t, cfg.Path())
}
