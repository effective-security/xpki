package crypto11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"sync"
	"testing"

	pkcs11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// XPKI-110 on SoftHSM: the token's login state is shared by every session of
// the process, so C_Logout on one PKCS11Lib logs the whole process out, and
// C_CloseAllSessions invalidates every session on the slot the way a token
// removal does. Before the fix an operation failed with
// CKR_USER_NOT_LOGGED_IN (or CKR_SESSION_HANDLE_INVALID) until a new Init.

// newReloginLib opens a second PKCS11Lib on the test token, closed at cleanup.
func newReloginLib(t *testing.T, opts ...Option) *PKCS11Lib {
	t.Helper()
	lib, err := Init(loadTestConfig(t), opts...)
	require.NoError(t, err)
	t.Cleanup(func() { closeLib(t, lib) })
	return lib
}

// genReloginKey generates an ECDSA key on lib, destroyed at cleanup.
func genReloginKey(t *testing.T, lib *PKCS11Lib) (*PKCS11PrivateKeyECDSA, string) {
	t.Helper()
	priv, err := lib.GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)
	keyID := string(mustKeyIDOn(t, lib, priv))
	t.Cleanup(func() { assert.NoError(t, lib.DestroyKeyPairOnSlot(lib.Slot.id, keyID)) })
	return priv, keyID
}

func signAndVerify(t *testing.T, priv *PKCS11PrivateKeyECDSA, msg string) error {
	t.Helper()
	digest := sha256.Sum256([]byte(msg))
	sig, err := priv.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	assert.True(t, ecdsa.VerifyASN1(priv.Public().(*ecdsa.PublicKey), digest[:], sig))
	return nil
}

func sessionState(t *testing.T, lib *PKCS11Lib, session pkcs11.SessionHandle) uint {
	t.Helper()
	info, err := lib.Ctx.GetSessionInfo(session)
	require.NoError(t, err)
	return info.State
}

// A private-key operation after a logout logs the token in again and
// succeeds; the login session is replaced by a logged-in one.
func TestRelogin_AfterLogout(t *testing.T) {
	requireP11(t)
	lib := newReloginLib(t)
	priv, _ := genReloginKey(t, lib)
	require.NoError(t, signAndVerify(t, priv, "before logout"))

	loginSession := lib.Session
	require.NoError(t, lib.Ctx.Logout(loginSession))
	assert.Equal(t, uint(pkcs11.CKS_RW_PUBLIC_SESSION), sessionState(t, lib, loginSession))

	require.NoError(t, signAndVerify(t, priv, "after logout"))
	require.NoError(t, signAndVerify(t, priv, "after re-login"))
	assert.Equal(t, uint(pkcs11.CKS_RW_USER_FUNCTIONS), sessionState(t, lib, lib.Session))
}

// EnumKeys lists private keys only when logged in; after a logout it logs
// in again instead of returning an empty list without an error.
func TestRelogin_EnumKeysAfterLogout(t *testing.T) {
	requireP11(t)
	lib := newReloginLib(t)
	_, keyID := genReloginKey(t, lib)

	require.NoError(t, lib.Ctx.Logout(lib.Session))

	keys, err := lib.EnumKeys(lib.Slot.id, "")
	require.NoError(t, err)
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	assert.Contains(t, ids, keyID)
}

// Concurrent operations after a logout all succeed with a single re-login.
func TestRelogin_ConcurrentSingleLogin(t *testing.T) {
	requireP11(t)
	lib := newReloginLib(t)
	priv, _ := genReloginKey(t, lib)
	require.NoError(t, lib.Ctx.Logout(lib.Session))

	const workers = 8
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- signAndVerify(t, priv, "concurrent")
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, uint64(1), lib.loginGen.Load())
}

// A re-login with a wrong PIN fails once and is not tried again by that
// PKCS11Lib, so a changed PIN cannot lock the token; a new Init recovers.
func TestRelogin_WrongPINIsSticky(t *testing.T) {
	requireP11(t)
	cfg := loadTestConfig(t)
	lib := newReloginLib(t)
	priv, keyID := genReloginKey(t, lib)

	lib.Config = &badTokenConfig{TokenConfig: cfg, pin: "not-the-pin"}
	logins := 0
	login := lib.ops.login
	lib.ops.login = func(session pkcs11.SessionHandle, pin string) error {
		logins++
		return login(session, pin)
	}
	require.NoError(t, lib.Ctx.Logout(lib.Session))

	err := signAndVerify(t, priv, "wrong pin")
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_PIN_INCORRECT))
	assert.ErrorContains(t, err, "re-login after ")
	assert.ErrorContains(t, err, "login into PKCS#11 token")
	err = signAndVerify(t, priv, "wrong pin again")
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_PIN_INCORRECT))
	assert.Equal(t, 1, logins, "a PIN failure must not be retried")

	// a new PKCS11Lib on the token logs in with the right PIN; the login
	// state is shared by the process, so the first one works again too
	lib.Config = cfg
	lib2 := newReloginLib(t)
	key, err := lib2.FindKeyPair(keyID, "")
	require.NoError(t, err)
	require.NoError(t, signAndVerify(t, key.(*PKCS11PrivateKeyECDSA), "new lib"))
	require.NoError(t, signAndVerify(t, priv, "first lib after the other logged in"))
}

// TestRelogin_CloseAllSessions runs the reinsertion scenario in a child
// process, since C_CloseAllSessions invalidates the sessions of every
// PKCS11Lib in the process, including the shared p11lib.
func TestRelogin_CloseAllSessions(t *testing.T) {
	requireP11(t)
	runChild(t, "TestReloginChild_CloseAllSessions")
}

// TestReloginChild_CloseAllSessions runs only inside runChild. After every
// session on the slot is closed (as when a token is removed and reinserted)
// the idle pooled session is stale and the token is logged out; the very
// next operation succeeds, and Close leaves no session behind.
func TestReloginChild_CloseAllSessions(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		t.Skip("runs in a child process started by TestRelogin_CloseAllSessions")
	}
	cfg := loadTestConfig(t)
	lib, err := Init(cfg, WithMaxSessions(4))
	require.NoError(t, err)
	priv, err := lib.GenerateECDSAKeyPair(elliptic.P256())
	require.NoError(t, err)
	keyID := string(mustKeyIDOn(t, lib, priv))
	require.NoError(t, signAndVerify(t, priv, "before"))
	// the pool of the slot now holds an idle session
	require.Len(t, lib.pools[lib.Slot.id].idle, 1)

	require.NoError(t, lib.Ctx.CloseAllSessions(lib.Slot.id))

	require.NoError(t, signAndVerify(t, priv, "after reinsertion"))
	assert.Equal(t, uint(pkcs11.CKS_RW_USER_FUNCTIONS), sessionState(t, lib, lib.Session))
	keys, err := lib.EnumKeys(lib.Slot.id, "")
	require.NoError(t, err)
	found := false
	for _, k := range keys {
		found = found || k.ID == keyID
	}
	assert.True(t, found, "private key must be listed after re-login")

	require.NoError(t, lib.DestroyKeyPairOnSlot(lib.Slot.id, keyID))
	require.NoError(t, lib.Close())
}
