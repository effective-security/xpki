package cryptoprov_test

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// valueProvider is a provider passed by value whose dynamic type is not
// comparable, so it can never be the same instance as another one.
type valueProvider struct {
	*namedProvider
	tags []string
}

// comparableValueProvider is a provider passed by value whose dynamic type is
// comparable.
type comparableValueProvider struct {
	*namedProvider
}

// assertIs checks err against target with both stdlib and cockroachdb Is.
func assertIs(t *testing.T, err, target error) {
	t.Helper()
	assert.True(t, stderrors.Is(err, target), "stdlib errors.Is(%v, %v)", err, target)
	assert.True(t, errors.Is(err, target), "cockroachdb errors.Is(%v, %v)", err, target)
}

func TestNew_Nil(t *testing.T) {
	t.Parallel()

	var typedNil *namedProvider
	for _, tc := range []struct {
		name string
		def  cryptoprov.Provider
	}{
		{name: "untyped", def: nil},
		{name: "typed", def: typedNil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp, err := cryptoprov.New(tc.def, nil)
			require.EqualError(t, err, "default provider is required: nil provider")
			assertIs(t, err, cryptoprov.ErrNilProvider)
			assert.Nil(t, cp)
		})
	}

	t.Run("nil entry", func(t *testing.T) {
		cp, err := cryptoprov.New(newNamedProvider("default", "m"),
			[]cryptoprov.Provider{newNamedProvider("a", "m"), typedNil})
		require.EqualError(t, err, "unable to add provider at index 1: unable to add provider: nil provider")
		assertIs(t, err, cryptoprov.ErrNilProvider)
		assert.Nil(t, cp)
	})
}

func TestNew_DefaultOnly(t *testing.T) {
	t.Parallel()

	def := newNamedProvider("default", "m")
	cp, err := cryptoprov.New(def, nil)
	require.NoError(t, err)
	assert.Same(t, def, cp.Default())

	got, err := cp.ByManufacturer("default", "m")
	require.NoError(t, err)
	assert.Same(t, def, got)

	_, err = cp.ByManufacturer("default", "other")
	assert.EqualError(t, err, `provider for "default" and model "other" not found`)
}

func TestCryptoAdd_Duplicates(t *testing.T) {
	t.Parallel()

	def := newNamedProvider("default", "m")
	a := newNamedProvider("a", "m")
	cp, err := cryptoprov.New(def, []cryptoprov.Provider{a})
	require.NoError(t, err)

	t.Run("same instance", func(t *testing.T) {
		require.NoError(t, cp.Add(a))
		require.NoError(t, cp.Add(a))
		require.NoError(t, cp.Add(def))
		require.NoError(t, cp.Add(def))
	})

	t.Run("other instance", func(t *testing.T) {
		err := cp.Add(newNamedProvider("a", "m"))
		require.EqualError(t, err, `manufacturer "a" and model "m": duplicate provider`)
		assertIs(t, err, cryptoprov.ErrDuplicateProvider)
	})

	t.Run("other instance of default", func(t *testing.T) {
		err := cp.Add(newNamedProvider("default", "m"))
		require.EqualError(t, err, `manufacturer "default" and model "m": duplicate provider`)
		assertIs(t, err, cryptoprov.ErrDuplicateProvider)
	})

	t.Run("same manufacturer other model", func(t *testing.T) {
		b := newNamedProvider("a", "other")
		require.NoError(t, cp.Add(b))
		got, err := cp.ByManufacturer("a", "other")
		require.NoError(t, err)
		assert.Same(t, b, got)
	})

	t.Run("key parts are not concatenated", func(t *testing.T) {
		// both were "x@y@z" in the old manufacturer + "@" + model key
		xy := newNamedProvider("x@y", "z")
		yz := newNamedProvider("x", "y@z")
		require.NoError(t, cp.Add(xy))
		require.NoError(t, cp.Add(yz))
		got, err := cp.ByManufacturer("x@y", "z")
		require.NoError(t, err)
		assert.Same(t, xy, got)
		got, err = cp.ByManufacturer("x", "y@z")
		require.NoError(t, err)
		assert.Same(t, yz, got)
	})

	t.Run("nil", func(t *testing.T) {
		var typedNil *namedProvider
		assertIs(t, cp.Add(nil), cryptoprov.ErrNilProvider)
		err := cp.Add(typedNil)
		require.EqualError(t, err, "unable to add provider: nil provider")
		assertIs(t, err, cryptoprov.ErrNilProvider)
	})

	// the originals are kept
	got, err := cp.ByManufacturer("a", "m")
	require.NoError(t, err)
	assert.Same(t, a, got)
	got, err = cp.ByManufacturer("default", "m")
	require.NoError(t, err)
	assert.Same(t, def, got)
}

func TestCryptoAdd_ValueProviders(t *testing.T) {
	t.Parallel()

	cp, err := cryptoprov.New(newNamedProvider("default", "m"), nil)
	require.NoError(t, err)

	// a comparable value equal to the registered one is the same provider
	cv := comparableValueProvider{namedProvider: newNamedProvider("cv", "m")}
	require.NoError(t, cp.Add(cv))
	require.NoError(t, cp.Add(cv))

	// a non-comparable value is never the same provider, and must not panic
	vp := valueProvider{namedProvider: newNamedProvider("vp", "m")}
	require.NoError(t, cp.Add(vp))
	assert.NotPanics(t, func() {
		err = cp.Add(vp)
	})
	assertIs(t, err, cryptoprov.ErrDuplicateProvider)
}

func TestCrypto_ZeroValue(t *testing.T) {
	t.Parallel()

	var cp cryptoprov.Crypto
	assert.Nil(t, cp.Default())

	_, err := cp.ByManufacturer("a", "m")
	assert.EqualError(t, err, `provider for "a" and model "m" not found`)

	a := newNamedProvider("a", "m")
	require.NoError(t, cp.Add(a))
	got, err := cp.ByManufacturer("a", "m")
	require.NoError(t, err)
	assert.Same(t, a, got)
}

const closerManufacturer = "cryptoprov-test-closer"

// closerProvider counts Close calls; Load must close what it loaded when it
// fails.
type closerProvider struct {
	*namedProvider
	closed *atomic.Int32
}

func (p *closerProvider) Close() error {
	p.closed.Add(1)
	return errors.New("close failed")
}

// registerCloserLoader registers a loader for closerManufacturer until the
// end of t and returns the count of closed providers.
func registerCloserLoader(t *testing.T) *atomic.Int32 {
	t.Helper()
	closed := &atomic.Int32{}
	require.NoError(t, cryptoprov.Register(closerManufacturer, func(tc cryptoprov.TokenConfig) (cryptoprov.Provider, error) {
		return &closerProvider{
			namedProvider: newNamedProvider(tc.Manufacturer(), tc.Model()),
			closed:        closed,
		}, nil
	}))
	t.Cleanup(func() {
		_, err := cryptoprov.Unregister(closerManufacturer)
		assert.NoError(t, err)
	})
	return closed
}

func writeTokenConfig(t *testing.T, manufacturer, model string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "token.yaml")
	body := "manufacturer: " + manufacturer + "\nmodel: " + model + "\n"
	require.NoError(t, os.WriteFile(cfg, []byte(body), 0600))
	return cfg
}

// The registry is process-global, so these tests do not run in parallel.
func TestLoad_ClosesOnError(t *testing.T) {
	closed := registerCloserLoader(t)
	cfgA := writeTokenConfig(t, closerManufacturer, "a")
	cfgB := writeTokenConfig(t, closerManufacturer, "b")

	t.Run("ok", func(t *testing.T) {
		closed.Store(0)
		cp, err := cryptoprov.Load(cfgA, []string{cfgB})
		require.NoError(t, err)
		assert.Equal(t, "a", cp.Default().Model())
		b, err := cp.ByManufacturer(closerManufacturer, "b")
		require.NoError(t, err)
		assert.Equal(t, "b", b.Model())
		assert.Zero(t, closed.Load())
	})

	t.Run("duplicate", func(t *testing.T) {
		closed.Store(0)
		cp, err := cryptoprov.Load(cfgA, []string{cfgB, cfgA})
		require.Error(t, err)
		assert.Equal(t, "unable to add provider from "+cfgA+`: manufacturer "`+closerManufacturer+`" and model "a": duplicate provider`, err.Error())
		assertIs(t, err, cryptoprov.ErrDuplicateProvider)
		assert.Nil(t, cp)
		assert.EqualValues(t, 3, closed.Load())
	})

	t.Run("missing config", func(t *testing.T) {
		closed.Store(0)
		cp, err := cryptoprov.Load(cfgA, []string{filepath.Join(t.TempDir(), "missing.yaml")})
		require.Error(t, err)
		assert.Nil(t, cp)
		assert.EqualValues(t, 1, closed.Load())
	})
}

func TestLoad_InmemDuplicate(t *testing.T) {
	// inmem_testprov.json names the same manufacturer and model as the
	// default "" config, but loads another instance
	cp, err := cryptoprov.Load("", []string{"testdata/inmem_testprov.json"})
	require.Error(t, err)
	assertIs(t, err, cryptoprov.ErrDuplicateProvider)
	assert.Nil(t, cp)
}

func TestLoadProvider_Registry(t *testing.T) {
	cfg := writeTokenConfig(t, closerManufacturer, "a")

	_, err := cryptoprov.LoadProvider(cfg)
	assert.EqualError(t, err, "provider not registered: "+closerManufacturer)

	registerCloserLoader(t)
	p, err := cryptoprov.LoadProvider(cfg)
	require.NoError(t, err)
	assert.Equal(t, closerManufacturer, p.Manufacturer())
	assert.Equal(t, "a", p.Model())

	err = cryptoprov.Register(closerManufacturer, nil)
	assert.EqualError(t, err, "already registered: "+closerManufacturer)
}
