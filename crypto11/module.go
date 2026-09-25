package crypto11

import (
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/cockroachdb/errors"
	pkcs11 "github.com/miekg/pkcs11"
)

// module is a loaded PKCS#11 library shared by every PKCS11Lib opened
// on the same library file. C_Initialize and C_Finalize are process-wide,
// so the module is initialized by the first reference and finalized by the
// last.
type module struct {
	id moduleID
	// handle is the dynamic loader's handle (loadedHandle), or 0
	handle uintptr
	ctx    *pkcs11.Ctx
	refs   int
	// finalize is false when the library was already initialized by
	// code outside this package, which then owns C_Finalize.
	finalize bool
}

// moduleID identifies a library file where the loader handle is not
// available (non-unix). A path with a directory is matched by file identity
// (os.SameFile), so symlinks and hardlinks to one library share a module. A
// bare name such as "libsofthsm2.so" is resolved by the dynamic loader's
// search path, not the working directory, and is matched by name only. On
// unix modules are matched by loader handle, which also unifies a bare name
// with a path to the same library.
type moduleID struct {
	path string
	info os.FileInfo
}

func newModuleID(path string) moduleID {
	id := moduleID{
		path: path,
	}
	if filepath.Base(path) != path {
		if info, err := os.Stat(path); err == nil {
			id.info = info
		}
	}
	return id
}

func (id moduleID) same(other moduleID) bool {
	if id.info != nil && other.info != nil {
		return os.SameFile(id.info, other.info)
	}
	return id.info == nil && other.info == nil && id.path == other.path
}

var (
	// modulesMu protects modules and module.refs.
	modulesMu sync.Mutex
	modules   []*module
)

// findModule returns the open module with the loader handle, or, when the
// handle is 0, with the same moduleID. The caller must hold modulesMu.
func findModule(id moduleID, handle uintptr) *module {
	for _, m := range modules {
		if handle != 0 {
			if m.handle == handle {
				return m
			}
			continue
		}
		if m.handle == 0 && m.id.same(id) {
			return m
		}
	}
	return nil
}

// openModule returns a new reference to the module at path, loading and
// initializing the library when no reference is open.
//
// The library is loaded first so that its loader handle can be compared;
// a duplicate load of an open module only drops its extra loader reference.
func openModule(path string) (*module, error) {
	id := newModuleID(path)

	modulesMu.Lock()
	defer modulesMu.Unlock()

	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, errors.WithMessage(errCannotOpenPKCS11, path)
	}
	handle := loadedHandle(path)
	if m := findModule(id, handle); m != nil {
		ctx.Destroy()
		m.refs++
		return m, nil
	}

	finalize := true
	if err := ctx.Initialize(); err != nil {
		if !errors.Is(err, pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			ctx.Destroy()
			return nil, errors.WithMessagef(err, "initialize PKCS#11 library: %s", path)
		}
		finalize = false
	}

	m := &module{
		id:       id,
		handle:   handle,
		ctx:      ctx,
		refs:     1,
		finalize: finalize,
	}
	modules = append(modules, m)
	return m, nil
}

// release drops one reference. The last reference finalizes the library,
// when this package initialized it, and then unloads it.
func (m *module) release() error {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	m.refs--
	if m.refs > 0 {
		return nil
	}
	modules = slices.DeleteFunc(modules, func(o *module) bool { return o == m })

	var err error
	if m.finalize {
		if ferr := m.ctx.Finalize(); ferr != nil {
			err = errors.WithMessagef(ferr, "finalize PKCS#11 library: %s", m.id.path)
		}
	}
	m.ctx.Destroy()
	return err
}
