//go:build unix

package crypto11

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

// loadedHandle returns the dynamic loader's handle for the library at path,
// which pkcs11.New has already loaded, or 0. The loader returns one handle
// for every name that resolves to the same loaded object (a bare name found
// on the search path, a path, a symlink or a hardlink), so the handle
// identifies the module across aliases.
func loadedHandle(path string) uintptr {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	h := C.dlopen(cpath, C.RTLD_LAZY|C.RTLD_NOLOAD)
	if h == nil {
		return 0
	}
	// the handle stays valid: pkcs11.New holds its own reference
	C.dlclose(h)
	return uintptr(h)
}
