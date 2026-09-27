package dataprotection_test

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/effective-security/xpki/dataprotection"
)

// ExampleNewSymmetric protects a payload with a secret generated from
// crypto/rand. The secret is key material: generate it once, store it in a
// secret store, and give the same bytes to every process that must read the
// blobs. A passphrase is not a suitable secret.
func ExampleNewSymmetric() {
	secret := make([]byte, dataprotection.SymmetricMinSecretSize)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}

	p, err := dataprotection.NewSymmetric(secret)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	plaintext := []byte("session state")
	protected, err := p.Protect(ctx, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(protected) == len(plaintext)+dataprotection.SymmetricOverhead)

	unprotected, err := p.Unprotect(ctx, protected)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(unprotected))

	// another secret can not read the blob
	other := make([]byte, dataprotection.SymmetricMinSecretSize)
	if _, err := rand.Read(other); err != nil {
		panic(err)
	}
	p2, _ := dataprotection.NewSymmetric(other)
	_, err = p2.Unprotect(ctx, protected)
	fmt.Println(err)
	// Output:
	// true
	// session state
	// failed to unprotect: cipher: message authentication failed
}
