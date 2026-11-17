package signctx

import (
	"context"
	"crypto"
	"io"

	"github.com/cockroachdb/errors"
)

// Signer is a crypto.Signer whose signature operation can take a context.
// cryptoprov.ContextSigner has the same method set.
type Signer interface {
	crypto.Signer
	SignContext(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Decrypter is a crypto.Decrypter whose decryption can take a context.
// cryptoprov.ContextDecrypter has the same method set.
type Decrypter interface {
	crypto.Decrypter
	DecryptContext(ctx context.Context, rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error)
}

// Sign signs digest with signer under ctx: through SignContext when signer
// is a Signer, otherwise through Sign once ctx is checked, since a plain
// signer cannot be interrupted.
func Sign(ctx context.Context, signer crypto.Signer, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if cs, ok := signer.(Signer); ok {
		return cs.SignContext(ctx, rand, digest, opts)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	return signer.Sign(rand, digest, opts)
}

// Decrypt decrypts ciphertext with decrypter under ctx: through
// DecryptContext when decrypter is a Decrypter, otherwise through Decrypt
// once ctx is checked.
func Decrypt(ctx context.Context, decrypter crypto.Decrypter, rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if cd, ok := decrypter.(Decrypter); ok {
		return cd.DecryptContext(ctx, rand, ciphertext, opts)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	return decrypter.Decrypt(rand, ciphertext, opts)
}

// Bind returns a crypto.Signer whose Sign is Sign(ctx, signer, ...), for an
// API that only calls Sign, such as x509.CreateCertificate: a Signer signs
// through SignContext with ctx, any other signer through Sign once ctx is
// checked. The bound signer has Public and Sign, and SignMessage when signer
// is a crypto.MessageSigner but not a Signer: SignMessage takes no context,
// so a Signer is bound without it and crypto.SignMessage signs through the
// bound Sign. It hides every other method and the concrete type of signer,
// so bind at the call and keep signer for type checks. It must not outlive
// ctx.
func Bind(ctx context.Context, signer crypto.Signer) crypto.Signer {
	b := &bound{
		ctx:    ctx,
		signer: signer,
	}
	if _, ok := signer.(Signer); ok {
		return b
	}
	if ms, ok := signer.(crypto.MessageSigner); ok {
		return &boundMessageSigner{
			bound:   b,
			message: ms,
		}
	}
	return b
}

// bound is the signer Bind returns.
type bound struct {
	ctx    context.Context
	signer crypto.Signer
}

// Public returns the public key of the bound signer.
func (b *bound) Public() crypto.PublicKey {
	return b.signer.Public()
}

// Sign signs under the bound context.
func (b *bound) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return Sign(b.ctx, b.signer, rand, digest, opts)
}

// boundMessageSigner is the signer Bind returns for a crypto.MessageSigner
// that is not a Signer.
type boundMessageSigner struct {
	*bound
	message crypto.MessageSigner
}

// SignMessage checks the bound context and calls SignMessage of the signer,
// which takes no context.
func (b *boundMessageSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := b.ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	return b.message.SignMessage(rand, msg, opts)
}
