package cryptoprov

import (
	"context"
	"crypto"
	"io"

	"github.com/effective-security/xpki/v2/internal/signctx"
)

// ContextSigner is a crypto.Signer whose signature can be bounded or
// cancelled by a context: a KMS signer passes ctx to its SDK call, and a
// PKCS#11 signer waits for a pooled session no longer than ctx allows. Sign
// of such a signer is SignContext with context.Background(). Every signer of
// the providers of this module is one; use SignContext to sign with any
// crypto.Signer, and BindContext to hand ctx to an API that calls Sign.
type ContextSigner interface {
	crypto.Signer
	// SignContext is Sign under ctx: it returns an error that wraps
	// ctx.Err() when ctx ends before the signature is produced.
	SignContext(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// ContextDecrypter is a crypto.Decrypter whose decryption can be bounded or
// cancelled by a context, as ContextSigner is for signing. The RSA keys of
// crypto11 and of the in-memory providers are ContextDecrypters.
type ContextDecrypter interface {
	crypto.Decrypter
	// DecryptContext is Decrypt under ctx: it returns an error that wraps
	// ctx.Err() when ctx ends before the plaintext is produced.
	DecryptContext(ctx context.Context, rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error)
}

// SignContext signs digest with signer under ctx. A ContextSigner gets ctx
// through SignContext; any other signer is called through Sign after ctx is
// checked, since it cannot be interrupted.
func SignContext(ctx context.Context, signer crypto.Signer, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return signctx.Sign(ctx, signer, rand, digest, opts)
}

// DecryptContext decrypts ciphertext with decrypter under ctx. A
// ContextDecrypter gets ctx through DecryptContext; any other decrypter is
// called through Decrypt after ctx is checked.
func DecryptContext(ctx context.Context, decrypter crypto.Decrypter, rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return signctx.Decrypt(ctx, decrypter, rand, ciphertext, opts)
}

// BindContext returns a crypto.Signer whose Sign is signer's SignContext
// with ctx, for an API that only calls Sign, such as x509.CreateCertificate,
// x509.CreateCertificateRequest or ocsp.CreateResponse:
//
//	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, cryptoprov.BindContext(ctx, signer))
//
// The bound Sign is SignContext(ctx, signer, ...): a ContextSigner signs
// with ctx, any other signer once ctx is checked. The bound signer has
// Public and Sign, and SignMessage when signer is a crypto.MessageSigner but
// not a ContextSigner (SignMessage takes no context, so a ContextSigner signs
// through the bound Sign); it hides every other method and the concrete type
// of signer, so bind at the call and keep signer for type checks such as
// csr.SignatureAlgorithmer. It must not be used after ctx ends.
func BindContext(ctx context.Context, signer crypto.Signer) crypto.Signer {
	return signctx.Bind(ctx, signer)
}
