// Package signctx carries a context.Context to a signer or decrypter that
// can use one, for packages below cryptoprov in the import graph
// (certutil). cryptoprov.ContextSigner, ContextDecrypter, SignContext,
// DecryptContext and BindContext are the public form; an implementation
// satisfies both, since the interfaces have the same method sets.
//
//	signer = signctx.Bind(ctx, signer)
//	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
package signctx
