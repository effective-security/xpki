package signctx_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/effective-security/xpki/v2/internal/signctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ctxKey struct{}

// recorder is a Signer and Decrypter that records the context it got and
// counts the calls that reached the key.
type recorder struct {
	key   *rsa.PrivateKey
	ctx   context.Context
	calls int
}

func (r *recorder) Public() crypto.PublicKey {
	return r.key.Public()
}

func (r *recorder) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return r.SignContext(context.Background(), rand, digest, opts)
}

func (r *recorder) SignContext(ctx context.Context, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.ctx = ctx
	r.calls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.key.Sign(rand, digest, opts)
}

func (r *recorder) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return r.DecryptContext(context.Background(), rand, ciphertext, opts)
}

func (r *recorder) DecryptContext(ctx context.Context, rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	r.ctx = ctx
	r.calls++
	return r.key.Decrypt(rand, ciphertext, opts)
}

// messageSigner is a plain crypto.MessageSigner that counts SignMessage.
type messageSigner struct {
	crypto.Signer
	messages int
}

func (m *messageSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	m.messages++
	h := opts.HashFunc().New()
	h.Write(msg)
	return m.Sign(rand, h.Sum(nil), opts)
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &recorder{key: key}
}

func cancelled(t *testing.T) context.Context {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	return ctx
}

func digest(msg string) []byte {
	sum := sha256.Sum256([]byte(msg))
	return sum[:]
}

func TestSign(t *testing.T) {
	t.Parallel()
	rec := newRecorder(t)
	ctx := context.WithValue(t.Context(), ctxKey{}, "sign")

	sig, err := signctx.Sign(ctx, rec, rand.Reader, digest("m"), crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&rec.key.PublicKey, crypto.SHA256, digest("m"), sig))
	assert.Equal(t, "sign", rec.ctx.Value(ctxKey{}), "SignContext did not get ctx")

	// a plain signer is not called with an ended context
	plain := &messageSigner{Signer: rec.key}
	_, err = signctx.Sign(cancelled(t), plain, rand.Reader, digest("m"), crypto.SHA256)
	require.ErrorIs(t, err, context.Canceled)
	sig, err = signctx.Sign(t.Context(), plain, rand.Reader, digest("m"), crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&rec.key.PublicKey, crypto.SHA256, digest("m"), sig))
}

func TestDecrypt(t *testing.T) {
	t.Parallel()
	rec := newRecorder(t)
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rec.key.PublicKey, []byte("secret"), nil)
	require.NoError(t, err)
	opts := &rsa.OAEPOptions{Hash: crypto.SHA256}
	ctx := context.WithValue(t.Context(), ctxKey{}, "decrypt")

	plaintext, err := signctx.Decrypt(ctx, rec, rand.Reader, ciphertext, opts)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), plaintext)
	assert.Equal(t, "decrypt", rec.ctx.Value(ctxKey{}), "DecryptContext did not get ctx")

	_, err = signctx.Decrypt(cancelled(t), rec.key, rand.Reader, ciphertext, opts)
	require.ErrorIs(t, err, context.Canceled)
	plaintext, err = signctx.Decrypt(t.Context(), rec.key, rand.Reader, ciphertext, opts)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), plaintext)
}

func TestBind(t *testing.T) {
	t.Parallel()
	rec := newRecorder(t)
	ctx := context.WithValue(t.Context(), ctxKey{}, "bind")

	bound := signctx.Bind(ctx, rec)
	assert.Equal(t, rec.Public(), bound.Public())
	_, isMessageSigner := bound.(crypto.MessageSigner)
	assert.False(t, isMessageSigner, "a bound signer gained SignMessage")
	_, isDecrypter := bound.(crypto.Decrypter)
	assert.False(t, isDecrypter, "Bind is for signing only")

	sig, err := bound.Sign(rand.Reader, digest("m"), crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&rec.key.PublicKey, crypto.SHA256, digest("m"), sig))
	assert.Equal(t, "bind", rec.ctx.Value(ctxKey{}), "the bound Sign did not use ctx")

	_, err = signctx.Bind(cancelled(t), rec).Sign(rand.Reader, digest("m"), crypto.SHA256)
	require.ErrorIs(t, err, context.Canceled)

	// a plain signer is bound too: an ended context fails before it is called
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = signctx.Bind(cancelled(t), ecKey).Sign(rand.Reader, digest("m"), crypto.SHA256)
	require.ErrorIs(t, err, context.Canceled)
	sig, err = signctx.Bind(t.Context(), ecKey).Sign(rand.Reader, digest("m"), crypto.SHA256)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&ecKey.PublicKey, digest("m"), sig))
}

func TestBindMessageSigner(t *testing.T) {
	t.Parallel()
	rec := newRecorder(t)
	ms := &messageSigner{Signer: rec}

	bound, ok := signctx.Bind(t.Context(), ms).(crypto.MessageSigner)
	require.True(t, ok, "Bind dropped SignMessage")
	sig, err := bound.SignMessage(rand.Reader, []byte("m"), crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&rec.key.PublicKey, crypto.SHA256, digest("m"), sig))
	assert.Equal(t, 1, ms.messages)

	bound = signctx.Bind(cancelled(t), ms).(crypto.MessageSigner)
	_, err = bound.SignMessage(rand.Reader, []byte("m"), crypto.SHA256)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, ms.messages, "SignMessage ran with an ended context")
}

// contextMessageSigner is a Signer that is also a crypto.MessageSigner.
type contextMessageSigner struct {
	*recorder
	messages int
}

func (m *contextMessageSigner) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	m.messages++
	h := opts.HashFunc().New()
	h.Write(msg)
	return m.Sign(rand, h.Sum(nil), opts)
}

func TestBindContextMessageSigner(t *testing.T) {
	t.Parallel()
	signer := &contextMessageSigner{recorder: newRecorder(t)}
	ctx := context.WithValue(t.Context(), ctxKey{}, "bind")

	bound := signctx.Bind(ctx, signer)
	_, isMessageSigner := bound.(crypto.MessageSigner)
	assert.False(t, isMessageSigner, "SignMessage would bypass SignContext")

	sig, err := crypto.SignMessage(bound, rand.Reader, []byte("m"), crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&signer.key.PublicKey, crypto.SHA256, digest("m"), sig))
	assert.Equal(t, "bind", signer.ctx.Value(ctxKey{}), "the signature did not use ctx")
	assert.Zero(t, signer.messages)

	_, err = crypto.SignMessage(signctx.Bind(cancelled(t), signer), rand.Reader, []byte("m"), crypto.SHA256)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, signer.messages)
}
