package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	jose "github.com/go-jose/go-jose/v4"
)

const (
	// DefaultJWKSRefreshCooldown is the minimum interval between the end of
	// one RemoteKeySet fetch and the start of the next.
	DefaultJWKSRefreshCooldown = 10 * time.Second
	// DefaultJWKSFetchTimeout bounds each RemoteKeySet fetch.
	DefaultJWKSFetchTimeout = 10 * time.Second
	// DefaultJWKSMaxResponseSize is the largest JWKS document, in bytes,
	// that RemoteKeySet accepts.
	DefaultJWKSMaxResponseSize = 1 << 20

	// keyUseSignature is the JWK "use" value for signature keys (RFC 7517 4.2).
	keyUseSignature = "sig"
)

var (
	// ErrKeyNotFound is returned when a KeySet has no key eligible to verify
	// a token with the requested kid and algorithm.
	ErrKeyNotFound = errors.New("key not found")
	// ErrAmbiguousKey is returned when more than one key is eligible to
	// verify a token with the requested kid and algorithm.
	ErrAmbiguousKey = errors.New("ambiguous key")
)

// KeySet is an interface for verifying JWT signatures.
type KeySet interface {
	// GetKey returns the key to verify a token with the given kid header.
	// An empty keyID selects the only signing-eligible key, if there is
	// exactly one.
	GetKey(ctx context.Context, keyID string) (any, error)
}

// AlgorithmKeySet is a KeySet that can also restrict key selection to keys
// compatible with the token's signing algorithm. The parser uses it when the
// configured KeySet implements it.
type AlgorithmKeySet interface {
	KeySet
	// GetKeyForAlgorithm returns the only key eligible to verify a token with
	// the given kid and alg headers. An empty keyID matches every key.
	GetKeyForAlgorithm(ctx context.Context, keyID, alg string) (any, error)
}

// StaticKeySet is a verifier that validates JWT against a static set of public keys.
//
// A key is eligible when its JWK "use" is empty or "sig" and, when the token
// algorithm is known, its type, curve and JWK "alg" fit that algorithm.
// A token kid selects KeySet entries with that KeyID; when none has it,
// PublicKeys entries whose RFC 7638 SHA-256 thumbprint (base64url) equals the
// kid. An empty kid considers every entry of both lists. Exactly one eligible
// key must remain, otherwise GetKey returns ErrKeyNotFound or ErrAmbiguousKey.
type StaticKeySet struct {
	// PublicKeys used to verify the JWT. They have no kid, see StaticKeySet.
	// Supported types are *rsa.PublicKey and *ecdsa.PublicKey; any other
	// entry makes GetKey fail.
	PublicKeys []crypto.PublicKey
	KeySet     []jose.JSONWebKey
}

// GetKey returns the public key for the given kid.
func (s *StaticKeySet) GetKey(ctx context.Context, keyID string) (any, error) {
	return s.GetKeyForAlgorithm(ctx, keyID, "")
}

// GetKeyForAlgorithm returns the public key for the given kid and alg.
func (s *StaticKeySet) GetKeyForAlgorithm(_ context.Context, keyID, alg string) (any, error) {
	publicKeys, err := publicKeysToJWK(s.PublicKeys)
	if err != nil {
		return nil, err
	}
	if keyID == "" {
		return selectKey(append(publicKeys, s.KeySet...), keyID, alg)
	}
	if hasKeyID(s.KeySet, keyID) {
		return selectKey(s.KeySet, keyID, alg)
	}
	for i := range publicKeys {
		tp, err := publicKeys[i].Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to compute key thumbprint")
		}
		publicKeys[i].KeyID = base64.RawURLEncoding.EncodeToString(tp)
	}
	return selectKey(publicKeys, keyID, alg)
}

// publicKeysToJWK wraps raw public keys in kid-less JWKs.
func publicKeysToJWK(keys []crypto.PublicKey) ([]jose.JSONWebKey, error) {
	jwks := make([]jose.JSONWebKey, 0, len(keys))
	for i, key := range keys {
		switch key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			jwks = append(jwks, jose.JSONWebKey{Key: key})
		default:
			return nil, errors.Errorf("unsupported public key type at index %d: %T", i, key)
		}
	}
	return jwks, nil
}

func hasKeyID(keys []jose.JSONWebKey, keyID string) bool {
	for i := range keys {
		if keys[i].KeyID == keyID {
			return true
		}
	}
	return false
}

// selectKey returns the only key that matches keyID (empty matches all) and
// is eligible for alg.
func selectKey(keys []jose.JSONWebKey, keyID, alg string) (any, error) {
	var found any
	matched, eligible := 0, 0
	for i := range keys {
		key := &keys[i]
		if keyID != "" && key.KeyID != keyID {
			continue
		}
		matched++
		if !isSigningKeyFor(key, alg) {
			continue
		}
		eligible++
		found = key.Key
	}
	switch {
	case eligible == 1:
		return found, nil
	case eligible > 1:
		return nil, errors.Wrapf(ErrAmbiguousKey, "kid=%q alg=%q matches %d keys", keyID, alg, eligible)
	case matched > 0:
		return nil, errors.Wrapf(ErrKeyNotFound, "no signing key for kid=%q alg=%q", keyID, alg)
	default:
		return nil, errors.Wrapf(ErrKeyNotFound, "kid=%q", keyID)
	}
}

// isSigningKeyFor reports whether key may verify a signature made with alg.
// An empty alg checks only the key use.
func isSigningKeyFor(key *jose.JSONWebKey, alg string) bool {
	if key.Use != "" && key.Use != keyUseSignature {
		return false
	}
	if alg == "" {
		return true
	}
	if key.Algorithm != "" && key.Algorithm != alg {
		return false
	}
	switch alg {
	case algRS256, algRS384, algRS512:
		_, ok := key.Key.(*rsa.PublicKey)
		return ok
	case algES256, algES384, algES512:
		pub, ok := key.Key.(*ecdsa.PublicKey)
		return ok && pub.Curve == curveMap[alg]
	default:
		return false
	}
}

// RemoteKeySetOption configures a RemoteKeySet.
type RemoteKeySetOption func(*RemoteKeySet)

// WithHTTPClient sets the client used to fetch the JWKS document. The fetch
// timeout still applies to each request. A nil client keeps the default.
func WithHTTPClient(client *http.Client) RemoteKeySetOption {
	return func(r *RemoteKeySet) {
		if client != nil {
			r.client = client
		}
	}
}

// WithRefreshCooldown sets the minimum interval between the end of one fetch
// and the start of the next; lookups for unknown kids inside that window use
// the cached keys. Zero or negative disables throttling. The default is
// DefaultJWKSRefreshCooldown.
func WithRefreshCooldown(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) {
		r.cooldown = max(d, 0)
	}
}

// WithFetchTimeout bounds each fetch, including reading the body. Zero or
// negative keeps DefaultJWKSFetchTimeout.
func WithFetchTimeout(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) {
		if d > 0 {
			r.fetchTimeout = d
		}
	}
}

// WithMaxResponseSize sets the largest accepted JWKS document in bytes. Zero
// or negative keeps DefaultJWKSMaxResponseSize.
func WithMaxResponseSize(n int64) RemoteKeySetOption {
	return func(r *RemoteKeySet) {
		if n > 0 {
			r.maxResponseSize = n
		}
	}
}

// NewRemoteKeySet returns a KeySet that fetches a JWKS document from jwksURL
// over HTTP. NewParser uses it when ParserConfig.JWKSURL is set. Keys are
// fetched lazily on the first lookup and re-fetched when no cached key fits
// the lookup; concurrent refreshes are coalesced, and a refresh starts at
// most once per refresh cooldown. ctx bounds the lifetime of every fetch;
// each fetch is also bounded by the fetch timeout and response size limit.
// Reuse one RemoteKeySet per URL rather than creating new ones.
func NewRemoteKeySet(ctx context.Context, jwksURL string, opts ...RemoteKeySetOption) *RemoteKeySet {
	return newRemoteKeySet(ctx, jwksURL, opts...)
}

func newRemoteKeySet(ctx context.Context, jwksURL string, opts ...RemoteKeySetOption) *RemoteKeySet {
	if ctx == nil {
		ctx = context.Background()
	}
	r := &RemoteKeySet{
		jwksURL:         jwksURL,
		ctx:             ctx,
		cooldown:        DefaultJWKSRefreshCooldown,
		fetchTimeout:    DefaultJWKSFetchTimeout,
		maxResponseSize: DefaultJWKSMaxResponseSize,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.client == nil {
		r.client = &http.Client{Timeout: r.fetchTimeout}
	}
	return r
}

// RemoteKeySet is a KeySet implementation that validates JSON web tokens against
// a jwks_uri endpoint. Key selection follows the StaticKeySet rules for
// KeySet entries. Create it with NewRemoteKeySet.
type RemoteKeySet struct {
	jwksURL         string
	ctx             context.Context
	client          *http.Client
	cooldown        time.Duration
	fetchTimeout    time.Duration
	maxResponseSize int64
	now             func() time.Time

	// guard all other fields
	mu sync.RWMutex

	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *inflight

	// A set of cached keys.
	cachedKeys []jose.JSONWebKey
	// lastFetch is when the last fetch finished; lastErr is its error.
	lastFetch time.Time
	lastErr   error
	// fetches counts completed fetches, so a lookup that missed against an
	// older cache snapshot does not start another fetch (see keysFromRemote).
	fetches uint64
}

// inflight is used to wait on some in-flight request from multiple goroutines.
type inflight struct {
	doneCh chan struct{}

	keys []jose.JSONWebKey
	err  error
}

func newInflight() *inflight {
	return &inflight{doneCh: make(chan struct{})}
}

// wait returns a channel that multiple goroutines can receive on. Once it returns
// a value, the inflight request is done and result() can be inspected.
func (i *inflight) wait() <-chan struct{} {
	return i.doneCh
}

// done can only be called by a single goroutine. It records the result of the
// inflight request and signals other goroutines that the result is safe to
// inspect.
func (i *inflight) done(keys []jose.JSONWebKey, err error) {
	i.keys = keys
	i.err = err
	close(i.doneCh)
}

// result cannot be called until the wait() channel has returned a value.
func (i *inflight) result() ([]jose.JSONWebKey, error) {
	return i.keys, i.err
}

// GetKey returns the public key for the given kid.
func (r *RemoteKeySet) GetKey(ctx context.Context, keyID string) (any, error) {
	return r.GetKeyForAlgorithm(ctx, keyID, "")
}

// GetKeyForAlgorithm returns the public key for the given kid and alg.
func (r *RemoteKeySet) GetKeyForAlgorithm(ctx context.Context, keyID, alg string) (any, error) {
	keys, seen := r.keysFromCache()
	if len(keys) > 0 {
		if key, err := selectKey(keys, keyID, alg); err == nil {
			return key, nil
		}
	}
	// If no cached key fits, check for new keys from the remote. This is the
	// strategy recommended by the spec.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	keys, err := r.keysFromRemote(ctx, seen)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to fetch JWKS key")
	}
	return selectKey(keys, keyID, alg)
}

// keysFromCache returns the cached keys and the number of completed fetches
// they reflect.
func (r *RemoteKeySet) keysFromCache() ([]jose.JSONWebKey, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cachedKeys, r.fetches
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set. seen is the fetch count of the caller's cache
// snapshot. When a fetch completed after that snapshot, the caller shares its
// result instead of starting another one, as it would have by waiting on it.
// Within the refresh cooldown it returns the cached keys, or the last fetch
// error when nothing is cached.
func (r *RemoteKeySet) keysFromRemote(ctx context.Context, seen uint64) ([]jose.JSONWebKey, error) {
	// Need to lock to inspect the inflight request field.
	r.mu.Lock()
	inf := r.inflight
	if inf == nil {
		if r.fetches != seen {
			keys, lastErr := r.cachedKeys, r.lastErr
			r.mu.Unlock()
			if lastErr != nil {
				return nil, lastErr
			}
			return keys, nil
		}
		if !r.lastFetch.IsZero() && r.now().Sub(r.lastFetch) < r.cooldown {
			keys, lastErr := r.cachedKeys, r.lastErr
			r.mu.Unlock()
			if len(keys) == 0 && lastErr != nil {
				return nil, errors.WithMessage(lastErr, "JWKS refresh throttled after failure")
			}
			return keys, nil
		}
		// This goroutine has exclusive ownership over the new inflight
		// request, which is released by refresh.
		inf = newInflight()
		r.inflight = inf
		go r.refresh(inf)
	}
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, errors.WithStack(ctx.Err())
	case <-inf.wait():
		return inf.result()
	}
}

// refresh fetches the keys, publishes them to the cache and frees the
// inflight slot before waking the waiters, so new lookups see the new state.
func (r *RemoteKeySet) refresh(inf *inflight) {
	keys, err := r.updateKeys()

	r.mu.Lock()
	if err == nil {
		r.cachedKeys = keys
	}
	r.lastFetch = r.now()
	r.lastErr = err
	r.fetches++
	r.inflight = nil
	r.mu.Unlock()

	inf.done(keys, err)
}

func (r *RemoteKeySet) updateKeys() ([]jose.JSONWebKey, error) {
	ctx, cancel := context.WithTimeout(r.ctx, r.fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.jwksURL, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create request")
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to fetch keys")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("get keys failed: %s", resp.Status)
	}

	// Read one byte past the limit to detect oversized bodies, unless the
	// limit is already the largest representable size.
	readLimit := r.maxResponseSize
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return nil, errors.WithMessage(err, "failed to read response body")
	}
	if int64(len(body)) > r.maxResponseSize {
		return nil, errors.Errorf("JWKS response exceeds %d bytes", r.maxResponseSize)
	}

	var keySet jose.JSONWebKeySet
	err = json.Unmarshal(body, &keySet)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to decode keys")
	}
	return keySet.Keys, nil
}
