package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
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
	// DefaultJWKSMinCacheTTL is the shortest lifetime RemoteKeySet gives a
	// fetched JWKS document, whatever its response headers state.
	DefaultJWKSMinCacheTTL = 5 * time.Minute
	// DefaultJWKSMaxCacheTTL is the longest lifetime RemoteKeySet gives a
	// fetched JWKS document, and its lifetime when the response states none.
	DefaultJWKSMaxCacheTTL = time.Hour
	// DefaultJWKSStaleIfError is how long RemoteKeySet keeps using expired
	// keys while every refresh fails.
	DefaultJWKSStaleIfError = 24 * time.Hour

	// keyUseSignature is the JWK "use" value for signature keys (RFC 7517 4.2).
	keyUseSignature = "sig"

	// refreshAheadDivisor starts a background refresh in the last quarter of
	// the cache lifetime.
	refreshAheadDivisor = 4
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
	// Supported types are *rsa.PublicKey, *ecdsa.PublicKey and
	// *mldsa.PublicKey; any other entry, or an uninitialized ML-DSA key, makes
	// GetKey fail.
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
		switch typ := key.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			jwks = append(jwks, jose.JSONWebKey{Key: key})
		case *mldsa.PublicKey:
			if !validMLDSAKey(typ) {
				return nil, errors.Errorf("invalid ML-DSA public key at index %d", i)
			}
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
	case algMLDSA44, algMLDSA65, algMLDSA87:
		return mldsaKeyFits(key.Key, alg)
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

// WithMinCacheTTL sets the shortest lifetime of a fetched JWKS document, so a
// response with "Cache-Control: no-cache" or a short max-age does not cause a
// fetch on every lookup. Zero or negative keeps DefaultJWKSMinCacheTTL. A
// value above the maximum lifetime is lowered to it.
func WithMinCacheTTL(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) {
		if d > 0 {
			r.minTTL = d
		}
	}
}

// WithMaxCacheTTL sets the longest lifetime of a fetched JWKS document, which
// is also its lifetime when the response states none. Unless the refresh
// cooldown is longer, it bounds how long a key removed from the document is
// still accepted while the endpoint answers; a lookup that uses keys kept by
// WithStaleIfError can add the duration of one fetch. Zero or negative keeps
// DefaultJWKSMaxCacheTTL.
func WithMaxCacheTTL(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) {
		if d > 0 {
			r.maxTTL = d
		}
	}
}

// WithStaleIfError sets how long after their expiry the cached keys stay in
// use once a refresh in the last quarter of their lifetime, or after it, has
// failed; after that, lookups fail with the fetch error until a refresh
// succeeds. A fetch that fails earlier, for a kid that is not cached, does
// not count. Zero or negative fails lookups as soon as the keys expire and a
// refresh has failed. The default is DefaultJWKSStaleIfError.
func WithStaleIfError(d time.Duration) RemoteKeySetOption {
	return func(r *RemoteKeySet) {
		r.staleIfError = max(d, 0)
	}
}

// NewRemoteKeySet returns a KeySet that fetches a JWKS document from jwksURL
// over HTTP. NewParser uses it when ParserConfig.JWKSURI is set.
//
// Keys are fetched on the first lookup and cached for the lifetime that the
// response states (Cache-Control max-age, else Expires; no-cache and
// no-store state a lifetime of zero) less the age of the response (the
// greater of its Age header and the time since its Date), bounded by
// WithMinCacheTTL and WithMaxCacheTTL, and never shorter than the refresh
// cooldown. A lookup in
// the last quarter of that lifetime starts a refresh in the background and
// still uses the cached keys, so keys added to the document are picked up and
// removed keys stop being accepted without a lookup waiting for the endpoint.
// A lookup after the expiry waits for a refresh. Once a refresh in the last
// quarter or after the expiry has failed, the expired keys stay in use for
// WithStaleIfError, and every lookup that still uses them starts another
// background refresh once the cooldown has passed.
//
// A lookup that no usable cached key fits also refreshes, waiting for the
// result. Concurrent refreshes are coalesced, and a refresh of any kind
// starts at most once per refresh cooldown. ctx bounds the lifetime of every
// fetch; each fetch is also bounded by the fetch timeout and response size
// limit. A RemoteKeySet starts no goroutine when it is not used. Reuse one
// RemoteKeySet per URL rather than creating new ones.
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
		minTTL:          DefaultJWKSMinCacheTTL,
		maxTTL:          DefaultJWKSMaxCacheTTL,
		staleIfError:    DefaultJWKSStaleIfError,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	r.minTTL = min(r.minTTL, r.maxTTL)
	if r.client == nil {
		r.client = &http.Client{Timeout: r.fetchTimeout}
	}
	return r
}

// RemoteKeySet is a KeySet implementation that validates JSON web tokens against
// a jwks_uri endpoint. Key selection follows the StaticKeySet rules for
// KeySet entries. Create it with NewRemoteKeySet, which describes how keys
// are cached and refreshed.
type RemoteKeySet struct {
	jwksURL         string
	ctx             context.Context
	client          *http.Client
	cooldown        time.Duration
	fetchTimeout    time.Duration
	maxResponseSize int64
	minTTL          time.Duration
	maxTTL          time.Duration
	staleIfError    time.Duration
	now             func() time.Time

	// guard all other fields
	mu sync.RWMutex

	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *inflight

	// cachedKeys are the keys of the last successful fetch.
	cachedKeys []jose.JSONWebKey
	// expiresAt is when cachedKeys expire, and refreshAt when a lookup
	// starts a background refresh. serveUntil is when lookups stop using
	// cachedKeys without waiting for a fetch: expiresAt, or expiresAt plus
	// staleIfError after a fetch that failed at or after refreshAt. All three
	// are zero until the first successful fetch.
	expiresAt  time.Time
	refreshAt  time.Time
	serveUntil time.Time
	// lastFetch is when the last fetch finished; lastErr is its error.
	lastFetch time.Time
	lastErr   error
	// fetches counts completed fetches, so a lookup that missed against an
	// older cache snapshot does not start another fetch (see keysFromRemote).
	fetches uint64
}

// cacheState is a lookup's snapshot of the RemoteKeySet cache.
type cacheState struct {
	keys []jose.JSONWebKey
	// fetches is the number of completed fetches the snapshot reflects.
	fetches uint64
	// usable reports whether the lookup may use keys without a fetch.
	usable bool
	// refresh reports whether the lookup should start a background refresh.
	refresh bool
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
	c := r.keysFromCache(r.now())
	if c.refresh {
		r.refreshAhead(c.fetches)
	}
	if c.usable {
		if key, err := selectKey(c.keys, keyID, alg); err == nil {
			return key, nil
		}
	}
	// If no cached key fits, check for new keys from the remote. This is the
	// strategy recommended by the spec.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	keys, fetchErr := r.keysFromRemote(ctx, c.fetches)
	key, err := selectKey(keys, keyID, alg)
	if err != nil && fetchErr != nil {
		return nil, errors.WithMessage(fetchErr, "unable to fetch JWKS key")
	}
	return key, err
}

// keysFromCache returns a snapshot of the cache at now.
func (r *RemoteKeySet) keysFromCache(now time.Time) cacheState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	usable := now.Before(r.serveUntil)
	return cacheState{
		keys:    r.cachedKeys,
		fetches: r.fetches,
		usable:  usable,
		refresh: usable && !now.Before(r.refreshAt) && r.inflight == nil && !r.throttledLocked(now),
	}
}

// throttledLocked reports whether the refresh cooldown forbids a fetch at
// now. The caller holds mu.
func (r *RemoteKeySet) throttledLocked(now time.Time) bool {
	return !r.lastFetch.IsZero() && now.Sub(r.lastFetch) < r.cooldown
}

// refreshAhead starts a background refresh unless one is in flight or a
// fetch completed after the caller's snapshot, whose fetch count is seen.
// The snapshot already checked the cooldown, which only a completed fetch
// can restart.
func (r *RemoteKeySet) refreshAhead(seen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight == nil && r.fetches == seen {
		r.startRefreshLocked()
	}
}

// startRefreshLocked starts a fetch and returns its inflight request, which
// refresh releases. The caller holds mu and has checked that no fetch is in
// flight.
func (r *RemoteKeySet) startRefreshLocked() *inflight {
	inf := newInflight()
	r.inflight = inf
	go r.refresh(inf)
	return inf
}

// keysFromRemote syncs the key set from the remote set, records the values in
// the cache, and returns the keys a lookup may use with the error of the last
// fetch, if it failed (see outcomeLocked). seen is the fetch count of the
// caller's cache snapshot. When a fetch completed after that snapshot, the
// caller shares its outcome instead of starting another one, as it would have
// by waiting on it, unless that fetch succeeded and its keys have expired
// since. Within the refresh cooldown it returns the outcome of the last fetch.
func (r *RemoteKeySet) keysFromRemote(ctx context.Context, seen uint64) ([]jose.JSONWebKey, error) {
	// Need to lock to inspect the inflight request field.
	r.mu.Lock()
	inf := r.inflight
	if inf == nil {
		now := r.now()
		if r.fetches != seen && (r.lastErr != nil || now.Before(r.serveUntil)) {
			keys, err := r.outcomeLocked(now)
			r.mu.Unlock()
			return keys, err
		}
		if r.throttledLocked(now) {
			keys, err := r.outcomeLocked(now)
			r.mu.Unlock()
			return keys, errors.WithMessage(err, "JWKS refresh throttled after failure")
		}
		inf = r.startRefreshLocked()
	}
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, errors.WithStack(ctx.Err())
	case <-inf.wait():
		return inf.result()
	}
}

// outcomeLocked returns what a lookup that cannot wait for another fetch
// gets at now: the cached keys while lookups may use them, with the error of
// the last fetch if it failed; otherwise no keys and that error. The caller
// holds mu. The last fetch failed whenever the keys may not be used: a
// successful fetch keeps them usable for at least the cooldown, and
// keysFromRemote fetches again once that has passed.
func (r *RemoteKeySet) outcomeLocked(now time.Time) ([]jose.JSONWebKey, error) {
	if now.Before(r.serveUntil) {
		return r.cachedKeys, r.lastErr
	}
	if r.expiresAt.IsZero() {
		return nil, r.lastErr
	}
	return nil, errors.WithMessagef(r.lastErr, "JWKS keys expired at %s", r.expiresAt.UTC().Format(time.RFC3339))
}

// refresh fetches the keys, publishes them to the cache and frees the
// inflight slot before waking the waiters, so new lookups see the new state.
// The waiters get outcomeLocked at the end of the fetch.
func (r *RemoteKeySet) refresh(inf *inflight) {
	keys, ttl, err := r.updateKeys()

	r.mu.Lock()
	now := r.now()
	// stale is set when a fetch failed while keys are cached. Only a failure
	// at or after refreshAt starts the grace period: a miss-driven fetch that
	// failed early in the lifetime says nothing about the endpoint at the
	// expiry, so a lookup then still waits for a fetch.
	stale := err != nil && !r.expiresAt.IsZero()
	if err == nil {
		r.cachedKeys = keys
		r.expiresAt = now.Add(ttl)
		r.refreshAt = r.expiresAt.Add(-ttl / refreshAheadDivisor)
		r.serveUntil = r.expiresAt
	} else if stale && !now.Before(r.refreshAt) {
		r.serveUntil = r.expiresAt.Add(r.staleIfError)
	}
	r.lastFetch = now
	r.lastErr = err
	r.fetches++
	r.inflight = nil
	expiresAt, serveUntil := r.expiresAt, r.serveUntil
	result, resultErr := r.outcomeLocked(now)
	r.mu.Unlock()

	if stale {
		logger.KV(xlog.WARNING,
			"reason", "jwks_refresh",
			"url", r.jwksURL,
			"expires", expiresAt,
			"serve_until", serveUntil,
			"err", err.Error(),
		)
	}
	inf.done(result, resultErr)
}

// cacheTTL returns the lifetime of a document fetched with the response
// headers h: the lifetime they state, else the maximum, bounded by the
// minimum and maximum lifetime and never shorter than the refresh cooldown,
// so a refresh is never throttled when the keys expire.
func (r *RemoteKeySet) cacheTTL(h http.Header) time.Duration {
	ttl := r.maxTTL
	if lifetime, ok := cacheLifetime(h, r.now()); ok {
		ttl = min(max(lifetime, r.minTTL), r.maxTTL)
	}
	return max(ttl, r.cooldown)
}

// updateKeys fetches the JWKS document and returns its keys and their cache
// lifetime.
func (r *RemoteKeySet) updateKeys() ([]jose.JSONWebKey, time.Duration, error) {
	ctx, cancel := context.WithTimeout(r.ctx, r.fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.jwksURL, nil)
	if err != nil {
		return nil, 0, errors.WithMessage(err, "failed to create request")
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, errors.WithMessage(err, "failed to fetch keys")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, errors.Errorf("get keys failed: %s", resp.Status)
	}

	// Read one byte past the limit to detect oversized bodies, unless the
	// limit is already the largest representable size.
	readLimit := r.maxResponseSize
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	if err != nil {
		return nil, 0, errors.WithMessage(err, "failed to read response body")
	}
	if int64(len(body)) > r.maxResponseSize {
		return nil, 0, errors.Errorf("JWKS response exceeds %d bytes", r.maxResponseSize)
	}

	var keySet jose.JSONWebKeySet
	err = json.Unmarshal(body, &keySet)
	if err != nil {
		return nil, 0, errors.WithMessage(err, "failed to decode keys")
	}
	return keySet.Keys, r.cacheTTL(resp.Header), nil
}
