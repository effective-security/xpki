package jwt

import (
	"context"
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/cockroachdb/errors"
	jose "github.com/go-jose/go-jose/v3"
)

// KeySet is an interface for verifying JWT signatures.
type KeySet interface {
	GetKey(ctx context.Context, kid string) (any, error)
}

// StaticKeySet is a verifier that validates JWT against a static set of public keys.
type StaticKeySet struct {
	// PublicKeys used to verify the JWT. Supported types are *rsa.PublicKey and
	// *ecdsa.PublicKey.
	PublicKeys []crypto.PublicKey
	KeySet     []jose.JSONWebKey
}

// GetKey returns the public key for the given kid.
func (s *StaticKeySet) GetKey(ctx context.Context, keyID string) (any, error) {
	for _, key := range s.KeySet {
		if keyID == "" || key.KeyID == keyID {
			return key.Key, nil
		}
	}
	return nil, errors.Errorf("key not found: %s", keyID)
}

// NewRemoteKeySet returns a KeySet that can validate JSON web tokens by using HTTP
// GETs to fetch JSON web token sets hosted at a remote URL. This is automatically
// used by NewProvider using the URLs returned by OpenID Connect discovery, but is
// exposed for providers that don't support discovery or to prevent round trips to the
// discovery URL.
//
// The returned KeySet is a long lived verifier that caches keys based on any
// keys change. Reuse a common remote key set instead of creating new ones as needed.
func NewRemoteKeySet(ctx context.Context, jwksURL string) *RemoteKeySet {
	return newRemoteKeySet(ctx, jwksURL)
}

func newRemoteKeySet(ctx context.Context, jwksURL string) *RemoteKeySet {
	return &RemoteKeySet{jwksURL: jwksURL, ctx: ctx}
}

// RemoteKeySet is a KeySet implementation that validates JSON web tokens against
// a jwks_uri endpoint.
type RemoteKeySet struct {
	jwksURL string
	ctx     context.Context

	// guard all other fields
	mu sync.RWMutex

	// inflight suppresses parallel execution of updateKeys and allows
	// multiple goroutines to wait for its result.
	inflight *inflight

	// A set of cached keys.
	cachedKeys []jose.JSONWebKey
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
	keys := r.keysFromCache()
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			return key, nil
		}
	}
	// If the kid doesn't match, check for new keys from the remote. This is the
	// strategy recommended by the spec.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	keys, err := r.keysFromRemote(ctx)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to fetch JWKS key")
	}

	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			return key.Key, nil
		}
	}
	return nil, errors.Errorf("key not found: %s", keyID)
}

func (r *RemoteKeySet) keysFromCache() (keys []jose.JSONWebKey) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cachedKeys
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
func (r *RemoteKeySet) keysFromRemote(ctx context.Context) ([]jose.JSONWebKey, error) {
	// Need to lock to inspect the inflight request field.
	r.mu.Lock()
	// If there's not a current inflight request, create one.
	if r.inflight == nil {
		r.inflight = newInflight()

		// This goroutine has exclusive ownership over the current inflight
		// request. It releases the resource by nil'ing the inflight field
		// once the goroutine is done.
		go func() {
			// Sync keys and finish inflight when that's done.
			keys, err := r.updateKeys()

			r.inflight.done(keys, err)

			// Lock to update the keys and indicate that there is no longer an
			// inflight request.
			r.mu.Lock()
			defer r.mu.Unlock()

			if err == nil {
				r.cachedKeys = keys
			}

			// Free inflight so a different request can run.
			r.inflight = nil
		}()
	}
	inflight := r.inflight
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-inflight.wait():
		return inflight.result()
	}
}

func (r *RemoteKeySet) updateKeys() ([]jose.JSONWebKey, error) {
	req, err := http.NewRequest("GET", r.jwksURL, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create request")
	}
	client := http.DefaultClient

	resp, err := client.Do(req.WithContext(r.ctx))
	if err != nil {
		return nil, errors.WithMessage(err, "failed to fetch keys")
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to read response body")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("get keys failed: %s %s", resp.Status, body)
	}

	var keySet jose.JSONWebKeySet
	err = json.Unmarshal(body, &keySet)
	if err != nil {
		return nil, errors.Errorf("failed to decode keys: %v %s", err, body)
	}
	return keySet.Keys, nil
}
