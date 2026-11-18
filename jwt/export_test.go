package jwt

import "time"

// SetClock replaces the clock of r. Call it before the first lookup.
func (r *RemoteKeySet) SetClock(now func() time.Time) {
	r.now = now
}

// Fetches returns the number of fetches of r that have completed.
func (r *RemoteKeySet) Fetches() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fetches
}

// CacheTTL returns the lifetime given to the cached keys, measured from the
// end of the last fetch; it is meaningful when that fetch succeeded.
func (r *RemoteKeySet) CacheTTL() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.expiresAt.Sub(r.lastFetch)
}

// Inflight reports whether a fetch of r is in flight.
func (r *RemoteKeySet) Inflight() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.inflight != nil
}
