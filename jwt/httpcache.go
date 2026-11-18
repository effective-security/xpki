package jwt

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerCacheControl = "Cache-Control"
	headerExpires      = "Expires"
	headerDate         = "Date"
	headerAge          = "Age"

	directiveMaxAge  = "max-age"
	directiveNoCache = "no-cache"
	directiveNoStore = "no-store"

	// maxDeltaSeconds caps a delta-seconds value, as RFC 9111 §1.2.2 allows.
	maxDeltaSeconds = 1 << 31
)

// cacheLifetime returns how long a response received at now stays fresh in
// a private cache (RFC 9111 §4.2): its freshness lifetime, the max-age
// directive, else Expires minus Date, less its age (responseAge). no-store
// and no-cache, an invalid max-age and an invalid Expires state a lifetime of
// zero. ok is false when the headers state no lifetime.
func cacheLifetime(h http.Header, now time.Time) (lifetime time.Duration, ok bool) {
	lifetime, ok = cacheControlLifetime(h)
	if !ok {
		lifetime, ok = expiresLifetime(h, now)
	}
	if !ok {
		return 0, false
	}
	return max(lifetime-responseAge(h, now), 0), true
}

// responseAge returns the age of a response received at now (RFC 9111
// §4.2.3): the greater of its Age header and its apparent age, now minus
// Date. The apparent age is zero without a valid Date or when Date is ahead
// of now. A list-valued Age uses its first member; an invalid one is zero.
func responseAge(h http.Header, now time.Time) time.Duration {
	ageValue, _, _ := strings.Cut(h.Get(headerAge), ",")
	age, _ := deltaSeconds(strings.TrimSpace(ageValue))
	if date, err := http.ParseTime(h.Get(headerDate)); err == nil {
		age = max(age, now.Sub(date))
	}
	return age
}

// cacheControlLifetime returns the lifetime that the Cache-Control
// directives state. The most restrictive directive wins, and the first
// max-age is used when it appears more than once.
func cacheControlLifetime(h http.Header) (time.Duration, bool) {
	var (
		lifetime time.Duration
		found    bool
	)
	for _, value := range h.Values(headerCacheControl) {
		for directive := range strings.SplitSeq(value, ",") {
			name, arg, _ := strings.Cut(strings.TrimSpace(directive), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case directiveNoStore, directiveNoCache:
				return 0, true
			case directiveMaxAge:
				if found {
					continue
				}
				found = true
				// An invalid max-age makes the response stale.
				lifetime, _ = deltaSeconds(strings.Trim(strings.TrimSpace(arg), `"`))
			}
		}
	}
	return lifetime, found
}

// expiresLifetime returns Expires minus Date (or now, without a valid Date).
// An Expires value that is not an HTTP date, an empty one included, is in the
// past (RFC 9111 §5.3).
func expiresLifetime(h http.Header, now time.Time) (time.Duration, bool) {
	values := h.Values(headerExpires)
	if len(values) == 0 {
		return 0, false
	}
	expires, err := http.ParseTime(values[0])
	if err != nil {
		return 0, true
	}
	date := now
	if d, err := http.ParseTime(h.Get(headerDate)); err == nil {
		date = d
	}
	return max(expires.Sub(date), 0), true
}

// deltaSeconds parses an RFC 9111 delta-seconds value: one or more digits,
// capped at maxDeltaSeconds.
func deltaSeconds(value string) (time.Duration, bool) {
	if value == "" || strings.TrimLeft(value, "0123456789") != "" {
		return 0, false
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds > maxDeltaSeconds {
		// Only a range error is possible after the digit check.
		seconds = maxDeltaSeconds
	}
	return time.Duration(seconds) * time.Second, true
}
