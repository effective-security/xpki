package jwt

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCacheLifetime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	httpDate := func(t time.Time) string { return t.Format(http.TimeFormat) }

	tests := []struct {
		name     string
		header   map[string][]string
		lifetime time.Duration
		ok       bool
	}{
		{name: "no headers"},
		{
			name:     "max-age",
			header:   map[string][]string{headerCacheControl: {"max-age=600"}},
			lifetime: 600 * time.Second,
			ok:       true,
		},
		{
			name:     "google",
			header:   map[string][]string{headerCacheControl: {"public, max-age=21065, must-revalidate, no-transform"}},
			lifetime: 21065 * time.Second,
			ok:       true,
		},
		{
			name:     "directive names are case-insensitive",
			header:   map[string][]string{headerCacheControl: {"MAX-AGE=60"}},
			lifetime: time.Minute,
			ok:       true,
		},
		{
			name:     "quoted max-age",
			header:   map[string][]string{headerCacheControl: {`max-age="120"`}},
			lifetime: 2 * time.Minute,
			ok:       true,
		},
		{
			name:     "first max-age wins",
			header:   map[string][]string{headerCacheControl: {"max-age=60, max-age=600"}},
			lifetime: time.Minute,
			ok:       true,
		},
		{
			name:   "no-cache in a later line wins over max-age",
			header: map[string][]string{headerCacheControl: {"max-age=600", "no-cache"}},
			ok:     true,
		},
		{
			name:   "no-store",
			header: map[string][]string{headerCacheControl: {"no-store"}},
			ok:     true,
		},
		{
			name:   "qualified no-cache",
			header: map[string][]string{headerCacheControl: {`no-cache="Set-Cookie", max-age=600`}},
			ok:     true,
		},
		{
			name:   "negative max-age is stale",
			header: map[string][]string{headerCacheControl: {"max-age=-1"}},
			ok:     true,
		},
		{
			name:   "signed max-age is stale",
			header: map[string][]string{headerCacheControl: {"max-age=+5"}},
			ok:     true,
		},
		{
			name:   "non-numeric max-age is stale",
			header: map[string][]string{headerCacheControl: {"max-age=abc"}},
			ok:     true,
		},
		{
			name:   "empty max-age is stale",
			header: map[string][]string{headerCacheControl: {"max-age="}},
			ok:     true,
		},
		{
			name:     "huge max-age is capped",
			header:   map[string][]string{headerCacheControl: {"max-age=99999999999999999999"}},
			lifetime: maxDeltaSeconds * time.Second,
			ok:       true,
		},
		{
			name:   "s-maxage is for shared caches",
			header: map[string][]string{headerCacheControl: {"public, s-maxage=600"}},
		},
		{
			name: "max-age wins over Expires",
			header: map[string][]string{
				headerCacheControl: {"max-age=60"},
				headerExpires:      {httpDate(now.Add(time.Hour))},
			},
			lifetime: time.Minute,
			ok:       true,
		},
		{
			name: "Expires minus Date, less the apparent age",
			header: map[string][]string{
				headerCacheControl: {"public"},
				headerDate:         {httpDate(now.Add(-10 * time.Minute))},
				headerExpires:      {httpDate(now.Add(20 * time.Minute))},
			},
			lifetime: 20 * time.Minute,
			ok:       true,
		},
		{
			name: "Expires already passed by its Date",
			header: map[string][]string{
				headerCacheControl: {"public"},
				headerDate:         {httpDate(now.Add(-time.Hour))},
				headerExpires:      {httpDate(now.Add(-30 * time.Minute))},
			},
			ok: true,
		},
		{
			name: "max-age less the apparent age",
			header: map[string][]string{
				headerCacheControl: {"max-age=3600"},
				headerDate:         {httpDate(now.Add(-50 * time.Minute))},
			},
			lifetime: 10 * time.Minute,
			ok:       true,
		},
		{
			name: "Age above the apparent age",
			header: map[string][]string{
				headerCacheControl: {"max-age=600"},
				headerDate:         {httpDate(now.Add(-time.Minute))},
				headerAge:          {"300"},
			},
			lifetime: 300 * time.Second,
			ok:       true,
		},
		{
			name: "apparent age above Age",
			header: map[string][]string{
				headerCacheControl: {"max-age=600"},
				headerDate:         {httpDate(now.Add(-5 * time.Minute))},
				headerAge:          {"60"},
			},
			lifetime: 300 * time.Second,
			ok:       true,
		},
		{
			name: "Date ahead of now is no age",
			header: map[string][]string{
				headerCacheControl: {"max-age=600"},
				headerDate:         {httpDate(now.Add(time.Hour))},
			},
			lifetime: 600 * time.Second,
			ok:       true,
		},
		{
			name:     "Expires without Date",
			header:   map[string][]string{headerExpires: {httpDate(now.Add(20 * time.Minute))}},
			lifetime: 20 * time.Minute,
			ok:       true,
		},
		{
			name: "Expires with an invalid Date",
			header: map[string][]string{
				headerDate:    {"yesterday"},
				headerExpires: {httpDate(now.Add(20 * time.Minute))},
			},
			lifetime: 20 * time.Minute,
			ok:       true,
		},
		{
			name:   "Expires in the past",
			header: map[string][]string{headerExpires: {httpDate(now.Add(-time.Minute))}},
			ok:     true,
		},
		{
			name:   "invalid Expires is in the past",
			header: map[string][]string{headerExpires: {"0"}},
			ok:     true,
		},
		{
			name:   "empty Expires is in the past",
			header: map[string][]string{headerExpires: {""}},
			ok:     true,
		},
		{
			name: "Age is subtracted",
			header: map[string][]string{
				headerCacheControl: {"max-age=600"},
				headerAge:          {"100"},
			},
			lifetime: 500 * time.Second,
			ok:       true,
		},
		{
			name: "Age is subtracted from Expires",
			header: map[string][]string{
				headerExpires: {httpDate(now.Add(20 * time.Minute))},
				headerAge:     {"60"},
			},
			lifetime: 19 * time.Minute,
			ok:       true,
		},
		{
			name: "Age above the lifetime",
			header: map[string][]string{
				headerCacheControl: {"max-age=600"},
				headerAge:          {"1000"},
			},
			ok: true,
		},
		{
			name: "list-valued Age uses its first member",
			header: map[string][]string{
				headerCacheControl: {"max-age=600"},
				headerAge:          {"100, 200"},
			},
			lifetime: 500 * time.Second,
			ok:       true,
		},
		{
			name: "invalid Age is ignored",
			header: map[string][]string{
				headerCacheControl: {"max-age=600"},
				headerAge:          {"-5"},
			},
			lifetime: 600 * time.Second,
			ok:       true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lifetime, ok := cacheLifetime(http.Header(tc.header), now)
			assert.Equal(t, tc.lifetime, lifetime)
			assert.Equal(t, tc.ok, ok)
		})
	}
}
