package gorelease

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixtureServer is a minimal in-memory stand-in for proxy.golang.org's
// golang.org/toolchain module endpoints, with request counting so tests can
// assert on memoization and fetch behaviour without touching the network.
type fixtureServer struct {
	listBody   string
	listStatus int // 0 means 200 OK
	infoTimes  map[string]time.Time
	infoStatus map[string]int
	malformed  map[string]bool

	mu         sync.Mutex
	listCount  int
	infoCounts map[string]int
}

func newFixtureServer(listBody string, infoTimes map[string]time.Time) *fixtureServer {
	return &fixtureServer{
		listBody:   listBody,
		infoTimes:  infoTimes,
		infoStatus: map[string]int{},
		malformed:  map[string]bool{},
		infoCounts: map[string]int{},
	}
}

func (fs *fixtureServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/golang.org/toolchain/@v/list":
		fs.mu.Lock()
		fs.listCount++
		status := fs.listStatus
		fs.mu.Unlock()

		if status != 0 {
			http.Error(w, "boom", status)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(fs.listBody))

	case strings.HasSuffix(r.URL.Path, ".info"):
		full := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/golang.org/toolchain/@v/"), ".info")

		fs.mu.Lock()
		fs.infoCounts[full]++
		status, hasStatus := fs.infoStatus[full]
		isMalformed := fs.malformed[full]
		fs.mu.Unlock()

		if hasStatus {
			http.Error(w, "boom", status)
			return
		}
		if isMalformed {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not valid json"))
			return
		}

		tm, ok := fs.infoTimes[full]
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := json.Marshal(map[string]string{
			"Version": full,
			"Time":    tm.Format(time.RFC3339),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)

	default:
		http.NotFound(w, r)
	}
}

func (fs *fixtureServer) totalInfoRequests() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	total := 0
	for _, c := range fs.infoCounts {
		total += c
	}
	return total
}

func (fs *fixtureServer) infoRequestsFor(full string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.infoCounts[full]
}

func (fs *fixtureServer) listRequests() int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.listCount
}

// Shared fixture data used by most tests below.
//
// Dedup expectations baked into this fixture:
//   - 1.23.0, 1.23.4, 1.24.0, 1.24.5, 1.24.8, 1.25.0 all have a linux-amd64
//     entry, so that's the one that should be chosen for .info fetches even
//     though some (1.24.0) list darwin-arm64 first.
//   - 1.24.2 has NO linux-amd64 entry (darwin-arm64 and windows-amd64 only),
//     so the first-seen platform (darwin-arm64) must be chosen.
//   - 1.25rc1, 1.25rc2, 1.26beta1 are pre-releases and must be excluded
//     entirely, even though 1.25rc1/1.25rc2 would otherwise be the highest
//     "1.25" versions.
//   - Assorted malformed lines must be silently skipped.
const fixtureList = `v0.0.1-go1.23.0.linux-amd64
v0.0.1-go1.23.0.darwin-arm64
v0.0.1-go1.23.4.linux-amd64
v0.0.1-go1.24.0.darwin-arm64
v0.0.1-go1.24.0.linux-amd64
v0.0.1-go1.24.2.darwin-arm64
v0.0.1-go1.24.2.windows-amd64
v0.0.1-go1.24.5.darwin-arm64
v0.0.1-go1.24.5.linux-amd64
v0.0.1-go1.24.5.windows-amd64
v0.0.1-go1.24.8.linux-amd64
v0.0.1-go1.25.0.linux-amd64
v0.0.1-go1.25rc1.linux-amd64
v0.0.1-go1.25rc2.darwin-arm64
v0.0.1-go1.26beta1.linux-amd64
not-a-toolchain-line-at-all
v0.0.1-badformat.linux-amd64
v0.0.1-go1.24.5

`

func fixtureInfoTimes() map[string]time.Time {
	mustParse := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			panic(err)
		}
		return tm
	}
	return map[string]time.Time{
		"v0.0.1-go1.23.0.linux-amd64":  mustParse("2023-08-15T00:00:00Z"),
		"v0.0.1-go1.23.4.linux-amd64":  mustParse("2024-12-03T00:00:00Z"),
		"v0.0.1-go1.24.0.linux-amd64":  mustParse("2025-02-11T00:00:00Z"),
		"v0.0.1-go1.24.2.darwin-arm64": mustParse("2025-03-15T00:00:00Z"),
		"v0.0.1-go1.24.5.linux-amd64":  mustParse("2025-06-05T18:21:16Z"),
		"v0.0.1-go1.24.8.linux-amd64":  mustParse("2025-09-02T00:00:00Z"),
		"v0.0.1-go1.25.0.linux-amd64":  mustParse("2025-09-10T00:00:00Z"),
	}
}

func newTestIndex(t *testing.T, fs *fixtureServer) (*Index, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(fs)
	t.Cleanup(server.Close)
	return newIndexWithBaseURL(nil, server.URL), server
}

func TestLatestAvailable_DedupeAndFilter(t *testing.T) {
	fs := newFixtureServer(fixtureList, fixtureInfoTimes())
	ix, _ := newTestIndex(t, fs)
	ctx := context.Background()

	tests := []struct {
		name       string
		constraint string
		want       string
		wantErr    bool
	}{
		{name: "unconstrained picks global max, excludes rc/beta", constraint: "", want: "1.25.0"},
		{name: "1.24 series max", constraint: "1.24", want: "1.24.8"},
		{name: "1.23 series max", constraint: "1.23", want: "1.23.4"},
		{name: "rc-only series has no stable release", constraint: "1.26", wantErr: true},
		{name: "unknown minor", constraint: "9.9", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ix.LatestAvailable(ctx, tt.constraint)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("LatestAvailable(%q) = %q, want error", tt.constraint, got)
				}
				if !errors.Is(err, ErrNoReleases) {
					t.Errorf("LatestAvailable(%q) error = %v, want wrapping ErrNoReleases", tt.constraint, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LatestAvailable(%q) unexpected error: %v", tt.constraint, err)
			}
			if got != tt.want {
				t.Errorf("LatestAvailable(%q) = %q, want %q", tt.constraint, got, tt.want)
			}
		})
	}

	if n := fs.totalInfoRequests(); n != 0 {
		t.Errorf("LatestAvailable made %d .info requests, want 0", n)
	}
	if n := fs.listRequests(); n != 1 {
		t.Errorf("@v/list fetched %d times across LatestAvailable calls, want exactly 1 (memoized)", n)
	}
}

func TestLatestAsOf_Boundaries(t *testing.T) {
	fs := newFixtureServer(fixtureList, fixtureInfoTimes())
	ix, _ := newTestIndex(t, fs)
	ctx := context.Background()

	mustParse := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("parsing test time %q: %v", s, err)
		}
		return tm
	}

	tests := []struct {
		name       string
		t          time.Time
		constraint string
		want       string
		wantErr    bool
	}{
		{
			name:       "exact boundary: t equals release time",
			t:          mustParse("2025-02-11T00:00:00Z"),
			constraint: "",
			want:       "1.24.0",
		},
		{
			name:       "mid-window unconstrained",
			t:          mustParse("2025-07-01T00:00:00Z"),
			constraint: "",
			want:       "1.24.5",
		},
		{
			name:       "mid-window constrained (non-linux-amd64 dedup winner)",
			t:          mustParse("2025-04-01T00:00:00Z"),
			constraint: "1.24",
			want:       "1.24.2",
		},
		{
			name:       "t before every matching release returns oldest",
			t:          mustParse("2000-01-01T00:00:00Z"),
			constraint: "",
			want:       "1.23.0",
		},
		{
			name:       "t before every matching release, constrained",
			t:          mustParse("2000-01-01T00:00:00Z"),
			constraint: "1.24",
			want:       "1.24.0",
		},
		{
			name:       "constraint with no stable matches",
			t:          mustParse("2025-01-01T00:00:00Z"),
			constraint: "1.26",
			wantErr:    true,
		},
		{
			name:       "t far in the future returns global max",
			t:          mustParse("2099-01-01T00:00:00Z"),
			constraint: "",
			want:       "1.25.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ix.LatestAsOf(ctx, tt.t, tt.constraint)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("LatestAsOf(%s, %q) = %q, want error", tt.t, tt.constraint, got)
				}
				if !errors.Is(err, ErrNoReleases) {
					t.Errorf("LatestAsOf(%s, %q) error = %v, want wrapping ErrNoReleases", tt.t, tt.constraint, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LatestAsOf(%s, %q) unexpected error: %v", tt.t, tt.constraint, err)
			}
			if got != tt.want {
				t.Errorf("LatestAsOf(%s, %q) = %q, want %q", tt.t, tt.constraint, got, tt.want)
			}
		})
	}

	if n := fs.listRequests(); n != 1 {
		t.Errorf("@v/list fetched %d times across all LatestAsOf calls, want exactly 1 (memoized)", n)
	}
}

func TestLatestAsOf_Memoization(t *testing.T) {
	fs := newFixtureServer(fixtureList, fixtureInfoTimes())
	ix, _ := newTestIndex(t, fs)
	ctx := context.Background()

	// First call: unconstrained, t=2025-08-20 lands between 1.24.8's and
	// 1.25.0's release times but before 1.24.8 (see fixture times), so it
	// must walk 1.25.0 -> 1.24.8 -> 1.24.5 before finding a match.
	got, err := ix.LatestAsOf(ctx, mustParseRFC3339(t, "2025-08-20T00:00:00Z"), "")
	if err != nil {
		t.Fatalf("first LatestAsOf call failed: %v", err)
	}
	if got != "1.24.5" {
		t.Fatalf("first LatestAsOf call = %q, want %q", got, "1.24.5")
	}

	for _, full := range []string{
		"v0.0.1-go1.25.0.linux-amd64",
		"v0.0.1-go1.24.8.linux-amd64",
		"v0.0.1-go1.24.5.linux-amd64",
	} {
		if n := fs.infoRequestsFor(full); n != 1 {
			t.Errorf("after first call, .info requests for %s = %d, want 1", full, n)
		}
	}
	firstCallTotal := fs.totalInfoRequests()

	// Second call only needs releases whose times are already memoized from
	// the first call (1.25.0 and 1.24.8), so it must not issue any new
	// .info requests at all.
	got, err = ix.LatestAsOf(ctx, mustParseRFC3339(t, "2025-09-05T00:00:00Z"), "")
	if err != nil {
		t.Fatalf("second LatestAsOf call failed: %v", err)
	}
	if got != "1.24.8" {
		t.Fatalf("second LatestAsOf call = %q, want %q", got, "1.24.8")
	}

	if n := fs.totalInfoRequests(); n != firstCallTotal {
		t.Errorf("second LatestAsOf call issued %d new .info requests, want 0 (all memoized)", n-firstCallTotal)
	}
	if n := fs.listRequests(); n != 1 {
		t.Errorf("@v/list fetched %d times, want exactly 1 across both calls", n)
	}
}

func TestErrorPaths(t *testing.T) {
	t.Run("500 on list", func(t *testing.T) {
		fs := newFixtureServer(fixtureList, fixtureInfoTimes())
		fs.listStatus = http.StatusInternalServerError
		ix, _ := newTestIndex(t, fs)

		if _, err := ix.LatestAvailable(context.Background(), ""); err == nil {
			t.Fatal("LatestAvailable() with 500 on @v/list = nil error, want error")
		}
	})

	t.Run("500 on info", func(t *testing.T) {
		fs := newFixtureServer(fixtureList, fixtureInfoTimes())
		fs.infoStatus["v0.0.1-go1.23.0.linux-amd64"] = http.StatusInternalServerError
		ix, _ := newTestIndex(t, fs)

		// Constrain to 1.23 so the only candidates are 1.23.0 and 1.23.4;
		// asking for a time before both forces a walk that reaches 1.23.0.
		_, err := ix.LatestAsOf(context.Background(), mustParseRFC3339(t, "2000-01-01T00:00:00Z"), "1.23")
		if err == nil {
			t.Fatal("LatestAsOf() with 500 on .info = nil error, want error")
		}
	})

	t.Run("malformed JSON info", func(t *testing.T) {
		fs := newFixtureServer(fixtureList, fixtureInfoTimes())
		fs.malformed["v0.0.1-go1.23.0.linux-amd64"] = true
		ix, _ := newTestIndex(t, fs)

		_, err := ix.LatestAsOf(context.Background(), mustParseRFC3339(t, "2000-01-01T00:00:00Z"), "1.23")
		if err == nil {
			t.Fatal("LatestAsOf() with malformed .info JSON = nil error, want error")
		}
	})

	t.Run("no panic on repeated calls after list failure", func(t *testing.T) {
		fs := newFixtureServer(fixtureList, fixtureInfoTimes())
		fs.listStatus = http.StatusInternalServerError
		ix, _ := newTestIndex(t, fs)

		for i := 0; i < 3; i++ {
			if _, err := ix.LatestAvailable(context.Background(), ""); err == nil {
				t.Fatal("expected persistent error after list failure")
			}
		}
	})
}

func TestNewIndex_NilClientDefaults(t *testing.T) {
	ix := NewIndex(nil)
	if ix == nil {
		t.Fatal("NewIndex(nil) returned nil")
	}
	if ix.httpClient == nil {
		t.Fatal("NewIndex(nil) did not install a default http.Client")
	}
	if ix.httpClient.Timeout <= 0 {
		t.Errorf("NewIndex(nil) default client has non-positive timeout: %v", ix.httpClient.Timeout)
	}
	if ix.baseURL != defaultBaseURL {
		t.Errorf("NewIndex(nil) baseURL = %q, want %q", ix.baseURL, defaultBaseURL)
	}
}

func TestNewIndex_CustomClientPreserved(t *testing.T) {
	custom := &http.Client{Timeout: 7 * time.Second}
	ix := NewIndex(custom)
	if ix.httpClient != custom {
		t.Error("NewIndex(custom) did not preserve the provided client")
	}
}

func mustParseRFC3339(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parsing test time %q: %v", s, err)
	}
	return tm
}
