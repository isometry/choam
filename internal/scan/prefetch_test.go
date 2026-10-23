package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"osv.dev/bindings/go/api"
)

// fetchCountingServer serves querybatch with the given summaries and GET
// /v1/vulns/{id} from records, counting requests per ID and the peak number
// in flight. status, when set, overrides a GET's response code (hit is that
// ID's 1-based request number).
type fetchCountingServer struct {
	records map[string]*osvschema.Vulnerability
	order   []string // summary order in querybatch responses
	delay   time.Duration
	status  func(id string, hit int) int

	mu       sync.Mutex
	hits     map[string]int
	inflight atomic.Int32
	peak     atomic.Int32
}

func newFetchCountingServer(ids ...string) *fetchCountingServer {
	s := &fetchCountingServer{records: make(map[string]*osvschema.Vulnerability), hits: make(map[string]int)}
	s.order = ids
	for i, id := range ids {
		s.records[id] = mockVulnerability(id, "Go", "example.com/lib", fmt.Sprintf("1.%d.0", i+1))
	}
	return s
}

func (s *fetchCountingServer) client() *http.Client {
	return newMockHTTPClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v1/querybatch") {
			var vulns []*osvschema.Vulnerability
			for _, id := range s.order {
				vulns = append(vulns, &osvschema.Vulnerability{Id: id})
			}
			writeProto(w, &api.BatchVulnerabilityList{Results: []*api.VulnerabilityList{{Vulns: vulns}}})
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		n := s.inflight.Add(1)
		defer s.inflight.Add(-1)
		for peak := s.peak.Load(); n > peak && !s.peak.CompareAndSwap(peak, n); peak = s.peak.Load() {
		}
		time.Sleep(s.delay)
		s.mu.Lock()
		s.hits[id]++
		hit := s.hits[id]
		s.mu.Unlock()
		if s.status != nil {
			if code := s.status(id, hit); code != http.StatusOK {
				w.WriteHeader(code)
				return
			}
		}
		writeProto(w, s.records[id])
	}))
}

func (s *fetchCountingServer) hitCount(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[id]
}

func withConcurrency(t *testing.T, n int) {
	t.Helper()
	old := osvFetchConcurrency
	osvFetchConcurrency = n
	t.Cleanup(func() { osvFetchConcurrency = old })
}

func TestPrefetchAdvisories_FetchesEachIDOnce(t *testing.T) {
	srv := newFetchCountingServer("GO-1", "GO-2", "GO-3", "GO-4")
	scanner := newTestScanner(srv.client())
	scanner.cache.SetAdvisory("GO-4", srv.records["GO-4"])

	scanner.PrefetchAdvisories(t.Context(), []string{"GO-1", "GO-2", "GO-1", "GO-3", "GO-2", "GO-4"})

	for _, id := range []string{"GO-1", "GO-2", "GO-3"} {
		assert.Equal(t, 1, srv.hitCount(id), id)
		_, cached := scanner.cache.GetAdvisory(id)
		assert.True(t, cached, id)
	}
	assert.Zero(t, srv.hitCount("GO-4"), "an already cached record is not fetched")
}

func TestPrefetchAdvisories_BoundedConcurrency(t *testing.T) {
	withConcurrency(t, 3)
	ids := make([]string, 12)
	for i := range ids {
		ids[i] = fmt.Sprintf("GO-%02d", i)
	}
	srv := newFetchCountingServer(ids...)
	srv.delay = 20 * time.Millisecond
	newTestScanner(srv.client()).PrefetchAdvisories(t.Context(), ids)

	assert.Equal(t, int32(3), srv.peak.Load(), "requests overlap, up to the limit and no further")
}

func TestHydrateVulnerability_CollapsesConcurrentLookups(t *testing.T) {
	srv := newFetchCountingServer("GO-1")
	srv.delay = 100 * time.Millisecond
	scanner := newTestScanner(srv.client())

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			rec, err := scanner.Advisory(t.Context(), "GO-1")
			assert.NoError(t, err)
			assert.Equal(t, "GO-1", rec.GetId())
		})
	}
	wg.Wait()

	assert.Equal(t, 1, srv.hitCount("GO-1"))
}

// The written specs derive from these results, so they must not depend on
// how many lookups overlap.
func TestScanPackages_IndependentOfFetchConcurrency(t *testing.T) {
	ids := make([]string, 9)
	for i := range ids {
		ids[i] = fmt.Sprintf("GO-2026-%04d", i+1)
	}
	scan := func(limit int) string {
		withConcurrency(t, limit)
		srv := newFetchCountingServer(ids...)
		result, err := newTestScanner(srv.client()).ScanPackages(t.Context(), []Package{{Name: "example.com/lib", Version: "v1.0.0", Ecosystem: "Go"}})
		require.NoError(t, err)
		b, err := json.Marshal(result)
		require.NoError(t, err)
		return string(b)
	}
	assert.Equal(t, scan(1), scan(8))
}

// A lookup that keeps failing is only warmed, not swallowed: the ordered pass
// repeats it and fails the scan, as it does without any prefetch.
func TestScanPackages_PersistentFailureStillFailsClosed(t *testing.T) {
	srv := newFetchCountingServer("GO-1", "GO-2", "GO-3")
	srv.status = func(id string, _ int) int {
		if id == "GO-2" {
			return http.StatusInternalServerError
		}
		return http.StatusOK
	}
	result, err := newTestScanner(srv.client()).ScanPackages(t.Context(), []Package{{Name: "example.com/lib", Version: "v1.0.0", Ecosystem: "Go"}})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetching advisory GO-2")
	assert.Empty(t, result.Vulnerabilities, "a failed lookup must not read as a clean scan")
	assert.GreaterOrEqual(t, srv.hitCount("GO-2"), 2, "prefetch, then the ordered pass")
}

func TestScanPackages_TransientFailureRetriedDuringPrefetch(t *testing.T) {
	srv := newFetchCountingServer("GO-1", "GO-2", "GO-3")
	srv.status = func(id string, hit int) int {
		if id == "GO-2" && hit == 1 {
			return http.StatusServiceUnavailable
		}
		return http.StatusOK
	}
	scanner := newTestScanner(srv.client())
	scanner.client.attempts = 3
	scanner.client.backoff = func(int) time.Duration { return 0 }

	result, err := scanner.ScanPackages(t.Context(), []Package{{Name: "example.com/lib", Version: "v1.0.0", Ecosystem: "Go"}})

	require.NoError(t, err)
	assert.Len(t, result.Vulnerabilities, 3)
	assert.Equal(t, 2, srv.hitCount("GO-2"), "one 503, one retry; the ordered pass hits the cache")
}

func TestPrefetchAdvisories_StopsWhenCancelled(t *testing.T) {
	withConcurrency(t, 1)
	ids := make([]string, 20)
	for i := range ids {
		ids[i] = fmt.Sprintf("GO-%02d", i)
	}

	t.Run("already cancelled", func(t *testing.T) {
		srv := newFetchCountingServer(ids...)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		newTestScanner(srv.client()).PrefetchAdvisories(ctx, ids)
		for _, id := range ids {
			assert.Zero(t, srv.hitCount(id), id)
		}
	})

	t.Run("cancelled mid-way", func(t *testing.T) {
		srv := newFetchCountingServer(ids...)
		ctx, cancel := context.WithCancel(t.Context())
		srv.status = func(string, int) int { cancel(); return http.StatusOK }
		newTestScanner(srv.client()).PrefetchAdvisories(ctx, ids)
		total := 0
		for _, id := range ids {
			total += srv.hitCount(id)
		}
		assert.LessOrEqual(t, total, 2, "the pool stops submitting once ctx is done")
	})
}

// An OSV outage must cost one failed lookup, not one retry cycle per ID: the
// first failure ends the warm-up, and the ordered pass reports it.
func TestPrefetchAdvisories_StopsAfterFirstFailure(t *testing.T) {
	withConcurrency(t, 1)
	ids := make([]string, 30)
	for i := range ids {
		ids[i] = fmt.Sprintf("GO-%02d", i)
	}
	srv := newFetchCountingServer(ids...)
	srv.status = func(string, int) int { return http.StatusInternalServerError }

	newTestScanner(srv.client()).PrefetchAdvisories(t.Context(), ids)

	total := 0
	for _, id := range ids {
		total += srv.hitCount(id)
	}
	assert.LessOrEqual(t, total, 2, "no further lookup is started once one has failed")
}
