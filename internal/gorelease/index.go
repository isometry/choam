// Package gorelease answers "what was the latest stable Go release at time
// T?" and "what is the latest stable Go release available now?", optionally
// constrained to a minor series (e.g. "1.24"). It is backed by the Go module
// proxy's golang.org/toolchain pseudo-module, which lists one module version
// per Go release x platform and exposes each release's publish time via its
// ".info" endpoint.
//
// Limitations:
//   - The golang.org/toolchain module only covers Go 1.21 and later
//     (released August 2023); earlier releases are invisible to this index.
//   - Only stable releases are indexed. rc and beta pre-releases are
//     excluded entirely, both from LatestAsOf and LatestAvailable results.
package gorelease

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/isometry/choam/internal/goversion"
)

const (
	// defaultBaseURL is the default Go module proxy used to source release
	// data.
	defaultBaseURL = "https://proxy.golang.org"

	// defaultTimeout is used for the HTTP client NewIndex installs when
	// called with a nil *http.Client.
	defaultTimeout = 30 * time.Second

	// maxBodyBytes bounds how much of any single response body is read, as
	// a defensive measure against unexpectedly large or malicious
	// responses (mirrors internal/scan's conventions).
	maxBodyBytes = 10 << 20 // 10MB

	toolchainModulePath = "golang.org/toolchain"
)

// listLineRe matches a single line of the golang.org/toolchain module's
// @v/list output, e.g. "v0.0.1-go1.24.5.linux-amd64" or
// "v0.0.1-go1.25rc1.linux-amd64". Capture groups: (1) the "go"-prefixed
// release version, including any rc/beta suffix, (2) GOOS, (3) GOARCH.
var listLineRe = regexp.MustCompile(`^v0\.0\.1-(go1(?:\.\d+){1,2}(?:(?:rc|beta)\d+)?)\.([a-z0-9]+)-([a-z0-9]+)$`)

// prereleaseSuffixRe matches a trailing rc/beta pre-release suffix on a bare
// Go version, e.g. the "rc1" in "1.25rc1".
var prereleaseSuffixRe = regexp.MustCompile(`(rc|beta)\d+$`)

// ErrNoReleases indicates that no stable Go release matches the requested
// constraint - e.g. an unknown minor series, or one that only ever shipped
// rc/beta releases (and therefore has no stable entries in the index).
var ErrNoReleases = errors.New("gorelease: no matching stable Go releases")

// Index is a lazily-populated, memoized view over the golang.org/toolchain
// module's release list. It answers point-in-time "latest stable Go
// release" queries without re-fetching data it has already resolved.
//
// An Index is safe for concurrent use.
type Index struct {
	httpClient *http.Client
	baseURL    string

	mu       sync.Mutex
	loaded   bool
	loadErr  error
	releases map[string]string    // bare release version (e.g. "1.24.5") -> full toolchain module version chosen for .info fetches
	times    map[string]time.Time // bare release version -> memoized publish time
}

// NewIndex returns an Index backed by proxy.golang.org. A nil httpClient
// falls back to a default client with a ~30s timeout.
func NewIndex(httpClient *http.Client) *Index {
	return newIndexWithBaseURL(httpClient, defaultBaseURL)
}

// newIndexWithBaseURL is the seam tests use to point an Index at an
// httptest.Server instead of the real module proxy.
func newIndexWithBaseURL(httpClient *http.Client, baseURL string) *Index {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &Index{
		httpClient: httpClient,
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		times:      make(map[string]time.Time),
	}
}

// LatestAvailable returns the highest stable Go release (bare form, e.g.
// "1.24.5") within minorConstraint (e.g. "1.24"; empty means unconstrained).
// It requires only the release list, never a .info fetch.
func (ix *Index) LatestAvailable(ctx context.Context, minorConstraint string) (string, error) {
	if err := ix.ensureLoaded(ctx); err != nil {
		return "", err
	}

	ix.mu.Lock()
	candidates := ix.constrainedVersionsLocked(minorConstraint)
	ix.mu.Unlock()

	if len(candidates) == 0 {
		return "", fmt.Errorf("%w for constraint %q", ErrNoReleases, minorConstraint)
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if goversion.Compare(c, best) > 0 {
			best = c
		}
	}
	return best, nil
}

// LatestAsOf returns the highest stable Go release (bare form, e.g.
// "1.24.5") whose publish time is <= t, restricted to minorConstraint
// (e.g. "1.24") when non-empty. If t predates every matching release, the
// OLDEST matching release is returned instead of an error: callers use this
// to detect stdlib exposure, so it is safer to over-detect ("this looks
// like an old Go release") than to silently miss a release entirely.
func (ix *Index) LatestAsOf(ctx context.Context, t time.Time, minorConstraint string) (string, error) {
	if err := ix.ensureLoaded(ctx); err != nil {
		return "", err
	}

	ix.mu.Lock()
	candidates := ix.constrainedVersionsLocked(minorConstraint)
	ix.mu.Unlock()

	if len(candidates) == 0 {
		return "", fmt.Errorf("%w for constraint %q", ErrNoReleases, minorConstraint)
	}

	sort.Slice(candidates, func(i, j int) bool {
		return goversion.Compare(candidates[i], candidates[j]) > 0
	})
	oldest := candidates[len(candidates)-1]

	for _, release := range candidates {
		releaseTime, err := ix.releaseTime(ctx, release)
		if err != nil {
			return "", err
		}
		if !releaseTime.After(t) {
			return release, nil
		}
	}

	// t predates every matching release: fail toward "old Go".
	return oldest, nil
}

// ensureLoaded fetches and parses @v/list exactly once, memoizing either
// the parsed release set or the error for all subsequent calls.
func (ix *Index) ensureLoaded(ctx context.Context) error {
	ix.mu.Lock()
	defer ix.mu.Unlock()

	if ix.loaded {
		return ix.loadErr
	}
	ix.loaded = true

	releases, err := ix.fetchList(ctx)
	if err != nil {
		ix.loadErr = fmt.Errorf("loading %s release list: %w", toolchainModulePath, err)
		return ix.loadErr
	}
	ix.releases = releases
	return nil
}

// constrainedVersionsLocked returns the bare release versions matching
// minorConstraint (all releases when empty). Callers must hold ix.mu.
func (ix *Index) constrainedVersionsLocked(minorConstraint string) []string {
	versions := make([]string, 0, len(ix.releases))
	for bare := range ix.releases {
		if minorConstraint != "" && goversion.Minor(bare) != minorConstraint {
			continue
		}
		versions = append(versions, bare)
	}
	return versions
}

// releaseTime returns the memoized publish time for a bare release version,
// fetching and caching it via .info on first use.
func (ix *Index) releaseTime(ctx context.Context, bareVersion string) (time.Time, error) {
	ix.mu.Lock()
	if tm, ok := ix.times[bareVersion]; ok {
		ix.mu.Unlock()
		return tm, nil
	}
	fullVersion, ok := ix.releases[bareVersion]
	ix.mu.Unlock()

	if !ok {
		return time.Time{}, fmt.Errorf("gorelease: unknown release %q", bareVersion)
	}

	tm, err := ix.fetchInfoTime(ctx, fullVersion)
	if err != nil {
		return time.Time{}, fmt.Errorf("fetching release info for %s: %w", bareVersion, err)
	}

	ix.mu.Lock()
	ix.times[bareVersion] = tm
	ix.mu.Unlock()

	return tm, nil
}

// fetchList retrieves and parses the golang.org/toolchain module's
// @v/list, deduping release x platform entries down to one full module
// version per bare release version and excluding rc/beta pre-releases.
func (ix *Index) fetchList(ctx context.Context) (map[string]string, error) {
	body, err := ix.get(ctx, "/"+toolchainModulePath+"/@v/list")
	if err != nil {
		return nil, fmt.Errorf("fetching release list: %w", err)
	}

	releases := make(map[string]string)
	haveLinuxAmd64 := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		m := listLineRe.FindStringSubmatch(line)
		if m == nil {
			continue // malformed line: skip silently
		}
		goVersion, osName, arch := m[1], m[2], m[3]

		bare := strings.TrimPrefix(goVersion, "go")
		if prereleaseSuffixRe.MatchString(bare) {
			continue // rc/beta pre-release: excluded from the index
		}
		if !goversion.IsValid(bare) {
			continue // defensive: shouldn't happen given the regex above
		}

		isLinuxAmd64 := osName == "linux" && arch == "amd64"

		if _, seen := releases[bare]; !seen {
			releases[bare] = line
			haveLinuxAmd64[bare] = isLinuxAmd64
			continue
		}
		if isLinuxAmd64 && !haveLinuxAmd64[bare] {
			releases[bare] = line
			haveLinuxAmd64[bare] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning release list: %w", err)
	}

	return releases, nil
}

// releaseInfo mirrors the JSON shape of the module proxy's .info endpoint.
type releaseInfo struct {
	Version string
	Time    time.Time
}

// fetchInfoTime retrieves and parses the .info document for a full
// toolchain module version, returning its publish time.
func (ix *Index) fetchInfoTime(ctx context.Context, fullVersion string) (time.Time, error) {
	path := fmt.Sprintf("/%s/@v/%s.info", toolchainModulePath, fullVersion)

	body, err := ix.get(ctx, path)
	if err != nil {
		return time.Time{}, err
	}

	var info releaseInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return time.Time{}, fmt.Errorf("decoding release info for %s: %w", fullVersion, err)
	}
	if info.Time.IsZero() {
		return time.Time{}, fmt.Errorf("release info for %s is missing a Time field", fullVersion)
	}

	return info.Time, nil
}

// get performs a GET request against baseURL+path and returns the
// (size-limited) response body, treating any non-200 status as an error.
func (ix *Index) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ix.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", path, err)
	}

	resp, err := ix.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request for %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status for %s: HTTP %d", path, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response body for %s: %w", path, err)
	}

	return body, nil
}
