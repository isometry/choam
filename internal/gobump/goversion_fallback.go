package gobump

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/isometry/choam/internal/gorelease"
	"github.com/isometry/choam/internal/goversion"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// defaultGoProxyURL is the module proxy the best-effort go-version fallback
// fetches candidate go.mod files from (overridden in tests via
// GoBumpApplier.goProxyURL).
const defaultGoProxyURL = "https://proxy.golang.org"

// fallbackGoVersionBudget bounds one modroot's whole fallback probe - it is
// best-effort by design (see fallbackRequiredGoVersion) and must never stall
// the apply phase.
const fallbackGoVersionBudget = 30 * time.Second

// maxGoModBytes caps how much of a proxy .mod response is read; real go.mod
// files are tiny, so anything beyond this is not one.
const maxGoModBytes = 1 << 20

// fallbackRequiredGoVersion computes, without simulation, the max go
// directive across the modroot's candidate deps' own go.mod files, fetched
// from the module proxy at proxyBaseURL. Candidates are the coordinates in
// DesiredDeps plus the "new@version" side of DesiredReplaces. Candidates
// whose module path skip reports true for (GOPRIVATE/GONOPROXY - see
// internal/goproxy.IsPrivate) are never fetched, since doing so would leak
// the private module's name and version to a public proxy and 404 anyway;
// skip may be nil to probe every candidate. This is best-effort and
// fail-open: it only sees direct candidates (not the resolved graph the
// simulation proves), individual fetch/parse failures are skipped with a
// debug log, and an error is returned only when nothing at all could be
// fetched (the caller warns and proceeds without a value) - the error notes
// how many candidates were skipped as private so an all-private modroot is
// reported honestly rather than silently omitting the raise.
func fallbackRequiredGoVersion(ctx context.Context, client *http.Client, proxyBaseURL string, m *ModrootAnalysis, skip func(modulePath string) bool) (string, error) {
	candidates := fallbackCandidates(m)
	if len(candidates) == 0 {
		return "", nil
	}

	ctx, cancel := context.WithTimeout(ctx, fallbackGoVersionBudget)
	defer cancel()

	var maxGo string
	fetched := 0
	skippedPrivate := 0
	for _, candidate := range candidates {
		if skip != nil && skip(candidate.module) {
			skippedPrivate++
			slog.Debug("go-version fallback: private module - skipping probe",
				"modroot", m.Modroot, "module", candidate.module, "version", candidate.version)
			continue
		}
		goDirective, err := fetchModGoDirective(ctx, client, proxyBaseURL, candidate.module, candidate.version)
		if err != nil {
			slog.Debug("go-version fallback: could not fetch candidate go.mod - skipping",
				"modroot", m.Modroot, "module", candidate.module, "version", candidate.version, "error", err)
			continue
		}
		fetched++
		maxGo = goversion.Max(maxGo, goDirective)
	}

	if fetched == 0 {
		if skippedPrivate > 0 {
			return "", fmt.Errorf("none of the %d candidate go.mod files could be fetched (%d private modules skipped)", len(candidates), skippedPrivate)
		}
		return "", fmt.Errorf("none of the %d candidate go.mod files could be fetched", len(candidates))
	}
	return maxGo, nil
}

// moduleVersion is one fallback candidate coordinate.
type moduleVersion struct {
	module  string
	version string
}

// fallbackCandidates projects a modroot's desired deps ("module@version") and
// replaces ("old=new@version", new side) onto deduplicated module@version
// coordinates, in declaration order.
func fallbackCandidates(m *ModrootAnalysis) []moduleVersion {
	seen := make(map[string]struct{}, len(m.DesiredDeps)+len(m.DesiredReplaces))
	candidates := make([]moduleVersion, 0, len(m.DesiredDeps)+len(m.DesiredReplaces))
	add := func(mod, version string) {
		if mod == "" || version == "" {
			return
		}
		key := mod + "@" + version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, moduleVersion{module: mod, version: version})
	}

	for _, dep := range m.DesiredDeps {
		if mod, version, ok := splitCoordVersion(dep); ok {
			add(mod, version)
		}
	}
	for _, replace := range m.DesiredReplaces {
		coord, version, ok := splitCoordVersion(replace)
		if !ok {
			continue
		}
		if _, newPath, found := strings.Cut(coord, "="); found {
			add(newPath, version)
		}
	}
	return candidates
}

// fetchModGoDirective fetches {proxy}/{module}/@v/{version}.mod and returns
// its go directive ("" when the file has none - very old modules).
func fetchModGoDirective(ctx context.Context, client *http.Client, proxyBaseURL, modulePath, version string) (string, error) {
	escapedPath, err := module.EscapePath(modulePath)
	if err != nil {
		return "", fmt.Errorf("escaping module path: %w", err)
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", fmt.Errorf("escaping version: %w", err)
	}

	url := fmt.Sprintf("%s/%s/@v/%s.mod", strings.TrimSuffix(proxyBaseURL, "/"), escapedPath, escapedVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGoModBytes))
	if err != nil {
		return "", err
	}
	modFile, err := modfile.ParseLax(modulePath+"@"+version+"/go.mod", body, nil)
	if err != nil {
		return "", fmt.Errorf("parsing go.mod: %w", err)
	}
	if modFile.Go == nil {
		return "", nil
	}
	return modFile.Go.Version, nil
}

// validateGoVersionFloor decides whether minor (a bare Go minor series, e.g.
// "1.26") should be trusted as a go-version floor, consulting the shared
// per-run gorelease.Index (see GoBumpApplier.releaseIndex). It implements the
// fail-open policy shared by both validation sites - the fallback probe
// result here in fallbackGoVersions, and the go-package pin floor write in
// reconcileGoPackagePins:
//
//   - index == nil (no Analyzer wired) or minor == "" (nothing to check):
//     always valid - nothing to validate against.
//   - gorelease.ErrNoReleases - a definitive "no stable release ever shipped
//     for this series" answer - rejects the candidate (valid=false,
//     offlineErr=nil). This is the case a hostile or typo'd upstream go
//     directive (e.g. "go 1.99") must not silently become a floor.
//   - any other error (the release index itself is unreachable) fails open
//     (valid=true) but returns the error so the caller can warn: this check
//     runs right after the same module proxy already served the go.mod
//     file(s) minor was derived from, so an index-unreachable-but-go.mod-
//     fetchable failure is rare, and rejecting a legitimate version over a
//     transient blip would regress the common raise.
func validateGoVersionFloor(ctx context.Context, index *gorelease.Index, minor string) (valid bool, offlineErr error) {
	if index == nil || minor == "" {
		return true, nil
	}
	if _, err := index.LatestAvailable(ctx, minor); err != nil {
		if errors.Is(err, gorelease.ErrNoReleases) {
			return false, nil
		}
		return true, err
	}
	return true, nil
}

// newFloorValidator returns a validateGoVersionFloor closure that memoizes
// results per minor - used by reconcileGoPackagePins' per-pin loop, where the
// same modroot floor commonly recurs across several pins and would otherwise
// repeat the same index lookup (and, on failure, the same warning).
func newFloorValidator(ctx context.Context, index *gorelease.Index) func(minor string) (valid bool, offlineErr error) {
	type result struct {
		valid      bool
		offlineErr error
	}
	cache := make(map[string]result)
	return func(minor string) (bool, error) {
		if cached, ok := cache[minor]; ok {
			return cached.valid, cached.offlineErr
		}
		valid, offlineErr := validateGoVersionFloor(ctx, index, minor)
		cache[minor] = result{valid: valid, offlineErr: offlineErr}
		return valid, offlineErr
	}
}
