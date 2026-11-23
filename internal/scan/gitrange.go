package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
	"osv.dev/bindings/go/api"

	"github.com/isometry/choam/internal/goproxy"
	"github.com/isometry/choam/internal/logging"
)

// Git-range advisories.
//
// Some advisories (typically CNA-published CVEs for a Go module, e.g.
// HashiCorp's) reach OSV only as records with GIT commit ranges and no Go
// package, so a package@version query never returns them. OSV can still match
// them by commit: the module proxy names the commit a tagged version was cut
// from (.info "Origin.Hash"), and a commit query returns every record whose
// ranges contain it.
//
// A commit hit is scoped to the whole repository, not the module: every
// module of a monorepo (opentelemetry-go, aws-sdk-go-v2) would inherit all of
// its repo's advisories. So only a module at its repo root (Origin.Subdir
// empty) is considered, and only for records that no package-scoped record
// already covers (fixAccumulator.known) - a package-scoped record carries the
// curated module and import scoping and always wins.

const (
	// maxGitRangeWalk bounds the versions inspected per fix search.
	maxGitRangeWalk = 40

	// gitRangeSource marks a Vulnerability found by commit range.
	gitRangeSource = "osv-git-range"
)

// originInfo is what a module proxy reports about where a version was built
// from. hash is empty when it reports nothing usable (no Origin, or a proxy
// answer in the 4xx range).
type originInfo struct {
	hash   string
	subdir string
}

// FromGitRange reports whether v was found by commit range (see above) rather
// than by a package-scoped record.
func (v Vulnerability) FromGitRange() bool {
	m, ok := v.DatabaseSpecific.(map[string]any)
	return ok && m["source"] == gitRangeSource
}

// DisableGitRange turns the git-range pass off (--no-git-range): it needs the
// module proxy, which an outage or credentials may put out of reach.
func (vs *VulnerabilityScanner) DisableGitRange() { vs.proxyURL = "" }

func proxyURLFromEnv() string {
	url, _ := goproxy.FirstURL(os.Getenv("GOPROXY"))
	return url
}

// addGitRangeAdvisories adds the git-range advisories of every root Go module
// in plan to result and fixes (see the package comment above). A transport or
// server failure fails the scan, like any other OSV lookup.
func (vs *VulnerabilityScanner) addGitRangeAdvisories(ctx context.Context, plan scanPlan, result *ScanResult, fixes fixAccumulator) error {
	if vs.proxyURL == "" {
		return nil
	}
	var pkgs []Package
	for _, key := range plan.order {
		pkg := plan.pkgs[key]
		if pkg.Ecosystem == "Go" && !goproxy.IsPrivate(pkg.Name, vs.privatePatterns, "") {
			pkgs = append(pkgs, pkg)
		}
	}

	origins := make([]originInfo, len(pkgs))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(osvFetchConcurrency)
	for i, pkg := range pkgs {
		g.Go(func() (err error) {
			origins[i], err = vs.originFor(gctx, pkg.Name, "v"+pkg.Version)
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	var hashes []string
	for _, o := range origins {
		if o.hash != "" && o.subdir == "" {
			hashes = append(hashes, o.hash)
		}
	}
	hits, err := vs.commitVulns(ctx, hashes)
	if err != nil {
		return err
	}

	for i, pkg := range pkgs {
		if origins[i].hash == "" || origins[i].subdir != "" {
			continue
		}
		groups, err := vs.gitRangeGroups(ctx, pkg, hits[origins[i].hash], fixes.known)
		if err != nil {
			return err
		}
		for _, group := range groups {
			fix, err := vs.gitRangeFix(ctx, pkg, group)
			if err != nil {
				return err
			}
			vulnerability := gitRangeVulnerability(pkg, group, fix)
			logging.From(ctx).Debug("advisory matched by git commit range (no Go package record)",
				"module", pkg.Name, "version", pkg.Version, "vuln", vulnerability.ID, "fixed", vulnerability.FixedVersion)
			result.Vulnerabilities = append(result.Vulnerabilities, vulnerability)
			if vulnerability.FixedVersion != "" {
				vs.updateBestFixVersion(fixes.bestFixVersions, fixes.bumpVulnIDs, pkg, vulnerability.FixedVersion, vulnerability.ID)
			}
		}
	}
	return nil
}

// gitRangeGroups hydrates a commit hit's summaries and keeps the advisories
// that are genuinely git-range only: not withdrawn, not covered by a
// package-scoped record (known) and with no Go package of their own. Aliased
// records collapse into one group per advisory.
func (vs *VulnerabilityScanner) gitRangeGroups(ctx context.Context, pkg Package, summaries []*osvschema.Vulnerability, known map[string]struct{}) ([][]*osvschema.Vulnerability, error) {
	var records []*osvschema.Vulnerability
	for _, summary := range summaries {
		if _, ok := known[summary.GetId()]; ok {
			continue
		}
		record, err := vs.hydrateVulnerability(ctx, summary, pkg)
		if err != nil {
			return nil, err
		}
		if record == nil || record.GetWithdrawn() != nil || coveredBy(record, known) || hasGoPackage(record) {
			continue
		}
		records = append(records, record)
	}
	return collapseAliases(records), nil
}

func coveredBy(record *osvschema.Vulnerability, known map[string]struct{}) bool {
	for _, id := range append([]string{record.GetId()}, record.GetAliases()...) {
		if _, ok := known[id]; ok {
			return true
		}
	}
	return false
}

func hasGoPackage(record *osvschema.Vulnerability) bool {
	return slices.ContainsFunc(record.GetAffected(), func(a *osvschema.Affected) bool {
		return a.GetPackage().GetEcosystem() == "Go"
	})
}

// gitRangeFix finds the first release of pkg above its version, within the
// same major, that no longer carries the advisory: the version cut from one of
// the group's fixed commits, else the first whose commit OSV no longer
// matches. "" when there is none.
func (vs *VulnerabilityScanner) gitRangeFix(ctx context.Context, pkg Package, group []*osvschema.Vulnerability) (string, error) {
	fixed := make(map[string]struct{})
	ids := make(map[string]struct{})
	for _, record := range group {
		ids[record.GetId()] = struct{}{}
		for _, alias := range record.GetAliases() {
			ids[alias] = struct{}{}
		}
		for _, affected := range record.GetAffected() {
			for _, r := range affected.GetRanges() {
				if r.GetType() != osvschema.Range_GIT {
					continue
				}
				for _, event := range r.GetEvents() {
					if event.GetFixed() != "" {
						fixed[strings.ToLower(event.GetFixed())] = struct{}{}
					}
				}
			}
		}
	}

	versions, err := vs.laterVersions(ctx, pkg)
	if err != nil {
		return "", err
	}
	var rooted []string // versions with a usable root origin, ascending
	hashOf := make(map[string]string)
	for _, version := range versions {
		o, err := vs.originFor(ctx, pkg.Name, version)
		if err != nil {
			return "", err
		}
		if o.hash == "" || o.subdir != "" {
			continue
		}
		if _, ok := fixed[strings.ToLower(o.hash)]; ok {
			return version, nil
		}
		rooted = append(rooted, version)
		hashOf[version] = o.hash
	}
	// No release was cut from a fixed commit (fixes usually land mid-release):
	// the first release OSV no longer matches contains it. One batched query.
	hashes := make([]string, 0, len(rooted))
	for _, version := range rooted {
		hashes = append(hashes, hashOf[version])
	}
	hits, err := vs.commitVulns(ctx, hashes)
	if err != nil {
		return "", err
	}
	for _, version := range rooted {
		if !slices.ContainsFunc(hits[hashOf[version]], func(v *osvschema.Vulnerability) bool { return coveredBy(v, ids) }) {
			return version, nil
		}
	}
	return "", nil
}

// gitRangeVulnerability renders a git-range advisory group as a finding that
// carries no vulnerable imports: it applies whenever the module is linked.
func gitRangeVulnerability(pkg Package, group []*osvschema.Vulnerability, fix string) Vulnerability {
	id, aliases := advisoryIDs(group)
	v := Vulnerability{
		ID:               id,
		Aliases:          aliases,
		Module:           pkg.Name,
		Ecosystem:        pkg.Ecosystem,
		CurrentVersion:   versionDisplay(pkg.Ecosystem, pkg.Version),
		Summary:          group[0].GetSummary(),
		DatabaseSpecific: map[string]any{"source": gitRangeSource},
	}
	for _, record := range group {
		if s := extractSeverity(record); s != "" && (v.Severity == "" || SeverityRank(s) < SeverityRank(v.Severity)) {
			v.Severity = s
		}
	}
	if fix != "" {
		v.FixedVersion = versionDisplay(pkg.Ecosystem, strings.TrimPrefix(CanonicalModuleVersion(pkg.Name, fix), "v"))
	}
	return v
}

// laterVersions lists pkg's proxy releases above its version in the same
// major, ascending, bounded at maxGitRangeWalk. A pre-release is skipped
// unless pkg is itself on one; "+incompatible" releases (v2+ without a /vN
// path) count, any other build metadata does not.
func (vs *VulnerabilityScanner) laterVersions(ctx context.Context, pkg Package) ([]string, error) {
	current := "v" + pkg.Version
	all, err := vs.versionList(ctx, pkg.Name)
	if err != nil {
		return nil, err
	}
	var later []string
	for _, v := range all {
		switch {
		case !semver.IsValid(v) || (semver.Build(v) != "" && semver.Build(v) != "+incompatible"),
			semver.Major(v) != semver.Major(current),
			semver.Compare(v, current) <= 0,
			semver.Prerelease(v) != "" && semver.Prerelease(current) == "":
			continue
		}
		later = append(later, v)
	}
	semver.Sort(later)
	return later[:min(len(later), maxGitRangeWalk)], nil
}

func (vs *VulnerabilityScanner) versionList(ctx context.Context, mod string) ([]string, error) {
	if vs.cache != nil {
		if v, ok := vs.cache.GetVersions(mod); ok {
			return v, nil
		}
	}
	body, err := vs.proxyGet(ctx, mod, "list")
	if err != nil {
		return nil, err
	}
	versions := strings.Fields(string(body))
	if vs.cache != nil {
		vs.cache.SetVersions(mod, versions)
	}
	return versions, nil
}

// originFor reads the proxy's .info for module@version (version "v"-prefixed).
func (vs *VulnerabilityScanner) originFor(ctx context.Context, mod, version string) (originInfo, error) {
	key := mod + "@" + version
	if vs.cache != nil {
		if o, ok := vs.cache.GetOrigin(key); ok {
			return o, nil
		}
	}
	var o originInfo
	escaped, err := module.EscapeVersion(version)
	if err != nil {
		return o, nil //nolint:nilerr // not a valid version: nothing to go on
	}
	body, err := vs.proxyGet(ctx, mod, escaped+".info")
	if err != nil {
		return o, err
	}
	if len(body) > 0 {
		var info struct{ Origin struct{ Hash, Subdir string } }
		if err := json.Unmarshal(body, &info); err != nil {
			return o, fmt.Errorf("decoding proxy info for %s: %w", key, err)
		}
		o = originInfo{hash: info.Origin.Hash, subdir: info.Origin.Subdir}
	}
	if vs.cache != nil {
		vs.cache.SetOrigin(key, o)
	}
	return o, nil
}

// commitVulns returns the OSV commit-query summaries of each hash, querying
// (batched, paged) only those not cached.
func (vs *VulnerabilityScanner) commitVulns(ctx context.Context, hashes []string) (map[string][]*osvschema.Vulnerability, error) {
	out := make(map[string][]*osvschema.Vulnerability, len(hashes))
	var queries []*api.Query
	var queued []string
	for _, hash := range hashes {
		if _, done := out[hash]; done {
			continue
		}
		if vs.cache != nil {
			if v, ok := vs.cache.GetCommit(hash); ok {
				out[hash] = v
				continue
			}
		}
		out[hash] = nil
		queries = append(queries, &api.Query{Param: &api.Query_Commit{Commit: hash}})
		queued = append(queued, hash)
	}
	if len(queries) == 0 {
		return out, nil
	}
	results, err := vs.queryBatchAllPages(ctx, queries)
	if err != nil {
		return nil, err
	}
	for i, hash := range queued {
		out[hash] = results[i].GetVulns()
		if vs.cache != nil {
			vs.cache.SetCommit(hash, out[hash])
		}
	}
	return out, nil
}

// proxyGet fetches <proxy>/<module>/@v/<suffix>. A 4xx answer (module or
// version unknown to this proxy, or one needing credentials choam does not
// have) is "nothing to go on" - an empty body, not an error; transport
// failures, 429 and 5xx are retried and then fail the scan.
func (vs *VulnerabilityScanner) proxyGet(ctx context.Context, mod, suffix string) ([]byte, error) {
	escaped, err := module.EscapePath(mod)
	if err != nil {
		return nil, nil //nolint:nilerr // an unescapable path has no proxy entry
	}
	url := strings.TrimRight(vs.proxyURL, "/") + "/" + escaped + "/@v/" + suffix

	var lastErr error
	for attempt := range vs.client.attempts {
		if attempt > 0 {
			if err := sleepCtx(ctx, vs.client.backoff(attempt)); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", vs.client.userAgent)
		resp, err := vs.httpClient.Do(req)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			lastErr = fmt.Errorf("attempt %d: %w", attempt+1, err)
			continue
		}
		body, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		switch {
		case rerr != nil:
			lastErr = fmt.Errorf("attempt %d: reading response: %w", attempt+1, rerr)
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("attempt %d: status %d", attempt+1, resp.StatusCode)
		default:
			return nil, nil
		}
	}
	return nil, fmt.Errorf("module proxy %s: max retries exceeded: %w", url, lastErr)
}
