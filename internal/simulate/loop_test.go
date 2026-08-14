package simulate

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"
)

// fakeToolchain models the go tool over an in-memory module graph: the
// resolved graph is base overlaid with every successful `go get` of the
// current apply attempt. Attempt boundaries are detected by call sequence: a
// ModTidy not directly preceded by a successful Get is an attempt-opening
// tidy and resets the applied set (the loop restores go.mod/go.sum right
// before it).
type fakeToolchain struct {
	base     map[string]string                                             // module -> version before any gets
	latest   map[string]string                                             // module -> version resolved by @latest
	failGets map[string]error                                              // "module@version" (or "module@latest") -> error
	getErr   func(moduleAtVersion string, applied map[string]string) error // dynamic get failures
	tidyErr  func(applied map[string]string) error                         // invoked on attempt-closing tidy only
	pruned   map[string]bool                                               // modules `go mod tidy` removes from the graph
	capped   map[string]string                                             // module -> max version the tidied go.mod sustains

	// pruneUnless models a module whose require-block membership tracks
	// whether a SPECIFIC other candidate's `go get` actually ran in the
	// CURRENT attempt (unlike the static `pruned` above, which prunes the
	// same way every attempt, main-loop or trial): Requirements() excludes
	// the key module unless the value (trigger) module is present in
	// f.applied. Lets a test express "Y only becomes required because X's
	// closure pulls it in" - keyed off f.applied (reset every attempt, so
	// a trialApply that excludes X sees Y drop back out) while Y stays
	// resolvable via `base` regardless, exercising trialApply/scanTargets'
	// requirements-vs-resolved distinction - the exact thing the static
	// `pruned` set can't do, since it can't differ between a trial and the
	// main loop.
	pruneUnless map[string]string // module -> trigger module

	// getEffects models a get's transitive require changes, keyed by the
	// exact "module@version" argument: each listed module's applied version
	// is set alongside the got module itself - raised, or dragged back DOWN
	// (a real `go get` of a lower version downgrades modules that require a
	// higher one). Downgrades below base are not representable: baseGraph
	// overlays applied over base only when higher.
	getEffects map[string]map[string]string

	pristineReplaces map[string]ReplaceTarget // upstream go.mod replace directives

	// linked models `go list -deps` reachability: nil means "every module
	// in the current resolved graph is linked" (keeps reachability inert
	// for tests that don't care); linkedPkgs models the package-level set
	// (nil means unknown - package gates fail open); linkedErr makes
	// Linked fail (the loop must then fail open entirely).
	linked     []string
	linkedPkgs []string
	linkedErr  error

	// depGoVersions models DepGoVersions' module -> go directive map;
	// depGoVersionsErr makes it fail (the loop must fail open: empty field,
	// no loop failure). depGoVersionsFn, when set, takes priority over both
	// and computes the answer from the current attempt's applied set - lets
	// a test assert the value differs between the full converged graph and
	// confirmMinimalSet's minimal graph.
	depGoVersions    map[string]string
	depGoVersionsErr error
	depGoVersionsFn  func(applied map[string]string) (map[string]string, error)

	// linkedStd models LinkedStd's stdlib import-path set; linkedStdErr
	// makes it fail (the loop must fail open: nil field, no loop failure).
	// linkedStdFn, when set, takes priority over both and computes the
	// answer from the current attempt's applied set, mirroring
	// depGoVersionsFn.
	linkedStd    []string
	linkedStdErr error
	linkedStdFn  func(applied map[string]string) ([]string, error)

	applied  map[string]string
	replaced map[string]ReplaceTarget // replace edits of the current apply attempt
	lastCall string
	getLog   []string
	editLog  []string
}

func (f *fakeToolchain) Linked(ctx context.Context, dir string, _ []string) (map[string]struct{}, map[string]struct{}, error) {
	if f.linkedErr != nil {
		return nil, nil, f.linkedErr
	}
	var packages map[string]struct{}
	if f.linkedPkgs != nil {
		packages = make(map[string]struct{}, len(f.linkedPkgs))
		for _, pkg := range f.linkedPkgs {
			packages[pkg] = struct{}{}
		}
	}
	modules := make(map[string]struct{})
	if f.linked == nil {
		// Reachability-inert default: everything currently resolved is
		// linked. Preserve lastCall - this query must not perturb the
		// fake's apply-attempt boundary detection.
		lastCall := f.lastCall
		resolved, err := f.ListModules(ctx, dir)
		f.lastCall = lastCall
		if err != nil {
			return nil, nil, err
		}
		for module := range resolved {
			modules[module] = struct{}{}
		}
		return modules, packages, nil
	}
	for _, module := range f.linked {
		modules[module] = struct{}{}
	}
	return modules, packages, nil
}

func (f *fakeToolchain) DepGoVersions(_ context.Context, _ string) (map[string]string, error) {
	if f.depGoVersionsFn != nil {
		return f.depGoVersionsFn(f.applied)
	}
	if f.depGoVersionsErr != nil {
		return nil, f.depGoVersionsErr
	}
	return f.depGoVersions, nil
}

func (f *fakeToolchain) LinkedStd(_ context.Context, _ string, _ []string) (map[string]struct{}, error) {
	linkedStd, linkedStdErr := f.linkedStd, f.linkedStdErr
	if f.linkedStdFn != nil {
		linkedStd, linkedStdErr = f.linkedStdFn(f.applied)
	}
	if linkedStdErr != nil {
		return nil, linkedStdErr
	}
	if linkedStd == nil {
		return nil, nil
	}
	std := make(map[string]struct{}, len(linkedStd))
	for _, pkg := range linkedStd {
		std[pkg] = struct{}{}
	}
	return std, nil
}

func (f *fakeToolchain) ModTidy(_ context.Context, _ string) error {
	closing := f.lastCall == "get" || f.lastCall == "replace"
	f.lastCall = "tidy"
	if !closing {
		f.applied = make(map[string]string)
		f.replaced = make(map[string]ReplaceTarget)
		return nil
	}
	if f.tidyErr != nil {
		return f.tidyErr(f.applied)
	}
	return nil
}

func (f *fakeToolchain) Replace(_ context.Context, _ string, oldPath, newPath, version string) error {
	f.lastCall = "replace"
	if f.replaced == nil {
		f.replaced = make(map[string]ReplaceTarget)
	}
	f.replaced[oldPath] = ReplaceTarget{Path: newPath, Version: version}
	f.editLog = append(f.editLog, oldPath+"="+newPath+"@"+version)
	return nil
}

// activeReplaces returns the directives in effect: pristine overlaid with
// the current attempt's edits.
func (f *fakeToolchain) activeReplaces() map[string]ReplaceTarget {
	replaces := make(map[string]ReplaceTarget, len(f.pristineReplaces)+len(f.replaced))
	maps.Copy(replaces, f.pristineReplaces)
	maps.Copy(replaces, f.replaced)
	return replaces
}

func (f *fakeToolchain) Replaces(_ context.Context, _ string) (map[string]ReplaceTarget, error) {
	return f.activeReplaces(), nil
}

func (f *fakeToolchain) Get(_ context.Context, _ string, moduleAtVersion string) error {
	if err, ok := f.failGets[moduleAtVersion]; ok && err != nil {
		f.lastCall = "getfail"
		return err
	}
	if f.getErr != nil {
		if err := f.getErr(moduleAtVersion, f.applied); err != nil {
			f.lastCall = "getfail"
			return err
		}
	}
	idx := strings.LastIndex(moduleAtVersion, "@")
	module, version := moduleAtVersion[:idx], moduleAtVersion[idx+1:]
	if version == latestQuery {
		version = f.latest[module]
		if version == "" {
			f.lastCall = "getfail"
			return errors.New("no versions available")
		}
	}
	f.lastCall = "get"
	f.applied[module] = version
	maps.Copy(f.applied, f.getEffects[moduleAtVersion])
	f.getLog = append(f.getLog, moduleAtVersion)
	return nil
}

// baseGraph is the module graph before replace directives: base overlaid
// with this attempt's successful gets.
func (f *fakeToolchain) baseGraph() map[string]string {
	resolved := maps.Clone(f.base)
	for module, version := range f.applied {
		if current, ok := resolved[module]; !ok || semver.Compare(version, current) > 0 {
			resolved[module] = version
		}
	}
	return resolved
}

func (f *fakeToolchain) ListModules(_ context.Context, _ string) (map[string]string, error) {
	f.lastCall = "list"
	resolved := f.baseGraph()
	// Replace directives win over MVS selection, mirroring how the real
	// ListModules reports Replace.Path@Replace.Version.
	for oldPath, target := range f.activeReplaces() {
		_, present := resolved[oldPath]
		if !present && oldPath != target.Path {
			continue // replaced module not in the graph at all
		}
		if target.Version == "" {
			delete(resolved, oldPath) // local filesystem target: skipped
			continue
		}
		if oldPath != target.Path {
			delete(resolved, oldPath)
		}
		resolved[target.Path] = target.Version
	}
	return resolved, nil
}

// Requirements models the tidied go.mod require list: the base graph minus
// tidy-pruned modules, with tidy-reverted version caps applied - and
// deliberately WITHOUT replace directives reflected (a replace-pinned
// module's require line stays at the MVS floor; that require-lags-replace
// gap is the load-bearing semantics this fake exists to model).
func (f *fakeToolchain) Requirements(_ context.Context, _ string) (map[string]string, error) {
	requirements := f.baseGraph()
	for module := range f.pruned {
		delete(requirements, module)
	}
	for module, trigger := range f.pruneUnless {
		if _, ok := f.applied[trigger]; !ok {
			delete(requirements, module)
		}
	}
	for module, capVersion := range f.capped {
		if version, ok := requirements[module]; ok && semver.Compare(version, capVersion) > 0 {
			requirements[module] = capVersion
		}
	}
	return requirements, nil
}

// fakeAdvisory affects versions in [introduced, fixed); empty introduced
// means "always"; empty fixed means "no released fix". imports optionally
// models the advisory's vulnerable-package metadata
// (scan.Vulnerability.VulnerableImports).
type fakeAdvisory struct {
	module, id, introduced, fixed string
	imports                       []scan.VulnerableImport
}

type fakeScanner struct {
	advisories []fakeAdvisory
	scans      int
}

func (f *fakeScanner) ScanPackages(_ context.Context, pkgs []scan.Package) (*scan.ScanResult, error) {
	f.scans++
	result := &scan.ScanResult{}
	bumps := make(map[string]*scan.SecurityBump)
	for _, pkg := range pkgs {
		for _, adv := range f.advisories {
			if adv.module != pkg.Name {
				continue
			}
			if adv.introduced != "" && semver.Compare(pkg.Version, adv.introduced) < 0 {
				continue
			}
			if adv.fixed != "" && semver.Compare(pkg.Version, adv.fixed) >= 0 {
				continue
			}
			result.Vulnerabilities = append(result.Vulnerabilities, scan.Vulnerability{
				ID: adv.id, Module: pkg.Name, Ecosystem: "Go",
				CurrentVersion: pkg.Version, FixedVersion: adv.fixed,
				VulnerableImports: adv.imports,
			})
			if adv.fixed == "" {
				continue
			}
			bump := bumps[pkg.Name]
			if bump == nil {
				bump = &scan.SecurityBump{Name: pkg.Name, Ecosystem: "Go", CurrentVersion: pkg.Version, FixedVersion: adv.fixed}
				bumps[pkg.Name] = bump
			}
			if semver.Compare(adv.fixed, bump.FixedVersion) > 0 {
				bump.FixedVersion = adv.fixed
			}
			bump.VulnIDs = append(bump.VulnIDs, adv.id)
		}
	}
	for _, bump := range bumps {
		result.SecurityBumps = append(result.SecurityBumps, *bump)
	}
	return result, nil
}

func newTestModuleDir(t *testing.T) string {
	t.Helper()
	return newTestModuleDirWithGo(t, "1.21")
}

// newTestModuleDirWithGo mirrors newTestModuleDir with a caller-chosen go
// directive, for exercising tidiedGoModern's >= 1.17 threshold. The fake
// ModTidy never rewrites the fixture go.mod (unlike the real toolchain,
// which tidies with -go=<host>), so the on-disk directive stays purely
// fixture-controlled for the lifetime of the test.
func newTestModuleDirWithGo(t *testing.T, goDirective string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo "+goDirective+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.sum"), []byte(""), 0o644))
	return dir
}

// countingHandler is a minimal slog.Handler that counts records by message,
// for warn/info-once guard assertions.
type countingHandler struct {
	mu     sync.Mutex
	counts map[string]int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.counts == nil {
		h.counts = make(map[string]int)
	}
	h.counts[r.Message]++
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func (h *countingHandler) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[msg]
}

func TestRunLoop_RaisesToFixpoint(t *testing.T) {
	// The seed fixes GO-0001, but the rescan of the raised graph reveals
	// GO-0002 (introduced after the original version), requiring a second
	// iteration - the exact x/crypto v0.45.0-vs-v0.53.0 scenario.
	tc := &fakeToolchain{base: map[string]string{"golang.org/x/crypto": "v0.40.0"}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "golang.org/x/crypto", id: "GO-0001", fixed: "v0.45.0"},
		{module: "golang.org/x/crypto", id: "GO-0002", introduced: "v0.42.0", fixed: "v0.53.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "golang.org/x/crypto", Version: "v0.45.0", FromCVE: true, VulnIDs: []string{"GO-0001"}},
		},
		Baseline: map[string]string{"golang.org/x/crypto": "v0.40.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, 2, result.Iterations)
	assert.Equal(t, []string{"golang.org/x/crypto@v0.53.0"}, result.FinalDeps)
	assert.Empty(t, result.Residuals)
	assert.Empty(t, result.RemainingVulnIDs)
}

func TestRunLoop_IterationCap(t *testing.T) {
	// Each raised version reveals the next advisory: with MaxIterations=2
	// the loop must stop and report the unvalidated target as a residual.
	tc := &fakeToolchain{base: map[string]string{"example.com/mod": "v0.40.0"}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/mod", id: "GO-1", fixed: "v0.45.0"},
		{module: "example.com/mod", id: "GO-2", introduced: "v0.45.0", fixed: "v0.50.0"},
		{module: "example.com/mod", id: "GO-3", introduced: "v0.50.0", fixed: "v0.55.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
	}, Options{MaxIterations: 2})

	require.NoError(t, err)
	assert.False(t, result.Converged)
	assert.Equal(t, 2, result.Iterations)
	require.NotEmpty(t, result.Residuals)
	capResidual := result.Residuals[len(result.Residuals)-1]
	assert.Equal(t, "example.com/mod", capResidual.Module)
	assert.Contains(t, capResidual.Reason, "iteration cap")
}

func TestRunLoop_DropsUnresolvableCoUpdate(t *testing.T) {
	// The consul@v1.4.4 scenario: a coherence-only candidate whose `go get`
	// fails is sacrificed, and the CVE-backed candidate still lands.
	tc := &fakeToolchain{
		base: map[string]string{
			"github.com/hashicorp/consul":    "v1.0.0",
			"github.com/hashicorp/go-getter": "v1.5.0",
		},
		failGets: map[string]error{
			"github.com/hashicorp/consul@v1.4.4": errors.New("cannot find module providing package github.com/envoyproxy/go-control-plane/pkg/util"),
		},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "github.com/hashicorp/go-getter", id: "GO-GETTER-1", fixed: "v1.7.9"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "github.com/hashicorp/consul", Version: "v1.4.4"},
			{Module: "github.com/hashicorp/go-getter", Version: "v1.7.9", FromCVE: true, VulnIDs: []string{"GO-GETTER-1"}},
		},
		Baseline: map[string]string{
			"github.com/hashicorp/consul":    "v1.0.0",
			"github.com/hashicorp/go-getter": "v1.5.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"github.com/hashicorp/go-getter@v1.7.9"}, result.FinalDeps)
	require.Len(t, result.Dropped, 1)
	assert.Equal(t, "github.com/hashicorp/consul", result.Dropped[0].Module)
	assert.Contains(t, result.Dropped[0].Reason, "unresolvable")
	assert.Empty(t, result.Residuals)
}

func TestRunLoop_CVECandidateUnresolvable(t *testing.T) {
	// A CVE-backed fix that fails at its exact version is retried at
	// @latest; when that also fails it is PROMOTED to a replace directive
	// (edits need no get-time resolution). Only when the replace also fails
	// to sustain does it become a residual - here the promotion succeeds.
	tc := &fakeToolchain{
		base: map[string]string{"example.com/broken": "v1.0.0"},
		failGets: map[string]error{
			"example.com/broken@v1.2.0": errors.New("410 gone"),
			"example.com/broken@latest": errors.New("410 gone"),
		},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/broken", id: "GO-BROKEN-1", fixed: "v1.2.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/broken", Version: "v1.2.0", FromCVE: true, VulnIDs: []string{"GO-BROKEN-1"}},
		},
		Baseline: map[string]string{"example.com/broken": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Equal(t, []string{"example.com/broken=example.com/broken@v1.2.0"}, result.FinalReplaces)
	assert.Empty(t, result.Residuals, "the promoted replace rescues the fix")
	assert.Empty(t, result.RemainingVulnIDs)
}

func TestRunLoop_NoFixResidual(t *testing.T) {
	tc := &fakeToolchain{base: map[string]string{"example.com/unfixed": "v1.0.0"}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/unfixed", id: "GO-NOFIX-1"}, // no released fix
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{Modroot: "."}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, 1, result.Iterations)
	require.Len(t, result.Residuals, 1)
	assert.Equal(t, "no released fix", result.Residuals[0].Reason)
	assert.Equal(t, []string{"GO-NOFIX-1"}, result.RemainingVulnIDs)
}

func TestRunLoop_MajorPathChangeResidual(t *testing.T) {
	tc := &fakeToolchain{base: map[string]string{"example.com/legacy": "v1.2.0"}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/legacy", id: "GO-MAJOR-1", fixed: "v2.0.1"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{Modroot: "."}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	require.Len(t, result.Residuals, 1)
	assert.Contains(t, result.Residuals[0].Reason, "major version")
	assert.Equal(t, "v2.0.1", result.Residuals[0].FixedVersion)
	assert.Empty(t, result.FinalDeps)
}

func TestRunLoop_BaselineNoopsDropped(t *testing.T) {
	tc := &fakeToolchain{base: map[string]string{
		"example.com/aaa": "v2.2.0",
		"example.com/bbb": "v0.4.0",
	}}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/aaa", Version: "v2.2.0", FromCVE: true}, // baseline already there
			{Module: "example.com/bbb", Version: "v0.5.0", FromCVE: true},
		},
		Baseline: map[string]string{
			"example.com/aaa": "v2.2.0",
			"example.com/bbb": "v0.4.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.Equal(t, []string{"example.com/bbb@v0.5.0"}, result.FinalDeps)
	require.Len(t, result.Dropped, 1)
	assert.Contains(t, result.Dropped[0].Reason, "no-op")
}

func TestRunLoop_ConfirmationDropsRedundantPins(t *testing.T) {
	// A coherence-only pin that MVS satisfies anyway is dropped by the
	// confirmation pass; the CVE-backed entry survives.
	tc := &fakeToolchain{base: map[string]string{
		"example.com/pin":  "v1.0.0",
		"example.com/vuln": "v1.9.0",
	}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/vuln", id: "GO-VULN-1", fixed: "v2.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/pin", Version: "v1.5.0"},
			{Module: "example.com/vuln", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-VULN-1"}},
		},
		Baseline: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/vuln": "v1.9.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/vuln@v2.0.0"}, result.FinalDeps)
	require.Len(t, result.Dropped, 1)
	assert.Equal(t, "example.com/pin", result.Dropped[0].Module)
	assert.Contains(t, result.Dropped[0].Reason, "redundant")
}

func TestRunLoop_ConfirmationKeepsProtectivePins(t *testing.T) {
	// Dropping the pin would regress example.com/pin below its own fix
	// version - the confirmation pass must detect the raise and keep the
	// full set.
	tc := &fakeToolchain{base: map[string]string{
		"example.com/pin":  "v1.0.0",
		"example.com/vuln": "v1.9.0",
	}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/vuln", id: "GO-VULN-1", fixed: "v2.0.0"},
		{module: "example.com/pin", id: "GO-PIN-1", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/pin", Version: "v1.5.0"},
			{Module: "example.com/vuln", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-VULN-1"}},
		},
		Baseline: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/vuln": "v1.9.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.ElementsMatch(t, []string{"example.com/pin@v1.5.0", "example.com/vuln@v2.0.0"}, result.FinalDeps)
	assert.Empty(t, result.Dropped)
	assert.Empty(t, result.Residuals)
}

// depsGoVersionsByPin and stdByPin key a stateful DepGoVersions/LinkedStd
// answer off whether "example.com/pin" is still part of the current apply
// attempt: present models the full converged set (main-loop apply, both
// candidates active), absent models confirmMinimalSet's essential-only
// reapply once the redundant pin has been provisionally dropped. The
// minimal-state answer deliberately is NOT a subset of the full-state
// answer (it both loses "net/http" and gains "crypto/subtle") to prove
// StdPackages genuinely needs a recompute, not just a shrink, on adoption.
func depGoVersionsByPin(applied map[string]string) (map[string]string, error) {
	if _, pinned := applied["example.com/pin"]; pinned {
		return map[string]string{"example.com/pin": "1.26", "example.com/vuln": "1.24"}, nil
	}
	return map[string]string{"example.com/vuln": "1.24"}, nil
}

func stdByPin(applied map[string]string) ([]string, error) {
	if _, pinned := applied["example.com/pin"]; pinned {
		return []string{"fmt", "net/http"}, nil
	}
	return []string{"fmt", "crypto/subtle"}, nil
}

// TestRunLoop_ConfirmMinimalSetRecomputesCapabilitiesOnAdoption: when the
// confirmation pass adopts the minimal (redundant-pin-dropped) graph, the
// MaxDepGoVersion/StdPackages fields set from the converged full set must be
// refreshed against the adopted graph - not left describing the superset.
// This pins the fix for the gap where StdPackages, computed only once
// pre-minimization, could silently miss stdlib packages the adopted
// (differently-versioned) minimal graph actually links.
func TestRunLoop_ConfirmMinimalSetRecomputesCapabilitiesOnAdoption(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/vuln": "v1.9.0",
		},
		depGoVersionsFn: depGoVersionsByPin,
		linkedStdFn:     stdByPin,
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/vuln", id: "GO-VULN-1", fixed: "v2.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/pin", Version: "v1.5.0"},
			{Module: "example.com/vuln", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-VULN-1"}},
		},
		Baseline: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/vuln": "v1.9.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	require.Len(t, result.Dropped, 1, "pin must be dropped as redundant for this to exercise adoption")
	assert.Equal(t, "example.com/pin", result.Dropped[0].Module)

	// Minimal-state answers, not the full-set superset the loop would have
	// reported without the adoption-time recompute.
	assert.Equal(t, "1.24", result.MaxDepGoVersion)
	assert.Equal(t, map[string]struct{}{"fmt": {}, "crypto/subtle": {}}, result.StdPackages)
}

// TestRunLoop_ConfirmMinimalSetKeepsCapabilitiesOnRejection: mirrors
// TestRunLoop_ConfirmationKeepsProtectivePins, but with the same
// applied-set-keyed fake capability answers as the adoption test above.
// Because dropping the pin here regresses it below its own fix version,
// confirmMinimalSet must reject the minimal set - and the capability
// fields must stay at the full-set values computed post-convergence,
// never having been touched by the (never-reached) adoption-time
// recompute.
func TestRunLoop_ConfirmMinimalSetKeepsCapabilitiesOnRejection(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/vuln": "v1.9.0",
		},
		depGoVersionsFn: depGoVersionsByPin,
		linkedStdFn:     stdByPin,
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/vuln", id: "GO-VULN-1", fixed: "v2.0.0"},
		{module: "example.com/pin", id: "GO-PIN-1", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/pin", Version: "v1.5.0"},
			{Module: "example.com/vuln", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-VULN-1"}},
		},
		Baseline: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/vuln": "v1.9.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.Dropped, "the minimal set must be rejected, keeping both candidates")

	// Full-set (superset) answers - the minimal-state recompute never runs
	// because adoption is rejected.
	assert.Equal(t, "1.26", result.MaxDepGoVersion)
	assert.Equal(t, map[string]struct{}{"fmt": {}, "net/http": {}}, result.StdPackages)
}

const genprotoAmbiguityErr = `go mod tidy: exit status 1: 	google.golang.org/grpc/status imports
	google.golang.org/genproto/googleapis/rpc/status: ambiguous import: found package google.golang.org/genproto/googleapis/rpc/status in multiple modules:
	google.golang.org/genproto v0.0.0-20221024183307-1bc688fe9f3e (/home/u/go/pkg/mod/google.golang.org/genproto@v0.0.0-20221024183307-1bc688fe9f3e/googleapis/rpc/status)
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 (/home/u/go/pkg/mod/google.golang.org/genproto/googleapis/rpc@v0.0.0-20260226221140-a57be14db171/status)`

func TestAmbiguousImportModules(t *testing.T) {
	assert.Equal(t, []string{"google.golang.org/genproto"}, ambiguousImportModules(genprotoAmbiguityErr))
	assert.Empty(t, ambiguousImportModules("go mod tidy: some unrelated failure"))
}

func TestRunLoop_RepairsAmbiguousImport(t *testing.T) {
	// Bumping grpc trips the genproto monolith-vs-split ambiguity on tidy;
	// the loop must advance the monolith past the split point and keep the
	// CVE-backed grpc bump.
	tc := &fakeToolchain{
		base: map[string]string{
			"google.golang.org/grpc":     "v1.40.0",
			"google.golang.org/genproto": "v0.0.0-20221024183307-1bc688fe9f3e",
		},
		latest: map[string]string{
			"google.golang.org/genproto": "v0.0.0-20260226221140-a57be14db171",
		},
	}
	tc.tidyErr = func(applied map[string]string) error {
		if applied["google.golang.org/grpc"] != "" && applied["google.golang.org/genproto"] == "" {
			return errors.New(genprotoAmbiguityErr)
		}
		return nil
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "google.golang.org/grpc", id: "GO-GRPC-1", fixed: "v1.56.3"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "google.golang.org/grpc", Version: "v1.56.3", FromCVE: true, VulnIDs: []string{"GO-GRPC-1"}},
		},
		Baseline: map[string]string{
			"google.golang.org/grpc":     "v1.40.0",
			"google.golang.org/genproto": "v0.0.0-20221024183307-1bc688fe9f3e",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.ElementsMatch(t, []string{
		"google.golang.org/grpc@v1.56.3",
		"google.golang.org/genproto@v0.0.0-20260226221140-a57be14db171",
	}, result.FinalDeps)
	assert.Empty(t, result.Residuals)
}

func TestRunLoop_RepairsAmbiguousImportAtGetTime(t *testing.T) {
	// The grpc case from terraform-provider-template: `go get grpc@vX`
	// itself trips the genproto ambiguity. The remedy must be added without
	// penalizing grpc and applied BEFORE it on the retry.
	tc := &fakeToolchain{
		base: map[string]string{
			"google.golang.org/grpc":     "v1.40.0",
			"google.golang.org/genproto": "v0.0.0-20221024183307-1bc688fe9f3e",
		},
		latest: map[string]string{
			"google.golang.org/genproto": "v0.0.0-20260226221140-a57be14db171",
		},
	}
	tc.getErr = func(moduleAtVersion string, applied map[string]string) error {
		if moduleAtVersion == "google.golang.org/grpc@v1.79.3" && applied["google.golang.org/genproto"] == "" {
			return errors.New(genprotoAmbiguityErr)
		}
		return nil
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "google.golang.org/grpc", id: "GO-GRPC-1", fixed: "v1.79.3"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "google.golang.org/grpc", Version: "v1.79.3", FromCVE: true, VulnIDs: []string{"GO-GRPC-1"}},
		},
		Baseline: map[string]string{
			"google.golang.org/grpc":     "v1.40.0",
			"google.golang.org/genproto": "v0.0.0-20221024183307-1bc688fe9f3e",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.ElementsMatch(t, []string{
		"google.golang.org/grpc@v1.79.3",
		"google.golang.org/genproto@v0.0.0-20260226221140-a57be14db171",
	}, result.FinalDeps)
	assert.Empty(t, result.Residuals)
	assert.Empty(t, result.Dropped)
}

func TestRunLoop_ShedsCVECandidateWhenGraphWontTidy(t *testing.T) {
	// A tidy failure with nothing repairable and no coherence candidates
	// left must shed the CVE-backed candidate and report it as residual -
	// never fail the simulation outright.
	tc := &fakeToolchain{
		base: map[string]string{"example.com/hard": "v1.0.0"},
	}
	tc.tidyErr = func(applied map[string]string) error {
		if applied["example.com/hard"] != "" {
			return errors.New("go: incompatible module graph")
		}
		return nil
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/hard", id: "GO-HARD-1", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/hard", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-HARD-1"}},
		},
		Baseline: map[string]string{"example.com/hard": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	require.NotEmpty(t, result.Residuals)
	assert.Equal(t, "example.com/hard", result.Residuals[0].Module)
	assert.Contains(t, result.Residuals[0].Reason, "breaks module graph")
	assert.Equal(t, []string{"GO-HARD-1"}, result.RemainingVulnIDs)
}

func TestRunLoop_DropsTidyPrunedModules(t *testing.T) {
	// The glog case: nothing imports the module after the other bumps, so
	// `go mod tidy` prunes it - and melange's gobump errors on a deps entry
	// absent from the tidied go.mod. The entry must be dropped.
	// glog is in the pristine graph (so pre-apply reachability keeps it -
	// the fake treats every resolved module as linked) but go mod tidy
	// prunes it after the apply; matching Baseline below.
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/kept":       "v1.0.0",
			"github.com/golang/glog": "v0.0.0-20160126235308-23def4e6c14b",
		},
		pruned: map[string]bool{"github.com/golang/glog": true},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "github.com/golang/glog", Version: "v1.2.4", FromCVE: true, VulnIDs: []string{"GO-GLOG-1"}},
			{Module: "example.com/kept", Version: "v1.1.0", FromCVE: true},
		},
		Baseline: map[string]string{
			"github.com/golang/glog": "v0.0.0-20160126235308-23def4e6c14b",
			"example.com/kept":       "v1.0.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/kept@v1.1.0"}, result.FinalDeps)
	require.Len(t, result.Dropped, 1)
	assert.Equal(t, "github.com/golang/glog", result.Dropped[0].Module)
	assert.Contains(t, result.Dropped[0].Reason, "pruned by go mod tidy")
	assert.Empty(t, result.Residuals)
}

func TestRunLoop_PromotesRevertedCVEPinToReplace(t *testing.T) {
	// The x/crypto case: `go get` accepts the pin but the final tidy
	// reverts it below the requested version. A CVE-backed pin must be
	// PROMOTED to a replace directive (which survives tidy) instead of
	// being shed as a residual.
	tc := &fakeToolchain{
		base:   map[string]string{"golang.org/x/crypto": "v0.51.0", "example.com/kept": "v1.0.0"},
		capped: map[string]string{"golang.org/x/crypto": "v0.51.0"},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "golang.org/x/crypto", Version: "v0.52.0", FromCVE: true, VulnIDs: []string{"GO-CRYPTO-1"}},
			{Module: "example.com/kept", Version: "v1.1.0", FromCVE: true},
		},
		Baseline: map[string]string{
			"golang.org/x/crypto": "v0.51.0",
			"example.com/kept":    "v1.0.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/kept@v1.1.0"}, result.FinalDeps)
	assert.Equal(t, []string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"}, result.FinalReplaces)
	assert.ElementsMatch(t, []string{"golang.org/x/crypto", "example.com/kept"}, result.CVEBackedModules)
	assert.Empty(t, result.Residuals, "the promoted fix must not be a residual")
	assert.Contains(t, tc.editLog, "golang.org/x/crypto=golang.org/x/crypto@v0.52.0")
}

func TestRunLoop_RevertedCoherencePinStillShed(t *testing.T) {
	// A tidy-reverted pin with no CVE backing is not worth a replace
	// directive - unchanged shed behavior.
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/pin": "v1.0.0", "example.com/kept": "v1.0.0"},
		capped: map[string]string{"example.com/pin": "v1.0.0"},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/pin", Version: "v1.5.0"},
			{Module: "example.com/kept", Version: "v1.1.0", FromCVE: true},
		},
		Baseline: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/kept": "v1.0.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/kept@v1.1.0"}, result.FinalDeps)
	assert.Empty(t, result.FinalReplaces)
	require.NotEmpty(t, result.Dropped)
	assert.Contains(t, result.Dropped[0].Reason, "reverts the pin")
	assert.Empty(t, result.Residuals)
}

func TestRunLoop_OrderingPreserved(t *testing.T) {
	// Seed order (analyzeBumps' indirect -> direct -> new) must be preserved
	// in FinalDeps; raised candidates append after.
	tc := &fakeToolchain{base: map[string]string{
		"example.com/zzz": "v1.0.0",
		"example.com/aaa": "v1.0.0",
		"example.com/mmm": "v1.0.0",
	}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/mmm", id: "GO-M-1", introduced: "v1.0.5", fixed: "v1.3.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/zzz", Version: "v1.1.0", FromCVE: true},
			{Module: "example.com/aaa", Version: "v1.1.0", FromCVE: true},
			{Module: "example.com/mmm", Version: "v1.1.0", FromCVE: true},
		},
		Baseline: map[string]string{
			"example.com/zzz": "v1.0.0",
			"example.com/aaa": "v1.0.0",
			"example.com/mmm": "v1.0.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.Equal(t, []string{
		"example.com/zzz@v1.1.0",
		"example.com/aaa@v1.1.0",
		"example.com/mmm@v1.3.0", // raised in place, order kept
	}, result.FinalDeps)
}

func TestRunLoop_SeedReplacePreservedAndRaised(t *testing.T) {
	// A user-authored fork redirect enters as a replace seed; an advisory on
	// the replacement module must raise the directive, never issue a
	// `go get` for it.
	tc := &fakeToolchain{
		base: map[string]string{"github.com/old/mod": "v1.0.0"},
		pristineReplaces: map[string]ReplaceTarget{
			"github.com/old/mod": {Path: "github.com/fork/mod", Version: "v1.2.0"},
		},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "github.com/fork/mod", id: "GO-FORK-1", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "github.com/fork/mod", Version: "v1.2.0", Replace: true, ReplaceOld: "github.com/old/mod"},
		},
		Baseline: map[string]string{"github.com/fork/mod": "v1.2.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Equal(t, []string{"github.com/old/mod=github.com/fork/mod@v1.5.0"}, result.FinalReplaces)
	for _, get := range tc.getLog {
		assert.NotContains(t, get, "github.com/fork/mod", "replace-pinned module must never be fetched via go get")
	}
	assert.Empty(t, result.Residuals)
}

// TestRunLoop_SeedReplaceForModuleAbsentFromGoModSurvives: a replace pin for
// a module in NO require line (purely transitive - never a direct or
// indirect require, only reachable through the module graph) must still
// survive checkReplaceCandidate and land in FinalReplaces. Unlike a deps
// entry, a replace directive is never checked against Requirements for a
// seed (only a PROMOTED replace is - see TestRunLoop_PrunedPromotedReplace-
// BackfillsResidual for that contrast case); it only has to survive tidy.
// This mirrors omnibump v0.23.1's AUTO-954: absentReplacePins re-adds
// replace-type deps missing from a sub-module's go.mod because the
// directive (unlike a bare require) survives go mod tidy.
func TestRunLoop_SeedReplaceForModuleAbsentFromGoModSurvives(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{"example.com/app": "v1.0.0"},
		// Reachability runs BEFORE the first apply (dropUnreachable checks
		// the pre-replace graph), so a module with no other footprint needs
		// an explicit linked entry or it would be shed as unlinked before
		// the replace ever gets a chance to add it - a different mechanism
		// than the one this test targets.
		linked: []string{"example.com/app", "example.com/transitive"},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/transitive", Version: "v2.0.0", Replace: true, ReplaceOld: "example.com/transitive"},
		},
		Baseline: map[string]string{"example.com/transitive": "v2.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Equal(t, []string{"example.com/transitive=example.com/transitive@v2.0.0"}, result.FinalReplaces)
	assert.Empty(t, result.Dropped, `absent-from-go.mod must not be treated as "pruned" or "not sustained"`)
	assert.Empty(t, result.Residuals)
	for _, get := range tc.getLog {
		assert.NotContains(t, get, "example.com/transitive", "replace-pinned module must never be fetched via go get")
	}
}

func TestRunLoop_DepsSeedSupersededByReplaceSeed(t *testing.T) {
	// One channel per module: a deps seed for a module already claimed by a
	// replace seed is superseded (gobump's replace overrides the deps entry
	// anyway), merging its advisory backing into the directive.
	tc := &fakeToolchain{
		base: map[string]string{"example.com/mod": "v1.0.0"},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/mod", Version: "v1.5.0", Replace: true},
			{Module: "example.com/mod", Version: "v1.4.0", FromCVE: true, VulnIDs: []string{"GO-MOD-1"}},
		},
		Baseline: map[string]string{"example.com/mod": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Equal(t, []string{"example.com/mod=example.com/mod@v1.5.0"}, result.FinalReplaces)
	assert.Contains(t, result.CVEBackedModules, "example.com/mod")
	require.NotEmpty(t, result.Dropped)
	assert.Contains(t, result.Dropped[0].Reason, "superseded by replaces entry")
}

func TestRunLoop_DepsSeedRoutedThroughPristinePin(t *testing.T) {
	// A CVE fix for a module the upstream go.mod already replace-pins must
	// update the directive (a get cannot out-vote it).
	tc := &fakeToolchain{
		base: map[string]string{"example.com/mod": "v1.0.0"},
		pristineReplaces: map[string]ReplaceTarget{
			"example.com/mod": {Path: "example.com/mod", Version: "v1.1.0"},
		},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/mod", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-MOD-1"}},
		},
		Baseline: map[string]string{"example.com/mod": "v1.1.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Equal(t, []string{"example.com/mod=example.com/mod@v1.5.0"}, result.FinalReplaces)
	assert.Empty(t, tc.getLog, "no go get for a replace-pinned module")
}

func TestRunLoop_LocalPathReplacePinIsResidual(t *testing.T) {
	// A CVE fix for a module replace-pinned to a local path cannot be
	// applied at all - honest residual, never an edit.
	tc := &fakeToolchain{
		base: map[string]string{"example.com/vendored": "v1.0.0"},
		pristineReplaces: map[string]ReplaceTarget{
			"example.com/vendored": {Path: "./local", Version: ""},
		},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/vendored", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-VEND-1"}},
		},
		Baseline: map[string]string{"example.com/vendored": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Empty(t, result.FinalReplaces)
	assert.Empty(t, tc.editLog)
	require.NotEmpty(t, result.Residuals)
	assert.Contains(t, result.Residuals[0].Reason, "local path")
	assert.Equal(t, []string{"GO-VEND-1"}, result.RemainingVulnIDs)
}

func TestRunLoop_PromotedReplaceShedWhenTidyFails(t *testing.T) {
	// Promotion is an attempt, not a guarantee: a promoted replace whose
	// pinned version breaks the final tidy is shed with a residual.
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/hard": "v1.0.0", "example.com/kept": "v1.0.0"},
		capped: map[string]string{"example.com/hard": "v1.0.0"},
	}
	tc.tidyErr = func(applied map[string]string) error {
		if _, pinned := tc.replaced["example.com/hard"]; pinned {
			return errors.New("go: example.com/hard: incompatible module graph")
		}
		return nil
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/hard", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-HARD-1"}},
			{Module: "example.com/kept", Version: "v1.1.0", FromCVE: true},
		},
		Baseline: map[string]string{
			"example.com/hard": "v1.0.0",
			"example.com/kept": "v1.0.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/kept@v1.1.0"}, result.FinalDeps)
	assert.Empty(t, result.FinalReplaces)
	require.NotEmpty(t, result.Residuals)
	assert.Equal(t, "example.com/hard", result.Residuals[0].Module)
	assert.Equal(t, []string{"GO-HARD-1"}, result.RemainingVulnIDs)
}

func TestRunLoop_ConfirmMinimalSetKeepsReplaces(t *testing.T) {
	// The confirmation pass must re-apply replace directives (a promoted
	// fix) while dropping redundant coherence pins.
	tc := &fakeToolchain{
		base: map[string]string{
			"golang.org/x/crypto": "v0.51.0",
			"example.com/pin":     "v1.0.0",
		},
		capped: map[string]string{"golang.org/x/crypto": "v0.51.0"},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "golang.org/x/crypto", Version: "v0.52.0", FromCVE: true, VulnIDs: []string{"GO-CRYPTO-1"}},
			{Module: "example.com/pin", Version: "v1.5.0"}, // coherence-only, satisfied without it
		},
		Baseline: map[string]string{
			"golang.org/x/crypto": "v0.51.0",
			"example.com/pin":     "v1.0.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"}, result.FinalReplaces)
	var pinDropped bool
	for _, dropped := range result.Dropped {
		if dropped.Module == "example.com/pin" {
			pinDropped = true
			assert.Contains(t, dropped.Reason, "redundant")
		}
	}
	assert.True(t, pinDropped, "coherence pin must be dropped as redundant")
	assert.Empty(t, result.Residuals)
}

func TestRunLoop_PromotedReplaceBaselineNoop(t *testing.T) {
	// A promotion whose target the baseline (upstream replace directives
	// applied) already satisfies is a no-op and must not be emitted -
	// mirroring gobump's warn+skip on an existing newer replace.
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/mod": "v1.0.0"},
		capped: map[string]string{"example.com/mod": "v1.0.0"},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/mod", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-MOD-1"}},
		},
		// Baseline already at the target (e.g. an upstream replace pins it).
		Baseline: map[string]string{"example.com/mod": "v1.5.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Empty(t, result.FinalReplaces)
	var noop bool
	for _, dropped := range result.Dropped {
		if strings.Contains(dropped.Reason, "no-op") {
			noop = true
		}
	}
	assert.True(t, noop, "promotion at baseline must be dropped as a no-op")
}

// TestRunLoop_UnreachableSeedDroppedNoResidual: a CVE-backed seed whose
// module is not linked into any build artifact must be shed - with the
// distinct not-linked drop reason and, unlike every other CVE-backed drop,
// NO residual (the advisory affects nothing that ships).
func TestRunLoop_UnreachableSeedDroppedNoResidual(t *testing.T) {
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/linked": "v1.0.0", "example.com/testonly": "v1.0.0"},
		linked: []string{"example.com/linked"},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/testonly", id: "GO-9001", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/testonly", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-9001"}},
		},
		Baseline: map[string]string{"example.com/testonly": "v1.0.0"},
		Packages: []string{"."},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps, "unreachable seed must not survive")
	assert.Empty(t, result.Residuals, "an unreachable advisory is neither fixed nor residual")
	assert.Empty(t, result.RemainingVulnIDs)

	require.Len(t, result.Dropped, 1)
	assert.Equal(t, "example.com/testonly", result.Dropped[0].Module)
	assert.Contains(t, result.Dropped[0].Reason, "not linked into build artifacts (packages: .)")

	require.NotNil(t, result.Linked)
	assert.Contains(t, result.Linked, "example.com/linked")
}

// TestRunLoop_UnreachableAdvisoryNeverScanned: scan input is pre-filtered to
// linked modules, so an advisory on an unlinked graph module is never raised
// and never becomes a residual.
func TestRunLoop_UnreachableAdvisoryNeverScanned(t *testing.T) {
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/linked": "v1.0.0", "example.com/testonly": "v1.0.0"},
		linked: []string{"example.com/linked"},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/testonly", id: "GO-9002", fixed: "v2.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{Modroot: "."}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, 1, result.Iterations, "nothing to raise - one iteration")
	assert.Empty(t, result.FinalDeps)
	assert.Empty(t, result.Residuals)
	assert.Empty(t, result.Dropped)
}

// TestRunLoop_ReachabilityFailureFailsOpen: when LinkedModules errors, the
// loop must behave exactly as it did before reachability existed - the
// vulnerable module is raised and validated, nothing is dropped as unlinked.
func TestRunLoop_ReachabilityFailureFailsOpen(t *testing.T) {
	tc := &fakeToolchain{
		base:      map[string]string{"example.com/mod": "v1.0.0"},
		linkedErr: errors.New("go list: build constraints exclude all Go files"),
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/mod", id: "GO-9003", fixed: "v1.2.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot:  ".",
		Baseline: map[string]string{"example.com/mod": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/mod@v1.2.0"}, result.FinalDeps)
	assert.Empty(t, result.Dropped)
	assert.Nil(t, result.Linked, "failed reachability reports no linked set")
}

// TestRunLoop_ReachableModuleStillRaised: regression guard - with an
// explicit (non-nil) linked set containing the module, behavior is
// unchanged from the pre-reachability loop.
func TestRunLoop_ReachableModuleStillRaised(t *testing.T) {
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/mod": "v1.0.0"},
		linked: []string{"example.com/mod"},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/mod", id: "GO-9004", fixed: "v1.3.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot:  ".",
		Baseline: map[string]string{"example.com/mod": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/mod@v1.3.0"}, result.FinalDeps)
	assert.Equal(t, []string{"example.com/mod"}, result.CVEBackedModules)
	assert.Empty(t, result.Dropped)
}

// TestRunLoop_PackageUnreachableSeedDroppedPreApply: the x/sys/windows
// shape - the module IS linked (via another package) but the seed advisory's
// vulnerable packages are not in the artifact's import graph. The seed must
// be shed BEFORE the first apply (a doomed candidate must never perturb the
// graph) with the package-level reason and NO residual.
func TestRunLoop_PackageUnreachableSeedDroppedPreApply(t *testing.T) {
	tc := &fakeToolchain{
		base:       map[string]string{"golang.org/x/sys": "v0.39.0"},
		linked:     []string{"golang.org/x/sys"},
		linkedPkgs: []string{"golang.org/x/sys/unix"},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "golang.org/x/sys", Version: "v0.44.0", FromCVE: true, VulnIDs: []string{"GO-2026-5024"}},
		},
		Baseline:    map[string]string{"golang.org/x/sys": "v0.39.0"},
		VulnImports: map[string][]string{"GO-2026-5024": {"golang.org/x/sys/windows"}},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Empty(t, result.Residuals, "a package-unreachable advisory is neither fixed nor residual")
	assert.Empty(t, tc.getLog, "the doomed seed must never be applied")

	require.Len(t, result.Dropped, 1)
	assert.Contains(t, result.Dropped[0].Reason, "vulnerable package(s) not linked into build artifacts")
}

// TestRunLoop_PackageUnreachableRescanFindingNotRaised: a rescan finding
// whose own OSV metadata places the vulnerable code in an unlinked package
// must be neither raised nor a residual.
func TestRunLoop_PackageUnreachableRescanFindingNotRaised(t *testing.T) {
	tc := &fakeToolchain{
		base:       map[string]string{"golang.org/x/sys": "v0.39.0"},
		linked:     []string{"golang.org/x/sys"},
		linkedPkgs: []string{"golang.org/x/sys/unix"},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "golang.org/x/sys", id: "GO-2026-5024", fixed: "v0.44.0",
			imports: []scan.VulnerableImport{{Path: "golang.org/x/sys/windows", GOOS: []string{"windows"}}}},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{Modroot: "."}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, 1, result.Iterations, "nothing raised - single iteration")
	assert.Empty(t, result.FinalDeps)
	assert.Empty(t, result.Residuals)
	assert.Empty(t, result.Dropped)
}

// TestRunLoop_PackageReachableFindingStillRaised: regression guard - a
// finding whose vulnerable package IS linked behaves exactly as before.
func TestRunLoop_PackageReachableFindingStillRaised(t *testing.T) {
	tc := &fakeToolchain{
		base:       map[string]string{"golang.org/x/sys": "v0.39.0"},
		linked:     []string{"golang.org/x/sys"},
		linkedPkgs: []string{"golang.org/x/sys/unix"},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "golang.org/x/sys", id: "GO-UNIX-1", fixed: "v0.44.0",
			imports: []scan.VulnerableImport{{Path: "golang.org/x/sys/unix"}}},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot:  ".",
		Baseline: map[string]string{"golang.org/x/sys": "v0.39.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"golang.org/x/sys@v0.44.0"}, result.FinalDeps)
}

// TestRunLoop_MaxDepGoVersion: the max is computed across every module in the
// fake's DepGoVersions map, mixing bare-minor and patch forms.
func TestRunLoop_MaxDepGoVersion(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{"example.com/mod": "v1.0.0"},
		depGoVersions: map[string]string{
			"example.com/mod":   "1.24",
			"example.com/other": "1.25.2",
		},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, "1.25.2", result.MaxDepGoVersion)
}

// TestRunLoop_MaxDepGoVersionFailsOpen: a DepGoVersions error leaves the
// field empty without failing the loop.
func TestRunLoop_MaxDepGoVersionFailsOpen(t *testing.T) {
	tc := &fakeToolchain{
		base:             map[string]string{"example.com/mod": "v1.0.0"},
		depGoVersionsErr: errors.New("go list -m -json all: boom"),
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.MaxDepGoVersion)
}

// TestRunLoop_StdPackages: the fake's linked stdlib set is propagated as-is.
func TestRunLoop_StdPackages(t *testing.T) {
	tc := &fakeToolchain{
		base:      map[string]string{"example.com/mod": "v1.0.0"},
		linkedStd: []string{"fmt", "os"},
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, map[string]struct{}{"fmt": {}, "os": {}}, result.StdPackages)
}

// TestRunLoop_StdPackagesFailsOpen: a LinkedStd error leaves the field nil
// without failing the loop.
func TestRunLoop_StdPackagesFailsOpen(t *testing.T) {
	tc := &fakeToolchain{
		base:         map[string]string{"example.com/mod": "v1.0.0"},
		linkedStdErr: errors.New("go list -deps: boom"),
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Nil(t, result.StdPackages)
}

// TestRunLoop_PackageGateFailsOpen: without package metadata (no
// VulnImports, no linkedPkgs) behavior is identical to module-level only.
func TestRunLoop_PackageGateFailsOpen(t *testing.T) {
	tc := &fakeToolchain{
		base:   map[string]string{"golang.org/x/sys": "v0.39.0"},
		linked: []string{"golang.org/x/sys"},
		// linkedPkgs nil: package graph unknown - gates must fail open.
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "golang.org/x/sys", id: "GO-2026-5024", fixed: "v0.44.0",
			imports: []scan.VulnerableImport{{Path: "golang.org/x/sys/windows"}}},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot:  ".",
		Baseline: map[string]string{"golang.org/x/sys": "v0.39.0"},
	}, Options{})

	require.NoError(t, err)
	assert.Equal(t, []string{"golang.org/x/sys@v0.44.0"}, result.FinalDeps, "unknown package graph must not filter")
}

// TestRunLoop_SkipGuardPreventsDowngrade models the crossplane-2.0
// sigstore-go/timestamp-authority cascade: getting sigstore-go@v1.2.0
// transitively raises timestamp-authority past its own candidate version, so
// the timestamp-authority get - which a real go toolchain would execute as a
// DOWNGRADE dragging sigstore-go back to a vulnerable version - must be
// skipped (gobump parity) and the superseded entry dropped from FinalDeps
// entirely, with both advisory sets counted as fixed.
func TestRunLoop_SkipGuardPreventsDowngrade(t *testing.T) {
	const (
		sigstoreGo = "github.com/sigstore/sigstore-go"
		tsa        = "github.com/sigstore/timestamp-authority/v2"
	)
	tc := &fakeToolchain{
		base: map[string]string{sigstoreGo: "v1.1.4", tsa: "v2.0.6"},
		getEffects: map[string]map[string]string{
			sigstoreGo + "@v1.2.0": {tsa: "v2.1.2"},
			tsa + "@v2.1.0":        {sigstoreGo: "v1.1.4"}, // the downgrade, were it ever executed
		},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: sigstoreGo, id: "GO-SIG-1", fixed: "v1.2.0"},
		{module: tsa, id: "GO-TSA-1", fixed: "v2.1.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: sigstoreGo, Version: "v1.2.0", FromCVE: true, VulnIDs: []string{"GO-SIG-1"}},
			{Module: tsa, Version: "v2.1.0", FromCVE: true, VulnIDs: []string{"GO-TSA-1"}},
		},
		Baseline: map[string]string{sigstoreGo: "v1.1.4", tsa: "v2.0.6"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.NotContains(t, tc.getLog, tsa+"@v2.1.0", "the downgrade get must be skipped")
	assert.Equal(t, []string{sigstoreGo + "@v1.2.0"}, result.FinalDeps, "superseded entry must not be written")
	assert.Equal(t, []string{sigstoreGo}, result.CVEBackedModules)
	assert.Equal(t, "v2.1.2", result.Resolved[tsa], "transitively carried above its own candidate")
	assert.Empty(t, result.Residuals, "both advisories are fixed by the surviving entry")
	assert.Empty(t, result.RemainingVulnIDs)
	var reasons []string
	for _, d := range result.Dropped {
		if d.Module == tsa {
			reasons = append(reasons, d.Reason)
		}
	}
	require.Len(t, reasons, 1)
	assert.Contains(t, reasons[0], "superseded")
	assert.Contains(t, reasons[0], "v2.1.2")
}

// TestRunLoop_SkipGuardEqualVersionStillGets: the guard is strict-exceed
// (gobump parity) - a require raised to exactly the candidate version still
// gets, and an exactly-satisfied entry is not a supersession suspect.
func TestRunLoop_SkipGuardEqualVersionStillGets(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{"example.com/a": "v1.0.0", "example.com/b": "v1.0.0"},
		getEffects: map[string]map[string]string{
			"example.com/a@v2.0.0": {"example.com/b": "v2.0.0"},
		},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/a", id: "GO-A-1", fixed: "v2.0.0"},
		{module: "example.com/b", id: "GO-B-1", fixed: "v2.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/a", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-A-1"}},
			{Module: "example.com/b", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-B-1"}},
		},
		Baseline: map[string]string{"example.com/a": "v1.0.0", "example.com/b": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Contains(t, tc.getLog, "example.com/b@v2.0.0", "equal require must still get")
	assert.ElementsMatch(t, []string{"example.com/a@v2.0.0", "example.com/b@v2.0.0"}, result.FinalDeps)
	assert.Equal(t, 1, sc.scans, "no suspects - no supersession trial")
}

// TestRunLoop_SkipGuardLatestNeverSkipped: an @latest fallback bypasses the
// guard entirely - "latest" is not comparable to a require version.
func TestRunLoop_SkipGuardLatestNeverSkipped(t *testing.T) {
	tc := &fakeToolchain{
		base:     map[string]string{"example.com/mod": "v2.5.0"},
		latest:   map[string]string{"example.com/mod": "v3.1.0"},
		failGets: map[string]error{"example.com/mod@v3.0.0": errors.New("unknown revision")},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/mod", id: "GO-M-1", fixed: "v3.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/mod", Version: "v3.0.0", FromCVE: true, VulnIDs: []string{"GO-M-1"}},
		},
		Baseline: map[string]string{"example.com/mod": "v2.5.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Contains(t, tc.getLog, "example.com/mod@latest")
	assert.Equal(t, []string{"example.com/mod@v3.1.0"}, result.FinalDeps)
	assert.Empty(t, result.Residuals)
}

// TestRunLoop_SupersessionTrialRejectedKeepsEntry: a suspect whose explicit
// get had load-bearing side effects (its closure fixed a third, non-candidate
// module) is kept - the trial without it re-exposes that module's advisory as
// a raise, rejecting the reduced set.
func TestRunLoop_SupersessionTrialRejectedKeepsEntry(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/a": "v1.0.0",
			"example.com/b": "v1.0.0",
			"example.com/d": "v1.0.0",
		},
		getEffects: map[string]map[string]string{
			"example.com/b@v1.4.0": {"example.com/d": "v2.0.0"},
			"example.com/a@v2.0.0": {"example.com/b": "v1.5.0"},
		},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/a", id: "GO-A-1", fixed: "v2.0.0"},
		{module: "example.com/b", id: "GO-B-1", fixed: "v1.4.0"},
		{module: "example.com/d", id: "GO-D-1", fixed: "v2.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		// b first: its get executes (and fixes d) before a's closure raises b
		// past its own candidate version, making b a supersession suspect.
		Seeds: []Candidate{
			{Module: "example.com/b", Version: "v1.4.0", FromCVE: true, VulnIDs: []string{"GO-B-1"}},
			{Module: "example.com/a", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-A-1"}},
		},
		Baseline: map[string]string{"example.com/a": "v1.0.0", "example.com/b": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.ElementsMatch(t, []string{"example.com/a@v2.0.0", "example.com/b@v1.4.0"}, result.FinalDeps,
		"the suspect is load-bearing and must be kept")
	for _, d := range result.Dropped {
		assert.NotContains(t, d.Reason, "superseded")
	}
	assert.Empty(t, result.Residuals)
	assert.Equal(t, "v2.0.0", result.Resolved["example.com/d"])
}

// TestRunLoop_AbandonedFixResidualNotSilentlyVanished: a CVE candidate
// dropped on the residual-free "pruned: not required" path, whose module is
// nonetheless still in the resolved graph at a vulnerable version, must
// surface as a residual - never vanish (and never count as fixed).
func TestRunLoop_AbandonedFixResidualNotSilentlyVanished(t *testing.T) {
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/ghost": "v1.0.0"},
		pruned: map[string]bool{"example.com/ghost": true},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/ghost", id: "GO-G-1", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/ghost", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-G-1"}},
		},
		Baseline: map[string]string{"example.com/ghost": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	require.Len(t, result.Residuals, 1)
	residual := result.Residuals[0]
	assert.Equal(t, "example.com/ghost", residual.Module)
	assert.Equal(t, "v1.0.0", residual.ResolvedVersion)
	assert.Equal(t, []string{"GO-G-1"}, residual.VulnIDs)
	assert.Contains(t, residual.Reason, "fix abandoned")
	assert.Contains(t, residual.Reason, "pruned by go mod tidy")
	assert.Contains(t, residual.Reason, "advisory persists at v1.0.0")
	assert.Contains(t, result.RemainingVulnIDs, "GO-G-1")
}

// TestRunLoop_PrunedPromotedReplaceBackfillsResidual: same invariant through
// checkReplaceCandidate's residual-free "replaced module no longer required"
// path - the promoted replace's module still resolves vulnerable.
func TestRunLoop_PrunedPromotedReplaceBackfillsResidual(t *testing.T) {
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/phantom": "v1.0.0"},
		pruned: map[string]bool{"example.com/phantom": true},
		failGets: map[string]error{
			"example.com/phantom@v1.5.0": errors.New("unknown revision"),
			"example.com/phantom@latest": errors.New("proxy unavailable"),
		},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/phantom", id: "GO-P-1", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/phantom", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-P-1"}},
		},
		Baseline: map[string]string{"example.com/phantom": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	assert.Empty(t, result.FinalReplaces)
	require.Len(t, result.Residuals, 1)
	residual := result.Residuals[0]
	assert.Contains(t, residual.Reason, "fix abandoned")
	assert.Contains(t, residual.Reason, "replaced module no longer required")
	assert.Contains(t, result.RemainingVulnIDs, "GO-P-1")
}

// TestRunLoop_IntroducedFixableAdvisoryRaisedAndFixed: an advisory that
// applies only to the bumped-to version and HAS a fix is raised and applied
// by the fixpoint loop - nothing residual, nothing to classify.
func TestRunLoop_IntroducedFixableAdvisoryRaisedAndFixed(t *testing.T) {
	tc := &fakeToolchain{base: map[string]string{"example.com/step": "v1.0.0"}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/step", id: "GO-S-1", fixed: "v1.5.0"},
		{module: "example.com/step", id: "GO-S-2", introduced: "v1.4.0", fixed: "v1.8.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/step", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-S-1"}},
		},
		Baseline:        map[string]string{"example.com/step": "v1.0.0"},
		BaselineVulnIDs: map[string]struct{}{"GO-S-1": {}},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, 2, result.Iterations)
	assert.Equal(t, []string{"example.com/step@v1.8.0"}, result.FinalDeps)
	assert.Empty(t, result.Residuals)
}

// TestRunLoop_IntroducedUnfixableAdvisoryClassified: an advisory that applies
// only to the bumped-to version with NO released fix is accepted (the fix
// forward is still right) but classified and reported as introduced.
func TestRunLoop_IntroducedUnfixableAdvisoryClassified(t *testing.T) {
	tc := &fakeToolchain{base: map[string]string{"example.com/fwd": "v1.0.0"}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/fwd", id: "GO-OLD-1", fixed: "v2.0.0"},
		{module: "example.com/fwd", id: "GO-NEW-1", introduced: "v2.0.0"}, // no released fix
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/fwd", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-OLD-1"}},
		},
		Baseline:        map[string]string{"example.com/fwd": "v1.0.0"},
		BaselineVulnIDs: map[string]struct{}{"GO-OLD-1": {}},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/fwd@v2.0.0"}, result.FinalDeps, "the forward fix still applies")
	require.Len(t, result.Residuals, 1)
	residual := result.Residuals[0]
	assert.True(t, residual.Introduced)
	assert.Equal(t, []string{"GO-NEW-1"}, residual.VulnIDs)
	assert.Contains(t, residual.Reason, "introduced by bump to v2.0.0")
	assert.Contains(t, residual.Reason, "not present at baseline")
	assert.Contains(t, residual.Reason, "no released fix")
}

// TestRunLoop_NilBaselineSkipsClassification: without BaselineVulnIDs the
// classification is disabled entirely (fail open) - existing callers see
// unchanged residuals.
func TestRunLoop_NilBaselineSkipsClassification(t *testing.T) {
	tc := &fakeToolchain{base: map[string]string{"example.com/fwd": "v1.0.0"}}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/fwd", id: "GO-OLD-1", fixed: "v2.0.0"},
		{module: "example.com/fwd", id: "GO-NEW-1", introduced: "v2.0.0"}, // no released fix
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/fwd", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-OLD-1"}},
		},
		Baseline: map[string]string{"example.com/fwd": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	require.Len(t, result.Residuals, 1)
	assert.False(t, result.Residuals[0].Introduced)
	assert.Equal(t, "no released fix", result.Residuals[0].Reason)
}

// TestRunLoop_DegradedReachability_UnrequiredModuleNotResidual: the flux
// mirror. Precise reachability is unavailable (linkedErr), but the tidied
// go.mod's go directive qualifies (>= 1.17, the default fixture), so the
// degraded module-level signal takes over: graphonly is pruned by tidy
// (never required) and must be reported as UNLINKED (via UnrequiredModules
// and an empty Residuals set), never as a residual. The redundant coherence
// seed on linkedmod forces confirmMinimalSet to run a trial - proving the
// MANDATORY trialApply/scanTargets filtering (Step 2): without it, the
// unfiltered trial rescan would see graphonly's advisory as newly introduced
// (a major-version residual) and reject the trial.
func TestRunLoop_DegradedReachability_UnrequiredModuleNotResidual(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/linkedmod": "v1.0.0",
			"example.com/graphonly": "v1.0.0",
		},
		pruned:    map[string]bool{"example.com/graphonly": true},
		linkedErr: errors.New("go list -deps: build constraints exclude all Go files"),
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/graphonly", id: "GO-GRAPH-1", fixed: "v2.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/graphonly", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-GRAPH-1"}},
			{Module: "example.com/linkedmod", Version: "v1.1.0"}, // coherence-only
		},
		Baseline: map[string]string{
			"example.com/linkedmod": "v1.0.0",
			"example.com/graphonly": "v1.0.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Nil(t, result.Linked, "precise reachability unavailable")
	assert.Empty(t, result.FinalDeps, "graphonly must not survive: pruned and unlinkable")
	assert.Empty(t, result.Residuals, "an unrequired-and-unlinkable module is neither fixed nor residual")

	var graphonlyDropped bool
	for _, d := range result.Dropped {
		if d.Module == "example.com/graphonly" {
			graphonlyDropped = true
			assert.Contains(t, d.Reason, "pruned by go mod tidy: not required by the tidied go.mod")
		}
	}
	assert.True(t, graphonlyDropped, "graphonly must be recorded as dropped")

	require.NotNil(t, result.UnrequiredModules)
	assert.Equal(t, map[string]struct{}{"example.com/graphonly": {}}, result.UnrequiredModules)
}

// TestRunLoop_DegradedReachability_NoFixNotResidual: mirrors the "no
// released fix" case - without the degraded filter, graphonly would surface
// a "no released fix" residual purely because it's still in the resolved
// build list; the degraded signal must exclude it from the rescan entirely
// (it's provably never linked) so no residual is ever synthesized.
func TestRunLoop_DegradedReachability_NoFixNotResidual(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/other":     "v1.0.0",
			"example.com/graphonly": "v1.0.0",
		},
		pruned:    map[string]bool{"example.com/graphonly": true},
		linkedErr: errors.New("go list -deps: build constraints exclude all Go files"),
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/graphonly", id: "GO-GRAPH-2"}, // no released fix
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.Residuals, "graphonly's advisory must never be scanned in degraded mode")
	require.NotNil(t, result.UnrequiredModules)
	assert.Contains(t, result.UnrequiredModules, "example.com/graphonly")
}

// TestRunLoop_DegradedReachability_OldGoDirectiveDisablesSignal: the go
// directive guard. A pre-1.17 tidied go.mod cannot be trusted to cover the
// full import closure in its require block, so the degraded signal must stay
// off entirely and behavior reverts to the OLD (pre-degraded-signal)
// outcome: the abandoned fix surfaces as a residual, exactly like
// TestRunLoop_AbandonedFixResidualNotSilentlyVanished.
func TestRunLoop_DegradedReachability_OldGoDirectiveDisablesSignal(t *testing.T) {
	tc := &fakeToolchain{
		base:      map[string]string{"example.com/ghost": "v1.0.0"},
		pruned:    map[string]bool{"example.com/ghost": true},
		linkedErr: errors.New("go list -deps: build constraints exclude all Go files"),
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/ghost", id: "GO-G-1", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDirWithGo(t, "1.16"), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/ghost", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-G-1"}},
		},
		Baseline: map[string]string{"example.com/ghost": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Empty(t, result.FinalDeps)
	require.Len(t, result.Residuals, 1)
	residual := result.Residuals[0]
	assert.Equal(t, "example.com/ghost", residual.Module)
	assert.Equal(t, "v1.0.0", residual.ResolvedVersion)
	assert.Contains(t, residual.Reason, "fix abandoned")
	assert.Contains(t, residual.Reason, "pruned by go mod tidy: not required by the tidied go.mod")
	assert.Contains(t, residual.Reason, "advisory persists at v1.0.0")
	assert.Nil(t, result.UnrequiredModules, "a pre-1.17 tidied go.mod must disable the degraded signal")
}

// TestRunLoop_DegradedReachability_ReplaceResolvedNotUnrequired: the
// replace-resolved edge case. The require block names the OLD (replaced)
// path; the resolved graph and the advisory both name the NEW (replacement)
// path. degradedUnlinked must fail open through the replace identity - the
// module is genuinely required (under its old name) and must neither land
// in UnrequiredModules nor get an info-classification; the fix proceeds
// normally via the replace channel.
func TestRunLoop_DegradedReachability_ReplaceResolvedNotUnrequired(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{"example.com/old": "v1.0.0"},
		pristineReplaces: map[string]ReplaceTarget{
			"example.com/old": {Path: "example.com/new", Version: "v1.0.0"},
		},
		linkedErr: errors.New("go list -deps: build constraints exclude all Go files"),
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/new", id: "GO-NEW-1", fixed: "v2.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/new", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-NEW-1"}},
		},
		Baseline: map[string]string{"example.com/new": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/old=example.com/new@v2.0.0"}, result.FinalReplaces,
		"the fix must proceed via the replace channel")
	assert.Empty(t, result.Residuals)

	require.NotNil(t, result.UnrequiredModules)
	assert.NotContains(t, result.UnrequiredModules, "example.com/new",
		"the replace's old path is required, so the new path must not be classified unrequired")
}

// TestRunLoop_DegradedReachability_PrecisePathUnaffected: regression guard -
// with precise reachability available (linked non-nil), UnrequiredModules
// must stay nil and existing pruned-module residual behavior is byte-for-
// byte identical to TestRunLoop_AbandonedFixResidualNotSilentlyVanished.
func TestRunLoop_DegradedReachability_PrecisePathUnaffected(t *testing.T) {
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/ghost": "v1.0.0"},
		pruned: map[string]bool{"example.com/ghost": true},
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/ghost", id: "GO-G-1", fixed: "v1.5.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/ghost", Version: "v1.5.0", FromCVE: true, VulnIDs: []string{"GO-G-1"}},
		},
		Baseline: map[string]string{"example.com/ghost": "v1.0.0"},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	require.NotNil(t, result.Linked, "this fixture's default fake behavior reports precise reachability")
	assert.Nil(t, result.UnrequiredModules, "precise reachability must disable the degraded signal")
	require.Len(t, result.Residuals, 1)
	assert.Contains(t, result.Residuals[0].Reason, "fix abandoned")
}

// TestRunLoop_DegradedReachability_LinkedStdWarnOnce: the linked-stdlib
// lookup can fire twice per RunLoop call (once post-fixpoint, once more from
// adoptTrial when a refinement phase adopts a trial) - the warning must log
// only once. Mirrors TestRunLoop_ConfirmMinimalSetRecomputesCapabilitiesOnAdoption's
// fixture (a redundant coherence pin forces confirmMinimalSet to adopt a
// trial) with a failing LinkedStd instead of a fake capability function.
func TestRunLoop_DegradedReachability_LinkedStdWarnOnce(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/vuln": "v1.9.0",
		},
		linkedStdErr: errors.New("go list -deps: boom"),
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/vuln", id: "GO-VULN-1", fixed: "v2.0.0"},
	}}

	handler := &countingHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/pin", Version: "v1.5.0"},
			{Module: "example.com/vuln", Version: "v2.0.0", FromCVE: true, VulnIDs: []string{"GO-VULN-1"}},
		},
		Baseline: map[string]string{
			"example.com/pin":  "v1.0.0",
			"example.com/vuln": "v1.9.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	require.Len(t, result.Dropped, 1, "pin must be dropped as redundant for adoptTrial to fire")
	assert.Equal(t, 1, handler.count("linked stdlib package lookup unavailable"),
		"the warning must be logged exactly once despite two lookup attempts")
}

// TestRunLoop_DegradedReachability_TrialUsesTrialRequirements: the
// trialApply/scanTargets wiring is load-bearing (Step 2's "MANDATORY" call
// site) - proven here by a fixture where the trial's requirements genuinely
// differ from the main loop's, unlike every other degraded fixture (which
// uses the fake's STATIC `pruned` set, identical in the main loop and every
// trial). `pruneUnless` ties graphonly's presence in Requirements() to
// whether pin's `go get` ran THIS attempt:
//
//   - Main loop: pin is applied (coherence seed, redundant), and its
//     getEffects simultaneously raise graphonly to the fixed version -
//     graphonly is required (pin's closure pulls it in) but not vulnerable
//     there, so it scans clean and never becomes a residual.
//   - confirmMinimalSet's trial drops pin (not essential: no CVE, no
//     remedy, not a replace seed). Without pin's get, graphonly reverts to
//     its base (vulnerable) version AND drops out of tr.requirements -
//     degradedUnlinked correctly excludes it from the trial's rescan, the
//     trial sees no new advisories, and pin is confirmed redundant.
//
// Mutating trialApply's scanTargets call to pass l.requirements/l.replaces
// (the main loop's STALE, pin-applied requirements) instead of
// tr.requirements/tr.replaces makes degradedUnlinked wrongly see graphonly
// as required in the trial too - it gets scanned at its reverted vulnerable
// version, "fix requires major version import path change" surfaces as a
// brand-new residual (absent from the main loop's clean scan), and the
// trial is wrongly rejected: pin survives. Verified by hand-applying that
// exact mutation (see task-r1-report.md, Fix round 1) - it flips this
// test's assertions and passes with the wiring restored.
func TestRunLoop_DegradedReachability_TrialUsesTrialRequirements(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/pin":       "v1.0.0",
			"example.com/graphonly": "v1.0.0",
		},
		pruneUnless: map[string]string{"example.com/graphonly": "example.com/pin"},
		getEffects: map[string]map[string]string{
			"example.com/pin@v1.1.0": {"example.com/graphonly": "v2.0.0"},
		},
		linkedErr: errors.New("go list -deps: build constraints exclude all Go files"),
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/graphonly", id: "GO-GRAPH-3", fixed: "v2.0.0"},
	}}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/pin", Version: "v1.1.0"}, // coherence-only, redundant
		},
		Baseline: map[string]string{
			"example.com/pin":       "v1.0.0",
			"example.com/graphonly": "v1.0.0",
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Nil(t, result.Linked, "precise reachability unavailable")

	require.Len(t, result.Dropped, 1, "the trial-filtered rescan must confirm pin redundant")
	assert.Equal(t, "example.com/pin", result.Dropped[0].Module)
	assert.Contains(t, result.Dropped[0].Reason, "redundant")

	assert.Empty(t, result.FinalDeps, "pin must not survive: confirmed redundant")
	assert.Empty(t, result.Residuals,
		"graphonly's advisory must never surface: clean in the main loop, correctly filtered from the trial")
	assert.Contains(t, result.UnrequiredModules, "example.com/graphonly",
		"the adopted (trial) graph must reclassify graphonly as unrequired")
}

// TestRunLoop_DegradedReachability_SelfReplaceKeyFailsOpen: degradedUnlinked's
// first replace check (`replaces[module]` - a direct KEY hit) covers a
// self-replace (`replace m => m vX`, OldPath == Module): the module appears
// as a replace key AND is absent from the require block (a user-authored
// self-pin the tidied go.mod never lists in require - distinct from
// ReplaceResolvedNotUnrequired's old-path-required branch, which covers an
// old != new replace instead). Must fail open (never classified unrequired).
func TestRunLoop_DegradedReachability_SelfReplaceKeyFailsOpen(t *testing.T) {
	tc := &fakeToolchain{
		base: map[string]string{
			"example.com/other":   "v1.0.0",
			"example.com/selfpin": "v1.0.0",
		},
		pruned:    map[string]bool{"example.com/selfpin": true},
		linkedErr: errors.New("go list -deps: build constraints exclude all Go files"),
	}
	sc := &fakeScanner{}

	result, err := RunLoop(t.Context(), tc, sc, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/selfpin", Version: "v1.0.0", Replace: true, ReplaceOld: "example.com/selfpin"},
		},
	}, Options{})

	require.NoError(t, err)
	assert.True(t, result.Converged)
	assert.Equal(t, []string{"example.com/selfpin=example.com/selfpin@v1.0.0"}, result.FinalReplaces,
		"the self-replace must survive: checkReplaceCandidate never demands it be required")

	require.NotNil(t, result.UnrequiredModules)
	assert.NotContains(t, result.UnrequiredModules, "example.com/selfpin",
		"a module present as a replace KEY must fail open, not be classified unrequired")
}
