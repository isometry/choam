// Package simulate validates a proposed set of Go module bumps by doing what
// the melange build's bump step will do, ahead of time: clone the upstream
// source at the exact tag, apply the bumps with the step's own semantics
// (gobump for `uses: go/bump`, omnibump for `uses: bump` - see Engine), then
// OSV-rescan the resolved module graph and raise versions until a fixpoint.
// The deps list that survives is proven to (a) resolve cleanly and (b) leave
// no known-fixable vulnerability behind; anything unreachable is reported as
// a residual rather than silently dropped.
package simulate

import (
	"context"
	"slices"
	"time"

	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/semver"
)

// Toolchain abstracts the go tool operations the simulation needs. The real
// implementation shells out to the local go binary (see NewToolchain); tests
// inject fakes.
type Toolchain interface {
	// ModTidy runs `go mod tidy` in dir.
	ModTidy(ctx context.Context, dir string) error
	// Get runs `go get module@version` in dir.
	Get(ctx context.Context, dir, moduleAtVersion string) error
	// ListModules returns the resolved module graph (module path -> version)
	// from `go list -m all` in dir, with replace directives applied and the
	// main module and local-path replacements omitted.
	ListModules(ctx context.Context, dir string) (map[string]string, error)
	// Requirements returns the require entries (module path -> version) of
	// dir's go.mod as written - the set melange's gobump verifies deps
	// entries against after its final tidy.
	Requirements(ctx context.Context, dir string) (map[string]string, error)
	// DepGoVersions returns the go directive of every non-main module in the
	// build list (bare form, e.g. "1.24" or "1.24.5"), keyed by module path,
	// with replace directives applied (same skip-main semantics as
	// ListModules).
	DepGoVersions(ctx context.Context, dir string) (map[string]string, error)
	// Replace applies a replace directive (gobump parity:
	// `go mod edit -dropreplace=<old>` then `-replace=<old>=<new>@<version>`).
	Replace(ctx context.Context, dir, oldPath, newPath, version string) error
	// Replaces returns dir's go.mod replace directives keyed by Old.Path; a
	// local filesystem target is reported with Version == "".
	Replaces(ctx context.Context, dir string) (map[string]ReplaceTarget, error)
	// Linked returns the module paths AND package import paths in the
	// transitive non-test import graph of the given build patterns (empty
	// means ./...) - the modules the linker records in the binary's
	// buildinfo, i.e. what actually ships, plus the package-level detail
	// for checking advisories' vulnerable import paths. Errors make
	// reachability filtering fail OPEN (treat everything as linked).
	Linked(ctx context.Context, dir string, patterns []string) (modules, packages map[string]struct{}, err error)
	// LinkedStd returns the set of standard-library import paths in the
	// transitive non-test import graph of the given build patterns (empty
	// means ./...), evaluated for GOOS=linux (same walk semantics as
	// Linked, inverted filter).
	LinkedStd(ctx context.Context, dir string, patterns []string) (map[string]struct{}, error)
}

// Compiler is the optional compile-gate seam: a Toolchain that also
// implements it enables the post-convergence compile gate (see
// loop.compileGate), unless Options.NoCompile is set. *GoToolchain
// implements it.
type Compiler interface {
	// Compile compiles (without linking) the transitive non-test import
	// graph of patterns (empty means ./...) with the given build tags for
	// GOOS=linux, reporting per-package failures. An error return means the
	// go tool itself could not run, not that packages failed to compile.
	Compile(ctx context.Context, dir string, patterns, tags []string) (*CompileReport, error)
	// ModuleVersions lists module's released versions, ascending.
	ModuleVersions(ctx context.Context, dir, module string) ([]string, error)
	// ModuleRequires returns the require entries of module@version's own
	// go.mod.
	ModuleRequires(ctx context.Context, dir, module, version string) (map[string]string, error)
}

// CompileReport is the outcome of one Compiler.Compile.
type CompileReport struct {
	// Failed maps each package that failed to compile to its first error
	// lines ("# pkg" header stripped).
	Failed map[string][]string
	// Modules maps every non-standard package in the graph to its module
	// path (replacement applied); "" for main-module packages.
	Modules map[string]string
	// Imports holds the direct imports of each failed package, for repair
	// and relaxation attribution.
	Imports map[string][]string
	// FileModules maps module-cache file paths named in error lines
	// (<GOMODCACHE>/<mod>@<ver>/...) back to "module@version".
	FileModules map[string]string
}

// ReplaceTarget is the right-hand side of a go.mod replace directive.
type ReplaceTarget struct {
	Path    string
	Version string // empty for local filesystem replacements
}

// Scanner is the vulnerability-scanning seam; *scan.VulnerabilityScanner
// satisfies it.
type Scanner interface {
	ScanPackages(ctx context.Context, pkgs []scan.Package) (*scan.ScanResult, error)
}

// Candidate is one proposed module@version bump. FromCVE marks candidates
// backed by an OSV advisory: they are defended (retried at @latest, reported
// as residuals when unreachable), whereas coherence-only candidates
// (carried-forward pins) are the first to be sacrificed when the
// module graph won't resolve.
type Candidate struct {
	Module  string
	Version string
	FromCVE bool
	VulnIDs []string
	// Severity is the most severe advisory level the candidate addresses
	// (scan.SeverityRank vocabulary; empty when unknown).
	Severity string

	// Rungs is the candidate's fix ladder, highest first: one rung per
	// distinct advisory fix version (plus an existing YAML version), each
	// with the advisories it first fixes. The compile gate relaxes a
	// candidate whose version breaks the build one rung down. Empty means
	// the single rung {Version, VulnIDs, Severity}.
	Rungs []Rung

	// Replace marks a candidate applied as a go.mod replace directive
	// (survives `go mod tidy`, unlike a plain require pin) rather than a
	// `go get`. ReplaceOld is the directive's left-hand side; empty means a
	// self-replace (ReplaceOld == Module). User-authored YAML replaces enter
	// as replace seeds; the loop also promotes tidy-unsustainable CVE pins.
	Replace    bool
	ReplaceOld string
}

// OldPath returns the replace directive's left-hand side, defaulting to the
// module itself (self-replace).
func (c Candidate) OldPath() string {
	if c.ReplaceOld != "" {
		return c.ReplaceOld
	}
	return c.Module
}

// Rung is one step of a candidate's fix ladder: a target version and the
// advisories (with their most severe level) first fixed at it.
type Rung struct {
	Version  string
	VulnIDs  []string
	Severity string
}

// fixRungs returns c's ladder, defaulting to its single implicit rung.
func (c Candidate) fixRungs() []Rung {
	if len(c.Rungs) > 0 {
		return c.Rungs
	}
	return []Rung{{Version: c.Version, VulnIDs: c.VulnIDs, Severity: c.Severity}}
}

// FixRungs builds module's fix ladder from scan findings: one rung per
// distinct fixed version among module's advisories (restricted to ids when
// non-empty), plus a bare rung for each of also not already present
// (existing pins), highest first.
func FixRungs(vulns []scan.Vulnerability, module string, ids []string, also ...string) []Rung {
	var rungs []Rung
	for _, v := range vulns {
		if v.Module != module || v.FixedVersion == "" || (len(ids) > 0 && !slices.Contains(ids, v.ID)) {
			continue
		}
		rungs = mergeRungs(rungs, []Rung{{Version: v.FixedVersion, VulnIDs: []string{v.ID}, Severity: v.Severity}})
	}
	for _, version := range also {
		rungs = mergeRungs(rungs, []Rung{{Version: version}})
	}
	return rungs
}

// mergeRungs unions two ladders by version (advisories merged, most severe
// level kept), dropping non-semver versions (@latest), highest first.
func mergeRungs(a, b []Rung) []Rung {
	byVersion := make(map[string]*Rung)
	var merged []Rung
	for _, r := range append(append([]Rung{}, a...), b...) {
		if !semver.IsValid(r.Version) {
			continue
		}
		if existing, ok := byVersion[r.Version]; ok {
			existing.VulnIDs = mergeIDs(existing.VulnIDs, r.VulnIDs)
			existing.Severity = mergeSeverity(existing.Severity, r.Severity)
			continue
		}
		byVersion[r.Version] = &Rung{Version: r.Version, VulnIDs: r.VulnIDs, Severity: r.Severity}
	}
	for _, r := range byVersion {
		merged = append(merged, *r)
	}
	slices.SortFunc(merged, func(x, y Rung) int { return semver.Compare(y.Version, x.Version) })
	return merged
}

// DroppedCandidate records a candidate removed during simulation and why.
type DroppedCandidate struct {
	Module  string `json:"module" yaml:"module"`
	Version string `json:"version" yaml:"version"`
	Reason  string `json:"reason" yaml:"reason"`
	// Redundant marks an entry removed because it did no work: it matched or
	// regressed upstream, or the final tidied go.mod is identical without it.
	Redundant bool `json:"redundant,omitempty" yaml:"redundant,omitempty"`
}

// Residual is a vulnerability the simulation could not eliminate, with the
// reason zero-vulnerability state is unreachable for it.
type Residual struct {
	Module          string   `json:"module" yaml:"module"`
	ResolvedVersion string   `json:"resolved_version" yaml:"resolved_version"`
	FixedVersion    string   `json:"fixed_version,omitempty" yaml:"fixed_version,omitempty"` // empty: no released fix
	VulnIDs         []string `json:"vuln_ids,omitempty" yaml:"vuln_ids,omitempty"`
	Reason          string   `json:"reason" yaml:"reason"`

	// Introduced marks an advisory absent from the baseline analysis scan -
	// it applies only to a version the bump itself moved to, not to the
	// original graph. Accounting must not subtract introduced residuals from
	// the baseline "found" count.
	Introduced bool `json:"introduced,omitempty" yaml:"introduced,omitempty"`
}

// ModrootResult is the outcome of simulating one module root.
type ModrootResult struct {
	Modroot string `json:"modroot" yaml:"modroot"`

	// FinalDeps are the module@version entries proven to apply cleanly, in
	// stable (indirect -> direct -> new, alphabetical within group) order,
	// filtered to entries that actually move the module graph forward
	// relative to the original manifest.
	FinalDeps []string `json:"final_deps" yaml:"final_deps"`

	// FinalReplaces are the replace directives ("old=new@version", gobump
	// grammar) proven to apply cleanly: user-authored seeds plus pins the
	// loop promoted because go mod tidy would not sustain them as plain
	// requires. Note a replace pins its module exactly - future graph
	// demands for a higher version are overridden until a later choam run
	// re-raises the directive.
	FinalReplaces []string `json:"final_replaces,omitempty" yaml:"final_replaces,omitempty"`

	// Resolved is the full module graph (module -> version) after the final
	// clean apply.
	Resolved map[string]string `json:"-" yaml:"-"`

	// Linked is the artifact-linked module set of the final clean state
	// (see Toolchain.Linked); nil when reachability was unavailable and
	// the loop failed open (everything treated as linked). Callers use it
	// to tell which analysis-time findings never affected the artifact.
	Linked map[string]struct{} `json:"-" yaml:"-"`

	// LinkedPackages is the package-level companion of Linked: the import
	// paths in the artifact's non-test import graph, for checking an
	// advisory's vulnerable import paths (nil when unavailable - fail open).
	LinkedPackages map[string]struct{} `json:"-" yaml:"-"`

	// Requires are the final tidied go.mod require entries (module ->
	// version) - the sustainability contract melange's gobump verifies
	// deps entries against. A pin at (or below) its module's Requires
	// version is proven; anything above is not.
	Requires map[string]string `json:"-" yaml:"-"`

	// UnrequiredModules is the degraded module-level reachability signal,
	// populated ONLY when Linked is nil (the go list -deps walk failed open)
	// and the tidied go.mod's go directive is >= 1.17: modules present in
	// Resolved but absent from the tidied require block under any replace
	// identity. Such modules provide no package in the main module's import
	// closure and cannot be linked into any artifact. nil when unavailable or
	// when Linked is authoritative. Module-granular: unlike Linked, membership
	// of the COMPLEMENT does not imply linked (test-only deps are required but
	// never ship).
	UnrequiredModules map[string]struct{} `json:"-" yaml:"-"`

	// MaxDepGoVersion is the highest go directive across the final resolved
	// build list's non-main modules (bare form, e.g. "1.25"); empty when
	// unavailable. The scratch main module's own directive is deliberately
	// not consulted: the engine rewrites it (gobump: -go=<host>; omnibump:
	// lowered to the build's Go).
	MaxDepGoVersion string `json:"max_dep_go_version,omitempty" yaml:"max_dep_go_version,omitempty"`

	// StdPackages is the stdlib slice of the final artifact import graph
	// (LinkedStd over the converged checkout); nil when unknown.
	StdPackages map[string]struct{} `json:"-" yaml:"-"`

	// CVEBackedModules lists the modules in FinalDeps whose entries address
	// at least one advisory (vs coherence-only pins) - the simulation-time
	// equivalent of the checker's SecurityBumpModules.
	CVEBackedModules []string `json:"cve_backed_modules,omitempty" yaml:"cve_backed_modules,omitempty"`

	Residuals []Residual         `json:"residuals,omitempty" yaml:"residuals,omitempty"`
	Dropped   []DroppedCandidate `json:"dropped,omitempty" yaml:"dropped,omitempty"`

	// RemainingVulnIDs are the advisory IDs still present in the final
	// resolved graph (the union of all residuals' VulnIDs).
	RemainingVulnIDs []string `json:"remaining_vuln_ids,omitempty" yaml:"remaining_vuln_ids,omitempty"`

	Iterations int  `json:"iterations" yaml:"iterations"`
	Converged  bool `json:"converged" yaml:"converged"`
}

// ModrootRequest describes one module root to simulate.
type ModrootRequest struct {
	Modroot string
	Seeds   []Candidate
	// Baseline maps module path -> effective version in the original
	// manifest (replace directives applied). FinalDeps entries that don't
	// move a module beyond its baseline are dropped as no-ops.
	Baseline map[string]string
	// Packages are the build package patterns (relative to Modroot,
	// go/build's space-separated with.packages grammar) whose non-test
	// import graphs define artifact reachability; empty falls back to ./...
	// (over-approximate, never narrower than the artifact).
	Packages []string
	// Tags are the go/build steps' build tags (toolchaintags plus tags),
	// applied by the compile gate so it type-checks the files the build
	// will compile.
	Tags []string
	// VulnImports maps each seed advisory ID to the import paths its
	// vulnerable code lives in (from the analysis scan's OSV metadata; see
	// scan.Vulnerability.VulnerableImports). Seed candidates whose
	// advisories all live in unlinked packages are dropped before the
	// first apply. Absent/empty entries fail open.
	VulnImports map[string][]string
	// BaselineVulnIDs are the advisory IDs the analysis scan found in the
	// pristine graph. Residual advisories with no ID in this set were
	// INTRODUCED by the bump (they apply only to a bumped-to version) and
	// are reported and counted separately. Nil disables introduced-vuln
	// classification (fail open).
	BaselineVulnIDs map[string]struct{}
	// Engine is the bump step's apply semantics (see Engine).
	Engine Engine
	// NoTidy mirrors a `tidy: false` bump step: the engine runs no go mod
	// tidy at all.
	NoTidy bool
	// GoVersion is the build's Go version (bare, e.g. "1.25.9"); omnibump
	// lowers the go directive to it, never raises it. "" means the host go
	// (EngineOmnibump only).
	GoVersion string
}

// Options tunes the simulation.
type Options struct {
	// MaxIterations caps the raise-and-rescan fixpoint loop (default 5).
	MaxIterations int
	// CommandTimeout bounds each go tool invocation (default 2m).
	CommandTimeout time.Duration
	// Budget bounds the whole per-package simulation (default 10m).
	Budget time.Duration
	// NoCompile disables the compile gate (see Compiler).
	NoCompile bool
}

// WithDefaults fills unset options.
func (o Options) WithDefaults() Options {
	if o.MaxIterations <= 0 {
		o.MaxIterations = 5
	}
	if o.CommandTimeout <= 0 {
		o.CommandTimeout = 2 * time.Minute
	}
	if o.Budget <= 0 {
		o.Budget = 10 * time.Minute
	}
	return o
}
