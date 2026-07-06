// Package simulate validates a proposed set of Go module bumps by doing what
// the melange build's go/bump step will do, ahead of time: clone the upstream
// source at the exact tag, apply the bumps with the real go toolchain, then
// OSV-rescan the resolved module graph and raise versions until a fixpoint.
// The deps list that survives is proven to (a) resolve cleanly and (b) leave
// no known-fixable vulnerability behind; anything unreachable is reported as
// a residual rather than silently dropped.
package simulate

import (
	"context"
	"time"

	"github.com/isometry/choam/internal/scan"
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

// DroppedCandidate records a candidate removed during simulation and why.
type DroppedCandidate struct {
	Module  string `json:"module" yaml:"module"`
	Version string `json:"version" yaml:"version"`
	Reason  string `json:"reason" yaml:"reason"`
}

// Residual is a vulnerability the simulation could not eliminate, with the
// reason zero-vulnerability state is unreachable for it.
type Residual struct {
	Module          string   `json:"module" yaml:"module"`
	ResolvedVersion string   `json:"resolved_version" yaml:"resolved_version"`
	FixedVersion    string   `json:"fixed_version,omitempty" yaml:"fixed_version,omitempty"` // empty: no released fix
	VulnIDs         []string `json:"vuln_ids,omitempty" yaml:"vuln_ids,omitempty"`
	Reason          string   `json:"reason" yaml:"reason"`
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
	// VulnImports maps each seed advisory ID to the import paths its
	// vulnerable code lives in (from the analysis scan's OSV metadata; see
	// scan.Vulnerability.VulnerableImports). Seed candidates whose
	// advisories all live in unlinked packages are dropped before the
	// first apply. Absent/empty entries fail open.
	VulnImports map[string][]string
}

// Options tunes the simulation.
type Options struct {
	// MaxIterations caps the raise-and-rescan fixpoint loop (default 5).
	MaxIterations int
	// CommandTimeout bounds each go tool invocation (default 2m).
	CommandTimeout time.Duration
	// Budget bounds the whole per-package simulation (default 10m).
	Budget time.Duration
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
