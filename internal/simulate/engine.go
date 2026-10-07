package simulate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"

	omnibump "github.com/chainguard-dev/omnibump/pkg/languages/golang"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// Engine selects the apply semantics the simulation models: what the build's
// bump step will actually do with the written deps list.
type Engine int

const (
	// EngineGobump models melange's `uses: go/bump` (gobump): tidy
	// -go=<host>, one `go get` per entry (skipped when go.mod already
	// requires the module above the entry), tidy -go=<host>. The zero value.
	EngineGobump Engine = iota
	// EngineOmnibump models `uses: bump` by running omnibump's own
	// golang.DoUpdate behind the filter its CLI applies first (see rawSkip):
	// the go directive only ever lowered to the build's Go and the toolchain
	// line dropped, initial tidy, replaces, `go get` only for modules absent
	// from go.mod (or non-semver targets), the EXACT version set in place for
	// already-required modules (no MVS ripple), final tidy without -go, and
	// a post-tidy verification that no entry was downgraded.
	EngineOmnibump
)

func (e Engine) String() string {
	if e == EngineOmnibump {
		return "omnibump"
	}
	return "gobump"
}

// omnibumpUpdate is the DoUpdate EngineOmnibump runs (a seam for tests).
var omnibumpUpdate = omnibump.DoUpdate

// omnibumpModule is the module EngineOmnibump links (see OmnibumpVersion).
const omnibumpModule = "github.com/chainguard-dev/omnibump"

// OmnibumpVersion reports the omnibump version linked into this binary - the
// one EngineOmnibump simulates with - or "" when build info is unavailable.
func OmnibumpVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, dep := range info.Deps {
		if dep.Path != omnibumpModule {
			continue
		}
		if dep.Replace != nil {
			return dep.Replace.Path + "@" + dep.Replace.Version
		}
		return dep.Version
	}
	return ""
}

// applyStep names the part of an apply that failed.
type applyStep int

const (
	// stepSetup: the pristine module could not be prepared (restore, initial
	// tidy, a replace edit, or an engine-internal failure) - fatal.
	stepSetup applyStep = iota
	// stepGet: fetching an entry failed; cand names it when attributable.
	stepGet
	// stepTidy: the closing tidy failed.
	stepTidy
	// stepVerify: the engine's post-tidy verification rejected an entry
	// (omnibump: ErrPackageDowngrade / ErrPackageNotFound). The checkout
	// holds the tidied result, which is what the sustain checks inspect.
	stepVerify
)

// applyFailure is one failed apply: where it failed, the candidate it is
// attributed to (nil when the engine cannot tell), and the cause.
type applyFailure struct {
	step applyStep
	cand *candState
	err  error
}

// engine applies a candidate set to the checkout the way the build's bump
// step will. Implementations never mutate candidates: the caller decides
// what a failure or a skip means for loop state.
type engine interface {
	// apply restores the pristine snapshot and applies keep (in apply
	// order), returning the candidates it skipped as already satisfied.
	apply(ctx context.Context, keep []*candState) (skipped []*candState, fail *applyFailure)
	// tidyBaseline restores the pristine snapshot and runs only the
	// engine's own tidying (the compile gate's baseline state).
	tidyBaseline(ctx context.Context) error
}

func (l *loop) newEngine(ctx context.Context) (engine, error) {
	if l.req.Engine != EngineOmnibump {
		return gobumpEngine{l: l}, nil
	}
	raw, err := modfile.Parse("go.mod", l.pristine["go.mod"], nil)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream go.mod: %w", err)
	}
	host := ""
	if h, ok := l.tc.(interface{ hostGoVersion() string }); ok {
		host = h.hostGoVersion()
	}
	goVersion := l.req.GoVersion
	if goVersion == "" {
		goVersion = host // pinned explicitly: DoUpdate would otherwise run `go version` from the process cwd
	}
	e := &omnibumpEngine{l: l, raw: raw, goVersion: goVersion, env: omnibumpEnv(raw, goVersion, host)}
	logging.From(ctx).Debug("simulating with omnibump", "modroot", l.req.Modroot, "omnibump", OmnibumpVersion(),
		"go_version", goVersion, "tidy", !l.req.NoTidy, "gotoolchain", e.env["GOTOOLCHAIN"])
	return e, nil
}

// gobumpEngine is EngineGobump: tidy, replace edits, one skip-guarded
// `go get` per entry, tidy.
type gobumpEngine struct{ l *loop }

func (e gobumpEngine) apply(ctx context.Context, keep []*candState) ([]*candState, *applyFailure) {
	l := e.l
	if err := e.tidyBaseline(ctx); err != nil {
		return nil, &applyFailure{step: stepSetup, err: fmt.Errorf("initial go mod tidy: %w", err)}
	}
	// gobump parity: replace directives before any get. A replace edit is
	// syntactic - failure is fatal, not a graph problem.
	for _, c := range keep {
		if !c.Replace {
			continue
		}
		if c.Version == latestQuery {
			return nil, &applyFailure{step: stepSetup, err: fmt.Errorf("internal error: replace candidate %s has unresolved @latest version", c.Module)}
		}
		if err := l.tc.Replace(ctx, l.dir, c.OldPath(), c.Module, c.Version); err != nil {
			return nil, &applyFailure{step: stepSetup, err: fmt.Errorf("applying replace %s=%s@%s: %w", c.OldPath(), c.Module, c.Version, err)}
		}
	}
	var skipped []*candState
	for _, c := range keep {
		if c.Replace {
			continue
		}
		if l.getSatisfied(ctx, c) {
			// gobump parity: go/bump skips any entry whose current require
			// already exceeds the requested version. Running the get anyway
			// would be a DOWNGRADE that can drag an earlier candidate's
			// module back below its fix.
			skipped = append(skipped, c)
			logging.From(ctx).Debug("skipping go get: require already exceeds target",
				"modroot", l.req.Modroot, "module", c.Module, "target", c.Version)
			continue
		}
		if err := l.tc.Get(ctx, l.dir, c.Module+"@"+c.Version); err != nil {
			return skipped, &applyFailure{step: stepGet, cand: c, err: err}
		}
	}
	if err := l.tc.ModTidy(ctx, l.dir); err != nil {
		return skipped, &applyFailure{step: stepTidy, err: err}
	}
	return skipped, nil
}

func (e gobumpEngine) tidyBaseline(ctx context.Context) error {
	if err := e.l.restore(ctx); err != nil {
		return err
	}
	return e.l.tc.ModTidy(ctx, e.l.dir)
}

// omnibumpEngine is EngineOmnibump (see its doc).
type omnibumpEngine struct {
	l         *loop
	raw       *modfile.File     // upstream go.mod as cloned: the reference of the CLI's filter
	goVersion string            // UpdateConfig.GoVersion: the build's Go
	env       map[string]string // go tool settings for DoUpdate's subprocesses
	// pristineTidies records that DoUpdate with no entries succeeded once,
	// so a later "go mod tidy" failure is the closing tidy (the initial one
	// runs on identical input every time).
	pristineTidies bool
	// latest memoizes @latest resolutions (see resolveLatest).
	latest map[string]string
}

// queryResolver is implemented by toolchains that can resolve a version
// query (*GoToolchain does).
type queryResolver interface {
	ResolveQuery(ctx context.Context, dir, module, query string) (string, error)
}

// resolveLatest resolves c's @latest target to a concrete version, as
// omnibump's CLI does before filtering: the written deps carry the concrete
// version, which DoUpdate applies as an in-place require edit (after every
// `go get`), not as a get - so the simulation must too. Without a resolver
// (test fakes) the query passes through.
func (e *omnibumpEngine) resolveLatest(ctx context.Context, c *candState) (string, error) {
	if c.Version != latestQuery {
		return c.Version, nil
	}
	r, ok := e.l.tc.(queryResolver)
	if !ok {
		return c.Version, nil
	}
	if v, ok := e.latest[c.Module]; ok {
		return v, nil
	}
	v, err := r.ResolveQuery(ctx, e.l.dir, c.Module, latestQuery)
	if err != nil {
		return "", err
	}
	if e.latest == nil {
		e.latest = make(map[string]string)
	}
	e.latest[c.Module] = v
	return v, nil
}

func (e *omnibumpEngine) apply(ctx context.Context, keep []*candState) ([]*candState, *applyFailure) {
	if !e.pristineTidies {
		if err := e.tidyBaseline(ctx); err != nil {
			return nil, &applyFailure{step: stepSetup, err: fmt.Errorf("initial go mod tidy: %w", err)}
		}
	}
	if err := e.l.restore(ctx); err != nil {
		return nil, &applyFailure{step: stepSetup, err: err}
	}
	var skipped []*candState
	pkgs := make(map[string]*omnibump.Package, len(keep))
	for i, c := range keep {
		version, err := e.resolveLatest(ctx, c)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return skipped, &applyFailure{step: stepSetup, err: cerr}
			}
			return skipped, &applyFailure{step: stepGet, cand: c, err: err}
		}
		resolved := *c
		resolved.Version = version
		if reason := rawSkip(e.raw, &resolved); reason != "" {
			skipped = append(skipped, c)
			logging.From(ctx).Debug("omnibump skips entry", "modroot", e.l.req.Modroot,
				"module", c.Module, "target", version, "reason", reason)
			continue
		}
		pkg := &omnibump.Package{Name: c.Module, Version: version, Index: i}
		if c.Replace {
			pkg.Replace, pkg.OldName = true, c.OldPath()
		}
		pkgs[c.Module] = pkg
	}
	if len(pkgs) == 0 {
		// The CLI returns before DoUpdate: nothing is tidied at all.
		return skipped, nil
	}
	if err := e.doUpdate(ctx, pkgs); err != nil {
		return skipped, e.classify(ctx, err, keep)
	}
	return skipped, nil
}

func (e *omnibumpEngine) tidyBaseline(ctx context.Context) error {
	if err := e.l.restore(ctx); err != nil {
		return err
	}
	if err := e.doUpdate(ctx, map[string]*omnibump.Package{}); err != nil {
		return err
	}
	e.pristineTidies = true
	return nil
}

// doUpdate runs omnibump's DoUpdate in the checkout, with its go tool
// subprocesses configured by e.env and its clog output routed into ctx's
// logger.
func (e *omnibumpEngine) doUpdate(ctx context.Context, pkgs map[string]*omnibump.Package) error {
	// DoUpdate chains several go invocations (two tidies plus gets).
	ctx, cancel := context.WithTimeout(ctx, 3*e.l.opts.CommandTimeout)
	defer cancel()
	cfg := &omnibump.UpdateConfig{Modroot: e.l.dir, Tidy: !e.l.req.NoTidy, GoVersion: e.goVersion}
	libCtx := logging.Library(ctx, "omnibump")
	return withProcessEnv(e.env, func() error {
		_, err := omnibumpUpdate(libCtx, pkgs, cfg)
		return err
	})
}

// classify maps a DoUpdate error onto an applyFailure. omnibump wraps go tool
// failures as text ("failed to run 'go get': ... with output: <go output>"),
// so only its sentinels classify via errors.Is; attribution to a candidate is
// by the module path the text names.
func (e *omnibumpEngine) classify(ctx context.Context, err error, keep []*candState) *applyFailure {
	if cerr := ctx.Err(); cerr != nil {
		return &applyFailure{step: stepSetup, err: cerr}
	}
	msg := err.Error()
	switch {
	case errors.Is(err, omnibump.ErrPackageDowngrade), errors.Is(err, omnibump.ErrPackageNotFound):
		return &applyFailure{step: stepVerify, cand: namedCandidate(keep, msg), err: err}
	case errors.Is(err, omnibump.ErrMainModuleBump),
		strings.HasPrefix(msg, "failed to run 'go get'"),
		strings.HasPrefix(msg, "failed to update require for"):
		return &applyFailure{step: stepGet, cand: namedCandidate(keep, msg), err: err}
	case strings.HasPrefix(msg, "failed to run 'go mod tidy'"):
		return &applyFailure{step: stepTidy, err: err}
	default:
		return &applyFailure{step: stepSetup, err: fmt.Errorf("omnibump: %w", err)}
	}
}

// namedCandidate returns the candidate the error text names: an exact
// module@version first, else the longest module path the text contains (so
// a nested module path beats its parent). nil when none is named.
func namedCandidate(keep []*candState, msg string) *candState {
	var best *candState
	for _, c := range keep {
		if strings.Contains(msg, c.Module+"@"+c.Version) {
			return c
		}
		if strings.Contains(msg, c.Module) && (best == nil || len(c.Module) > len(best.Module)) {
			best = c
		}
	}
	return best
}

// rawSkip mirrors the filter omnibump's CLI applies to the deps list against
// the RAW (untidied) go.mod before calling DoUpdate (resolveAndFilterPackages,
// which DoUpdate itself does not do): the main module is never bumped, a deps
// entry for a replace-pinned module is skipped, and an entry equal to or
// older than the go.mod version is skipped (a replace entry for a module
// without its replace directive yet is kept: it creates the pin). Returns
// the skip reason, "" to apply. Version queries (@latest) are never skipped.
func rawSkip(raw *modfile.File, c *candState) string {
	if raw.Module != nil && c.Module == raw.Module.Mod.Path {
		return "main module"
	}
	current := rawVersion(raw, c.Module)
	if current == "" {
		return ""
	}
	if !c.Replace && rawReplaced(raw, c.Module) {
		return "pinned by a go.mod replace directive"
	}
	if !semver.IsValid(current) || !semver.IsValid(c.Version) {
		return ""
	}
	switch cmp := semver.Compare(current, c.Version); {
	case cmp == 0 && (!c.Replace || rawReplaced(raw, c.OldPath())):
		return "go.mod already at " + current
	case cmp > 0:
		return "go.mod already at newer " + current
	}
	return ""
}

// rawVersion is omnibump's getVersion: a replace target's version first,
// else the require version.
func rawVersion(raw *modfile.File, module string) string {
	for _, r := range raw.Replace {
		if r.New.Path == module {
			return r.New.Version
		}
	}
	for _, r := range raw.Require {
		if r.Mod.Path == module {
			return r.Mod.Version
		}
	}
	return ""
}

// rawReplaced reports whether a replace directive's left-hand side is module.
func rawReplaced(raw *modfile.File, module string) bool {
	for _, r := range raw.Replace {
		if r.Old.Path == module {
			return true
		}
	}
	return false
}

// omnibumpEnv is the go tool environment for DoUpdate's subprocesses: the
// same GOFLAGS/GOWORK/GO111MODULE choam's own go invocations force (see
// GoToolchain.runEnvTimeout), and GOTOOLCHAIN=local whenever the host go
// satisfies the go directive DoUpdate leaves (the upstream directive,
// lowered to goVersion) - the build image runs its own go without toolchain
// switching. When the host is older (or unknown) it stays auto, so the
// simulation can still resolve; a dependency demanding a newer go than the
// build's then fails at build time, not here.
func omnibumpEnv(raw *modfile.File, goVersion, host string) map[string]string {
	directive := ""
	if raw.Go != nil {
		directive = raw.Go.Version
	}
	if goVersion != "" && (directive == "" || goversion.Compare(directive, goVersion) > 0) {
		directive = goVersion
	}
	toolchain := "auto"
	if host != "" && goversion.Compare(host, directive) >= 0 {
		toolchain = "local"
	}
	return map[string]string{
		"GOTOOLCHAIN": toolchain,
		"GOFLAGS":     "-mod=mod",
		"GOWORK":      "off",
		"GO111MODULE": "on",
	}
}

// processEnvMu serializes withProcessEnv.
var processEnvMu sync.Mutex

// withProcessEnv runs fn with vars set in the process environment, restoring
// each variable's previous value (or absence) afterwards - also when fn
// panics or its context is cancelled (fn returns once its subprocesses are
// killed). omnibump's go tool runs inherit the process environment with no
// per-call override, so this is the only way to configure them. Calls are
// serialized; `choam bump` processes spec files sequentially, and choam's own
// go invocations set every variable used here explicitly (runEnvTimeout),
// so nothing else observes the temporary values.
func withProcessEnv(vars map[string]string, fn func() error) error {
	processEnvMu.Lock()
	defer processEnvMu.Unlock()

	type prior struct {
		value string
		set   bool
	}
	saved := make(map[string]prior, len(vars))
	defer func() {
		for key, p := range saved {
			if p.set {
				_ = os.Setenv(key, p.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}()
	for key, value := range vars {
		old, set := os.LookupEnv(key)
		saved[key] = prior{value: old, set: set}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("setting %s: %w", key, err)
		}
	}
	return fn()
}
