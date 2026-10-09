package simulate

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// GoToolchain runs the local go binary. The environment passes through the
// user's proxy/auth configuration (GOPROXY, GOPRIVATE, netrc via HOME) and
// forces the settings resolution parity depends on: GOTOOLCHAIN=auto so a
// go.mod demanding a newer toolchain is honored, -mod=mod so a vendor/
// directory doesn't mask resolution, and GOWORK=off so a stray go.work can't
// leak into the analysis.
type GoToolchain struct {
	goBin      string
	goVersion  string // bare version ("1.26.4"), for gobump-parity `go mod tidy -go=`
	goModCache string // GOMODCACHE, for mapping compile-error paths back to module@version
	goCache    string // GOCACHE, for recognising a build-cache entry lost mid-compile
	timeout    time.Duration

	// compileTimeout bounds a Compile invocation, which type-checks the
	// whole import graph and can take far longer than a resolution command
	// on a cold build cache (the simulation budget still bounds it).
	compileTimeout time.Duration

	modRequiresMu sync.Mutex
	modRequires   map[string]map[string]string // "module@version" -> its go.mod requires
}

// NewToolchain locates the go binary; the error return lets callers degrade
// gracefully (skip validation, report it) when no toolchain is available.
func NewToolchain(ctx context.Context, commandTimeout time.Duration) (*GoToolchain, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("go toolchain not found in PATH: %w", err)
	}
	if commandTimeout <= 0 {
		commandTimeout = 2 * time.Minute
	}
	t := &GoToolchain{
		goBin:          goBin,
		timeout:        commandTimeout,
		compileTimeout: max(commandTimeout, 10*time.Minute),
		modRequires:    make(map[string]map[string]string),
	}

	// melange's gobump tidies with `-go=<its local go version>`, switching
	// old modules to modern requirement-recording semantics; parity demands
	// the same (the build image's go version may still differ slightly -
	// documented residual risk).
	probeCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	env, err := exec.CommandContext(probeCtx, goBin, "env", "GOVERSION", "GOMODCACHE", "GOCACHE").Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(env)), "\n")
		t.goVersion = strings.TrimPrefix(strings.TrimSpace(lines[0]), "go")
		if len(lines) > 1 {
			t.goModCache = strings.TrimSpace(lines[1])
		}
		if len(lines) > 2 {
			t.goCache = strings.TrimSpace(lines[2])
		}
	}
	return t, nil
}

// hostGoVersion is the local go's bare version ("" when the probe failed).
func (t *GoToolchain) hostGoVersion() string { return t.goVersion }

func (t *GoToolchain) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return t.runEnv(ctx, dir, nil, args...)
}

// runEnv is run with extra environment entries appended after the standard
// parity settings (later entries win, so extraEnv can override).
func (t *GoToolchain) runEnv(ctx context.Context, dir string, extraEnv []string, args ...string) ([]byte, error) {
	return t.runEnvTimeout(ctx, dir, extraEnv, t.timeout, args...)
}

// runEnvTimeout is runEnv with an explicit per-command timeout. Only stdout
// is returned: the go tool writes progress ("go: downloading ...") and
// diagnostics to stderr, which would otherwise corrupt JSON decodes of
// stdout. stderr (falling back to stdout) is folded into the error instead,
// and an environment failure is marked ErrInfrastructure (see asInfra).
func (t *GoToolchain) runEnvTimeout(parent context.Context, dir string, extraEnv []string, timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, t.goBin, args...)
	killProcessGroupOnCancel(cmd)
	// Backstop: stop waiting for stdout/stderr this long after the process
	// is killed, even if something outside the group still holds a pipe.
	cmd.WaitDelay = waitDelay
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOTOOLCHAIN=auto",
		"GOFLAGS=-mod=mod",
		"GOWORK=off",
		"GO111MODULE=on",
	)
	cmd.Env = append(cmd.Env, extraEnv...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		diagnostics := stderr.Bytes()
		if len(bytes.TrimSpace(diagnostics)) == 0 {
			diagnostics = stdout.Bytes()
		}
		err = fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, condenseOutput(diagnostics))
		if parent.Err() == nil && ctx.Err() != nil {
			// The per-command bound fired while the simulation itself is
			// still live: a stalled proxy or network, not a verdict.
			return nil, fmt.Errorf("%w: timed out after %s: %w", ErrInfrastructure, timeout, err)
		}
		if ierr := asInfra(err); ierr != nil {
			return nil, ierr
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

// waitDelay bounds how long a cancelled go command's output pipes are
// drained after the kill (see exec.Cmd.WaitDelay).
const waitDelay = 5 * time.Second

// checkModuleArg rejects a module path or version that the go command would
// parse as a flag (or that is not a module/import path at all) before it is
// placed on a go command line. Versions may be semver or a query (a commit
// hash, "latest"); only a leading '-' or whitespace is refused.
func checkModuleArg(path, version string) error {
	if err := module.CheckImportPath(path); err != nil {
		return fmt.Errorf("refusing go command argument: %w", err)
	}
	if strings.HasPrefix(version, "-") || strings.ContainsFunc(version, unicode.IsSpace) {
		return fmt.Errorf("refusing go command argument: malformed version %q for %s", version, path)
	}
	return nil
}

// ErrInfrastructure marks a go tool failure caused by the environment - the
// network, the module proxy or VCS host (connection errors, TLS timeouts,
// 5xx responses) or a per-command timeout - rather than by the module graph.
// It is never a verdict on a candidate: the simulation fails (closed) with
// it instead of shedding or residualising anything.
var ErrInfrastructure = errors.New("go tool infrastructure failure")

// infraMarkers are go tool / net/http error texts that only an environment
// problem produces.
var infraMarkers = []string{
	"dial tcp",
	"TLS handshake timeout",
	"connection reset",
	"connection refused",
	"i/o timeout",
	"no such host",
	"net/http: request canceled",
	"server misbehaving",
	"unexpected EOF",
}

// proxy5xx matches a 5xx status line in go tool output (e.g. "reading
// https://proxy.golang.org/...: 502 Bad Gateway").
var proxy5xx = regexp.MustCompile(`\b5\d\d (?:[A-Z][a-z]+ ?)+`)

// asInfra classifies err: an infrastructure failure (see ErrInfrastructure)
// is returned wrapped in it (or as is when already wrapped); anything else,
// nil included, yields nil.
func asInfra(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInfrastructure) {
		return err
	}
	msg := err.Error()
	for _, marker := range infraMarkers {
		if strings.Contains(msg, marker) {
			return fmt.Errorf("%w: %w", ErrInfrastructure, err)
		}
	}
	if proxy5xx.MatchString(msg) {
		return fmt.Errorf("%w: %w", ErrInfrastructure, err)
	}
	return nil
}

func (t *GoToolchain) ModTidy(ctx context.Context, dir string) error {
	args := []string{"mod", "tidy"}
	if t.goVersion != "" {
		args = append(args, "-go="+t.goVersion)
	}
	_, err := t.run(ctx, dir, args...)
	return err
}

func (t *GoToolchain) Get(ctx context.Context, dir, moduleAtVersion string) error {
	path, version, _ := strings.Cut(moduleAtVersion, "@")
	if err := checkModuleArg(path, version); err != nil {
		return err
	}
	_, err := t.run(ctx, dir, "get", moduleAtVersion)
	return err
}

// goListModule is the subset of `go list -m -json` output the simulation needs.
type goListModule struct {
	Path      string
	Version   string
	Main      bool
	GoVersion string // the module's `go` directive, bare form (e.g. "1.24.5")
	Replace   *goListModule
}

func (t *GoToolchain) ListModules(ctx context.Context, dir string) (map[string]string, error) {
	output, err := t.run(ctx, dir, "list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}

	resolved := make(map[string]string)
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var mod goListModule
		if err := decoder.Decode(&mod); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parsing go list -m -json output: %w", err)
		}
		if mod.Main {
			continue
		}
		path, version := mod.Path, mod.Version
		if mod.Replace != nil {
			if mod.Replace.Version == "" {
				// Local filesystem replacement - nothing meaningful to scan.
				continue
			}
			path, version = mod.Replace.Path, mod.Replace.Version
		}
		if version == "" {
			continue
		}
		resolved[path] = version
	}
	return resolved, nil
}

// DepGoVersions returns the go directive of every non-main module in the
// build list (bare form, e.g. "1.24" or "1.24.5"), keyed by module path,
// with replace directives applied - mirrors ListModules' decode loop and
// skip-main/skip-local-replacement semantics exactly, substituting GoVersion
// for Version throughout.
func (t *GoToolchain) DepGoVersions(ctx context.Context, dir string) (map[string]string, error) {
	output, err := t.run(ctx, dir, "list", "-m", "-json", "all")
	if err != nil {
		return nil, err
	}

	versions := make(map[string]string)
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var mod goListModule
		if err := decoder.Decode(&mod); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parsing go list -m -json output: %w", err)
		}
		if mod.Main {
			continue
		}
		path, goVersion := mod.Path, mod.GoVersion
		if mod.Replace != nil {
			if mod.Replace.Version == "" {
				// Local filesystem replacement - mirror ListModules' skip.
				continue
			}
			path, goVersion = mod.Replace.Path, mod.Replace.GoVersion
		}
		if goVersion == "" {
			continue
		}
		versions[path] = goVersion
	}
	return versions, nil
}

// Linked returns the modules AND packages in the transitive non-test import
// graph of the target's build patterns - exactly what the linker records in
// the binary's buildinfo (what APK scanners read), plus the package-level
// detail needed to check an advisory's vulnerable import paths (a module can
// be linked via one package while the vulnerable package is not - e.g.
// x/sys/unix linked, x/sys/windows not). Both sets come from ONE go list walk
// per target arch, unioned: an import linked on any arch the package is
// built for ships. Deliberate choices:
//   - Test-only imports are excluded BY DESIGN (no -test flag): they never
//     ship in the artifact, which is precisely the narrowing this exists for.
//   - No -e flag: a package-load error (on any arch) fails the whole call so
//     the caller fails OPEN (no filtering); -e, or a partial union, would
//     silently under-report the import graph and wrongly drop real fixes -
//     the one unacceptable failure mode.
//   - Replace directives resolve to the replacement path, matching
//     ListModules' identity space (scan findings name the replacement).
//   - The build environment and tags are targetBuildEnv's and the target's,
//     shared with Compile, so the linked set and the compile gate judge the
//     same files (CGO aside: see targetBuildEnv).
func (t *GoToolchain) Linked(ctx context.Context, dir string, target BuildTarget) (modules, packages map[string]struct{}, err error) {
	const tmpl = `{{if and .Module (not .Standard)}}{{.ImportPath}} {{if .Module.Replace}}{{.Module.Replace.Path}}{{else}}{{.Module.Path}}{{end}}{{end}}`
	outputs, err := t.listDeps(ctx, dir, target, tmpl)
	if err != nil {
		return nil, nil, err
	}

	modules = make(map[string]struct{})
	packages = make(map[string]struct{})
	for _, output := range outputs {
		for line := range strings.SplitSeq(string(output), "\n") {
			pkg, module, found := strings.Cut(strings.TrimSpace(line), " ")
			if !found {
				continue
			}
			packages[pkg] = struct{}{}
			modules[module] = struct{}{}
		}
	}
	return modules, packages, nil
}

// LinkedStd returns the set of standard-library import paths in the
// transitive non-test import graph of the target's build patterns, with the
// same arch union and walk semantics as Linked (inverted filter: standard
// library packages instead of non-standard ones).
func (t *GoToolchain) LinkedStd(ctx context.Context, dir string, target BuildTarget) (map[string]struct{}, error) {
	const tmpl = `{{if .Standard}}{{.ImportPath}}{{end}}`
	outputs, err := t.listDeps(ctx, dir, target, tmpl)
	if err != nil {
		return nil, err
	}

	std := make(map[string]struct{})
	for _, output := range outputs {
		for line := range strings.SplitSeq(string(output), "\n") {
			if pkg := strings.TrimSpace(line); pkg != "" {
				std[pkg] = struct{}{}
			}
		}
	}
	return std, nil
}

// listDeps runs `go list -deps -f tmpl` for every target arch concurrently,
// returning the outputs in arch order. Every walk runs to completion (a
// failing arch does not cancel the others), so the error reported is that of
// the first failing arch in arch order whatever the timing; a cancellation
// of ctx stops them all.
func (t *GoToolchain) listDeps(ctx context.Context, dir string, target BuildTarget, tmpl string) ([][]byte, error) {
	arches := TargetArches(target.Arches)
	args := targetListArgs([]string{"list", "-deps", "-f", tmpl}, target.Patterns, target.Tags)
	outputs := make([][]byte, len(arches))
	errs := make([]error, len(arches))
	var wg sync.WaitGroup
	for i, arch := range arches {
		wg.Go(func() {
			outputs[i], errs[i] = t.runEnv(ctx, dir, targetBuildEnv(arch, target.Env, false), args...)
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("GOARCH=%s: %w", arches[i], err)
		}
	}
	return outputs, nil
}

// defaultArches are the GOARCHes melange builds Wolfi packages for when the
// spec does not restrict package.target-architecture.
var defaultArches = []string{"amd64", "arm64"}

// TargetArches normalizes a target-arch list: deduplicated, amd64 then arm64
// first and any others after in lexical order (so the compile gate's primary
// arch never depends on input order); empty means defaultArches.
func TargetArches(arches []string) []string {
	if len(arches) == 0 {
		return slices.Clone(defaultArches)
	}
	rank := func(arch string) int {
		if i := slices.Index(defaultArches, arch); i >= 0 {
			return i
		}
		return len(defaultArches)
	}
	out := slices.Clone(arches)
	slices.SortFunc(out, func(a, b string) int { return cmp.Or(cmp.Compare(rank(a), rank(b)), strings.Compare(a, b)) })
	return slices.Compact(out)
}

// hostCanCgo reports whether the host can compile cgo for linux/arch
// natively; no linux cross C toolchain is assumed (cross-cgo would fail
// runtime/cgo and mask every package above it).
func hostCanCgo(arch string) bool {
	return runtime.GOOS == "linux" && runtime.GOARCH == arch
}

// CompileCgoLimited reports whether the compile gate must type-check arch
// with CGO disabled although the build enables it (see targetBuildEnv).
func CompileCgoLimited(arch string, env BuildEnv) bool {
	return env.CGO != "0" && !hostCanCgo(arch)
}

// targetBuildEnv is the build environment every artifact-graph query
// (Linked, LinkedStd and, with compile set, Compile) evaluates arch under -
// the single source of GOOS/GOARCH/CGO_ENABLED/GOEXPERIMENT:
//   - GOOS=linux: melange builds linux packages.
//   - CGO_ENABLED is the spec's (env.CGO) when it sets one, else 1: melange's
//     go/build and go/install pull in build-base, so a native build has a C
//     toolchain and the go command enables cgo. Reachability always uses
//     that value - `go list -deps` only evaluates build constraints (cgo
//     files, import "C") and never invokes the C compiler, so it needs no C
//     toolchain even for a cross target. Compile does run cgo, so it falls
//     back to CGO_ENABLED=0 when the host cannot build cgo for linux/arch
//     (see hostCanCgo, CompileCgoLimited): the gate then judges the !cgo
//     files - a documented limitation, reported by the caller.
//   - GOEXPERIMENT is always set (empty clears the user's own), as the
//     go/build and go/install pipelines do.
func targetBuildEnv(arch string, env BuildEnv, compile bool) []string {
	cgo := "1"
	if env.CGO == "0" || (compile && !hostCanCgo(arch)) {
		cgo = "0"
	}
	return []string{"GOOS=linux", "GOARCH=" + arch, "CGO_ENABLED=" + cgo, "GOEXPERIMENT=" + env.GOExperiment}
}

// targetListArgs completes a `go list` invocation with the go/build steps'
// tags and the build patterns (empty means ./...).
func targetListArgs(args, patterns, tags []string) []string {
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	return append(args, patterns...)
}

// maxCompileErrorLines caps the error lines kept per failing package.
const maxCompileErrorLines = 5

// goListPackage is the subset of `go list -json` package output Compile
// needs.
type goListPackage struct {
	ImportPath string
	Standard   bool
	Module     *goListModule
	Imports    []string
	Error      *struct {
		Err string
	}
}

// Compile type-checks and compiles (without linking) every non-test package
// in the transitive import graph of the target's patterns, via
// `go list -e -export -deps -json`: -export forces a real compile of each
// package to export data, and -e records each package's own compile error
// on its .Error instead of aborting the walk - structured, per-package, no
// vet noise, no link step. A package whose dependency failed is not compiled
// at all (only DepsErrors), so failures surface on the deepest broken
// package - exactly the module that needs blaming. The build target is
// targetBuildEnv's for arch (one arch per call). The build cache is the
// user's GOCACHE, shared and incremental across compiles and runs. An error
// return means the go tool itself failed (not that packages failed to
// compile).
func (t *GoToolchain) Compile(ctx context.Context, dir string, target BuildTarget, arch string) (*CompileReport, error) {
	args := targetListArgs([]string{"list", "-e", "-export", "-deps", "-json=ImportPath,Standard,Module,Imports,Error"}, target.Patterns, target.Tags)
	output, err := t.runEnvTimeout(ctx, dir, targetBuildEnv(arch, target.Env, true), t.compileTimeout, args...)
	if err != nil {
		return nil, err
	}

	report := &CompileReport{
		Failed:      make(map[string][]string),
		Modules:     make(map[string]string),
		Imports:     make(map[string][]string),
		FileModules: make(map[string]string),
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var pkg goListPackage
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parsing go list -export -json output: %w", err)
		}
		if pkg.Standard {
			continue
		}
		if pkg.Module != nil {
			modulePath := pkg.Module.Path
			if pkg.Module.Replace != nil && pkg.Module.Replace.Version != "" {
				modulePath = pkg.Module.Replace.Path
			}
			if pkg.Module.Main {
				modulePath = ""
			}
			report.Modules[pkg.ImportPath] = modulePath
		}
		if pkg.Error == nil {
			continue
		}
		if t.lostCacheEntry(pkg.Error.Err) {
			// Not a verdict on the graph: another process removed build-cache
			// entries under this compile (e.g. a concurrent `go clean -cache`).
			return nil, fmt.Errorf("%w: build cache entry vanished during compile of %s: %s",
				ErrInfrastructure, pkg.ImportPath, compileErrorLines(pkg.Error.Err)[0])
		}
		lines := compileErrorLines(pkg.Error.Err)
		report.Failed[pkg.ImportPath] = lines
		report.Imports[pkg.ImportPath] = pkg.Imports
		for _, line := range lines {
			if file, coord, ok := t.modCacheFile(dir, line); ok {
				report.FileModules[file] = coord
			}
		}
	}
	return report, nil
}

// lostCacheEntry reports whether a package error is the compiler failing to
// open an export file in the build cache (GOCACHE) - an entry deleted while
// the go command relied on it.
func (t *GoToolchain) lostCacheEntry(errText string) bool {
	return t.goCache != "" && strings.Contains(errText, "(open "+t.goCache+string(filepath.Separator)) &&
		strings.Contains(errText, "no such file or directory")
}

// compileErrorLines extracts the first maxCompileErrorLines diagnostic lines
// from a go list package error, dropping the "# pkg" header.
func compileErrorLines(errText string) []string {
	var lines []string
	for line := range strings.SplitSeq(errText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}
		lines = append(lines, line)
		if len(lines) == maxCompileErrorLines {
			break
		}
	}
	if len(lines) == 0 {
		lines = []string{strings.TrimSpace(errText)}
	}
	return lines
}

// modCacheFile maps a "file:line:col: msg" diagnostic whose file lives in the
// module cache (<GOMODCACHE>/<escaped module>@<version>/...) back to its
// absolute path and module@version.
func (t *GoToolchain) modCacheFile(dir, line string) (file, coord string, ok bool) {
	if t.goModCache == "" {
		return "", "", false
	}
	idx := strings.Index(line, ".go:")
	if idx < 0 {
		return "", "", false
	}
	file = line[:idx+len(".go")]
	if !filepath.IsAbs(file) {
		file = filepath.Join(dir, file)
	}
	file = filepath.Clean(file)
	rel, err := filepath.Rel(filepath.Clean(t.goModCache), file)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", "", false
	}
	rel = filepath.ToSlash(rel)
	at := strings.Index(rel, "@")
	if at < 0 {
		return "", "", false
	}
	version, _, _ := strings.Cut(rel[at+1:], "/")
	modulePath, err := module.UnescapePath(rel[:at])
	if err != nil {
		return "", "", false
	}
	version, err = module.UnescapeVersion(version)
	if err != nil {
		return "", "", false
	}
	return file, modulePath + "@" + version, true
}

// ModuleVersions lists the released versions of module (`go list -m
// -versions`), in ascending semver order.
func (t *GoToolchain) ModuleVersions(ctx context.Context, dir, modulePath string) ([]string, error) {
	if err := checkModuleArg(modulePath, ""); err != nil {
		return nil, err
	}
	output, err := t.run(ctx, dir, "list", "-m", "-versions", modulePath)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return nil, nil
	}
	versions := fields[1:]
	slices.SortFunc(versions, func(a, b string) int { return cmp.Or(semver.Compare(a, b), strings.Compare(a, b)) })
	return versions, nil
}

// ResolveQuery resolves module@query (e.g. a commit hash) to a concrete
// version (`go list -m`).
func (t *GoToolchain) ResolveQuery(ctx context.Context, dir, modulePath, query string) (string, error) {
	if err := checkModuleArg(modulePath, query); err != nil {
		return "", err
	}
	output, err := t.run(ctx, dir, "list", "-m", "-f", "{{.Version}}", modulePath+"@"+query)
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(output))
	if version == "" {
		return "", fmt.Errorf("go list -m %s@%s: no version", modulePath, query)
	}
	return version, nil
}

// RequiredBy returns, from `go mod graph`, each module's requirers in the
// build list: required module -> requiring module path -> required version.
// Only edges from a requirer's selected version (the highest version of it
// in the graph, as MVS picks) count; the main module's own requirements are
// excluded.
func (t *GoToolchain) RequiredBy(ctx context.Context, dir string) (map[string]map[string]string, error) {
	output, err := t.run(ctx, dir, "mod", "graph")
	if err != nil {
		return nil, err
	}
	type edge struct{ from, fromVersion, to, toVersion string }
	var edges []edge
	selected := make(map[string]string)
	for line := range strings.SplitSeq(string(output), "\n") {
		from, to, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		fromPath, fromVersion, fromVersioned := strings.Cut(from, "@")
		toPath, toVersion, _ := strings.Cut(to, "@")
		if !fromVersioned || fromPath == "go" || fromPath == "toolchain" || toPath == "go" || toPath == "toolchain" {
			continue // main module or go/toolchain pseudo-nodes
		}
		edges = append(edges, edge{fromPath, fromVersion, toPath, toVersion})
		for path, version := range map[string]string{fromPath: fromVersion, toPath: toVersion} {
			if semver.Compare(version, selected[path]) > 0 {
				selected[path] = version
			}
		}
	}
	requiredBy := make(map[string]map[string]string)
	for _, e := range edges {
		if selected[e.from] != e.fromVersion {
			continue
		}
		if requiredBy[e.to] == nil {
			requiredBy[e.to] = make(map[string]string)
		}
		requiredBy[e.to][e.from] = e.toVersion
	}
	return requiredBy, nil
}

// ModuleRequires returns the require entries of module@version's own go.mod
// (`go list -m -json` fetches only the .mod/.info, never the zip), memoized
// per toolchain: module versions are immutable.
func (t *GoToolchain) ModuleRequires(ctx context.Context, dir, modulePath, version string) (map[string]string, error) {
	if err := checkModuleArg(modulePath, version); err != nil {
		return nil, err
	}
	key := modulePath + "@" + version
	t.modRequiresMu.Lock()
	cached, ok := t.modRequires[key]
	t.modRequiresMu.Unlock()
	if ok {
		return cached, nil
	}

	output, err := t.run(ctx, dir, "list", "-m", "-json", key)
	if err != nil {
		return nil, err
	}
	var info struct{ GoMod string }
	if err := json.Unmarshal(output, &info); err != nil {
		return nil, fmt.Errorf("parsing go list -m -json %s output: %w", key, err)
	}
	if info.GoMod == "" {
		return nil, fmt.Errorf("no go.mod reported for %s", key)
	}
	content, err := os.ReadFile(info.GoMod)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod of %s: %w", key, err)
	}
	modFile, err := modfile.ParseLax(info.GoMod, content, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod of %s: %w", key, err)
	}
	requires := make(map[string]string, len(modFile.Require))
	for _, require := range modFile.Require {
		requires[require.Mod.Path] = require.Mod.Version
	}

	t.modRequiresMu.Lock()
	t.modRequires[key] = requires
	t.modRequiresMu.Unlock()
	return requires, nil
}

// Replace applies a replace directive with gobump parity: dropreplace first
// (so a stale directive can't shadow the new one), then the replacement.
func (t *GoToolchain) Replace(ctx context.Context, dir, oldPath, newPath, version string) error {
	for _, path := range []string{oldPath, newPath} {
		if err := checkModuleArg(path, version); err != nil {
			return err
		}
	}
	if _, err := t.run(ctx, dir, "mod", "edit", "-dropreplace="+oldPath); err != nil {
		return err
	}
	_, err := t.run(ctx, dir, "mod", "edit", fmt.Sprintf("-replace=%s=%s@%s", oldPath, newPath, version))
	return err
}

// Replaces parses dir's go.mod replace directives, keyed by the replaced
// (old) module path. Local filesystem targets carry an empty Version.
// Note: modfile.ParseLax skips replace directives entirely, so this must use
// the full parser.
func (t *GoToolchain) Replaces(_ context.Context, dir string) (map[string]ReplaceTarget, error) {
	path := filepath.Join(dir, "go.mod")
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	modFile, err := modfile.Parse(path, content, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	replaces := make(map[string]ReplaceTarget, len(modFile.Replace))
	for _, replace := range modFile.Replace {
		replaces[replace.Old.Path] = ReplaceTarget{
			Path:    replace.New.Path,
			Version: replace.New.Version, // empty for local filesystem targets
		}
	}
	return replaces, nil
}

// Requirements parses dir's go.mod require entries. No go tool invocation -
// the file as tidied IS the contract gobump checks deps entries against.
func (t *GoToolchain) Requirements(_ context.Context, dir string) (map[string]string, error) {
	path := filepath.Join(dir, "go.mod")
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	modFile, err := modfile.ParseLax(path, content, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	requirements := make(map[string]string, len(modFile.Require))
	for _, require := range modFile.Require {
		requirements[require.Mod.Path] = require.Mod.Version
	}
	return requirements, nil
}

// condenseOutput trims go tool output to the informative tail: full `go get`
// transcripts are dominated by "downloading" progress lines, while the error
// cause is at the end.
func condenseOutput(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, ": downloading ") {
			continue
		}
		kept = append(kept, line)
	}
	const maxLines = 20
	if len(kept) > maxLines {
		kept = kept[len(kept)-maxLines:]
	}
	return strings.Join(kept, "\n")
}
