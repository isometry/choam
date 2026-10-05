package simulate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
)

// GoToolchain runs the local go binary. The environment passes through the
// user's proxy/auth configuration (GOPROXY, GOPRIVATE, netrc via HOME) and
// forces the settings resolution parity depends on: GOTOOLCHAIN=auto so a
// go.mod demanding a newer toolchain is honored, -mod=mod so a vendor/
// directory doesn't mask resolution, and GOWORK=off so a stray go.work can't
// leak into the analysis.
type GoToolchain struct {
	goBin     string
	goVersion string // bare version ("1.26.4"), for gobump-parity `go mod tidy -go=`
	timeout   time.Duration
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
	t := &GoToolchain{goBin: goBin, timeout: commandTimeout}

	// melange's gobump tidies with `-go=<its local go version>`, switching
	// old modules to modern requirement-recording semantics; parity demands
	// the same (the build image's go version may still differ slightly -
	// documented residual risk).
	probeCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	version, err := exec.CommandContext(probeCtx, goBin, "env", "GOVERSION").Output()
	if err == nil {
		t.goVersion = strings.TrimPrefix(strings.TrimSpace(string(version)), "go")
	}
	return t, nil
}

func (t *GoToolchain) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return t.runEnv(ctx, dir, nil, args...)
}

// runEnv is run with extra environment entries appended after the standard
// parity settings (later entries win, so extraEnv can override).
func (t *GoToolchain) runEnv(ctx context.Context, dir string, extraEnv []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, t.goBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOTOOLCHAIN=auto",
		"GOFLAGS=-mod=mod",
		"GOWORK=off",
		"GO111MODULE=on",
	)
	cmd.Env = append(cmd.Env, extraEnv...)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, condenseOutput(output.Bytes()))
	}
	return output.Bytes(), nil
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
// graph of the given build patterns - exactly what the linker records in the
// binary's buildinfo (what APK scanners read), plus the package-level detail
// needed to check an advisory's vulnerable import paths (a module can be
// linked via one package while the vulnerable package is not - e.g.
// x/sys/unix linked, x/sys/windows not). Both sets come from ONE go list
// walk. Deliberate choices:
//   - Test-only imports are excluded BY DESIGN (no -test flag): they never
//     ship in the artifact, which is precisely the narrowing this exists for.
//   - No -e flag: a package-load error fails the whole call so the caller
//     fails OPEN (no filtering); -e would silently under-report the import
//     graph and wrongly drop real fixes - the one unacceptable failure mode.
//   - Replace directives resolve to the replacement path, matching
//     ListModules' identity space (scan findings name the replacement).
//   - GOOS=linux for build-target parity (melange targets linux; GOOS is the
//     axis that flips import sets via _linux.go files). GOARCH stays host,
//     and melange's build tags (netgo, osusergo, user tags) are not
//     replicated - an over-approximation, acceptable.
func (t *GoToolchain) Linked(ctx context.Context, dir string, patterns []string) (modules, packages map[string]struct{}, err error) {
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	const tmpl = `{{if and .Module (not .Standard)}}{{.ImportPath}} {{if .Module.Replace}}{{.Module.Replace.Path}}{{else}}{{.Module.Path}}{{end}}{{end}}`
	args := append([]string{"list", "-deps", "-f", tmpl}, patterns...)
	output, err := t.runEnv(ctx, dir, []string{"GOOS=linux"}, args...)
	if err != nil {
		return nil, nil, err
	}

	modules = make(map[string]struct{})
	packages = make(map[string]struct{})
	for line := range strings.SplitSeq(string(output), "\n") {
		pkg, module, found := strings.Cut(strings.TrimSpace(line), " ")
		if !found {
			continue
		}
		packages[pkg] = struct{}{}
		modules[module] = struct{}{}
	}
	return modules, packages, nil
}

// LinkedStd returns the set of standard-library import paths in the
// transitive non-test import graph of the given build patterns, evaluated
// for GOOS=linux (same walk semantics as Linked, inverted filter: standard
// library packages instead of non-standard ones).
func (t *GoToolchain) LinkedStd(ctx context.Context, dir string, patterns []string) (map[string]struct{}, error) {
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	const tmpl = `{{if .Standard}}{{.ImportPath}}{{end}}`
	args := append([]string{"list", "-deps", "-f", tmpl}, patterns...)
	output, err := t.runEnv(ctx, dir, []string{"GOOS=linux"}, args...)
	if err != nil {
		return nil, err
	}

	std := make(map[string]struct{})
	for line := range strings.SplitSeq(string(output), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" {
			continue
		}
		std[pkg] = struct{}{}
	}
	return std, nil
}

// Replace applies a replace directive with gobump parity: dropreplace first
// (so a stale directive can't shadow the new one), then the replacement.
func (t *GoToolchain) Replace(ctx context.Context, dir, oldPath, newPath, version string) error {
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
