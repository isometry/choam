package simulate

import (
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// typecheckFixture writes a dependency-free main module (path -> content,
// subdirectories allowed) and returns a fresh toolchain (empty cache) and
// the module dir. Skipped under -short or without a go binary.
func typecheckFixture(t *testing.T, files map[string]string) (*GoToolchain, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping go toolchain integration test in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	dir := t.TempDir()
	for name, content := range files {
		writeFixtureFile(t, filepath.Join(dir, name), content)
	}
	toolchain, err := NewToolchain(t.Context(), 2*time.Minute)
	require.NoError(t, err)
	return toolchain, dir
}

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// cacheDelta runs fn and returns the type-check cache hits and misses it
// caused.
func cacheDelta(toolchain *GoToolchain, fn func()) (hits, misses int) {
	h0, m0 := toolchain.typecheckCache.stats()
	fn()
	h1, m1 := toolchain.typecheckCache.stats()
	return h1 - h0, m1 - m0
}

// TestTypecheck_PositionFreeExportIsCacheHitForImporter: export data is
// written without positions, so shifting a line in a package rechecks only
// that package - its API hash is unchanged and every importer is a hit.
func TestTypecheck_PositionFreeExportIsCacheHitForImporter(t *testing.T) {
	lib := "package lib\n\n// T is exported.\ntype T struct{ N int }\n\nfunc New() T { return T{N: 1} }\n"
	toolchain, dir := typecheckFixture(t, map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.21\n",
		"lib/lib.go": lib,
		"main.go":    "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/m/lib\"\n)\n\nfunc main() { fmt.Println(lib.New().N) }\n",
	})
	ctx := t.Context()

	report, err := toolchain.Compile(ctx, dir, BuildTarget{}, "amd64")
	require.NoError(t, err)
	assert.Empty(t, report.Failed)
	assert.Equal(t, "", report.Modules["example.com/m/lib"])

	hits, misses := cacheDelta(toolchain, func() {
		_, err = toolchain.Compile(ctx, dir, BuildTarget{}, "amd64")
	})
	require.NoError(t, err)
	assert.Zero(t, misses, "an unchanged graph is all hits")
	assert.Positive(t, hits)

	writeFixtureFile(t, filepath.Join(dir, "lib", "lib.go"), "\n\n"+lib)
	_, misses = cacheDelta(toolchain, func() {
		report, err = toolchain.Compile(ctx, dir, BuildTarget{}, "amd64")
	})
	require.NoError(t, err)
	assert.Empty(t, report.Failed)
	assert.Equal(t, 1, misses, "only the shifted package is rechecked: its export hash is position-free")

	_, misses = cacheDelta(toolchain, func() {
		_, err = toolchain.Compile(ctx, dir, BuildTarget{}, "arm64")
	})
	require.NoError(t, err)
	assert.Less(t, misses, 100, "cross-arch rechecks only packages whose files or imports' APIs differ")
}

// TestTypecheck_SecondArchReusesCache: cache keys are arch-independent, so
// type-checking arm64 after amd64 (as the gate does, in sequence) rechecks
// only packages whose file set differs. Standard-library packages with arch
// files do differ, so the measure is relative: the same module with an
// API-neutral _amd64.go/_arm64.go pair in lib misses exactly one more
// package on arm64 - lib itself; its importers (mid, main) are hits.
func TestTypecheck_SecondArchReusesCache(t *testing.T) {
	files := map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.21\n",
		"lib/lib.go": "package lib\n\nfunc Value() int { return 1 }\n",
		"mid/mid.go": "package mid\n\nimport \"example.com/m/lib\"\n\nfunc Twice() int { return 2 * lib.Value() }\n",
		"main.go":    "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/m/mid\"\n)\n\nfunc main() { fmt.Println(mid.Twice()) }\n",
	}
	secondArchMisses := func(extra map[string]string) int {
		all := maps.Clone(files)
		maps.Copy(all, extra)
		toolchain, dir := typecheckFixture(t, all)
		report, err := toolchain.Compile(t.Context(), dir, BuildTarget{}, "amd64")
		require.NoError(t, err)
		require.Empty(t, report.Failed)
		_, misses := cacheDelta(toolchain, func() {
			report, err = toolchain.Compile(t.Context(), dir, BuildTarget{}, "arm64")
		})
		require.NoError(t, err)
		require.Empty(t, report.Failed)
		return misses
	}

	plain := secondArchMisses(nil)
	withArchFiles := secondArchMisses(map[string]string{
		"lib/arch_amd64.go": "package lib\n\nfunc arch() string { return \"amd64\" }\n",
		"lib/arch_arm64.go": "package lib\n\nfunc arch() string { return \"arm64\" }\n",
	})
	assert.Equal(t, plain+1, withArchFiles, "only lib rechecks; its unchanged API keeps mid and main cached")
}

// TestTypecheck_PatchBumpUnchangedAPIIsCacheHit: a module-cache dependency
// raised to a release that changes only a function body is rechecked; its
// importer (and everything else) is a cache hit.
func TestTypecheck_PatchBumpUnchangedAPIIsCacheHit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping go toolchain integration test in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	body := func(n string) map[string]string {
		return map[string]string{
			"go.mod": "module example.com/dep\n\ngo 1.21\n",
			"dep.go": "package dep\n\nfunc Value() int { return " + n + " }\n",
		}
	}
	useFileProxy(t, writeFileProxy(t, map[string]map[string]string{
		"example.com/dep@v1.0.0": body("1"),
		"example.com/dep@v1.0.1": body("2"),
	}))
	dir := newFixtureModule(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n",
		"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/dep\"\n)\n\nfunc main() { fmt.Println(dep.Value()) }\n",
	})
	toolchain, err := NewToolchain(t.Context(), 2*time.Minute)
	require.NoError(t, err)
	ctx := t.Context()

	report, err := toolchain.Compile(ctx, dir, BuildTarget{}, "amd64")
	require.NoError(t, err)
	assert.Empty(t, report.Failed)
	assert.Equal(t, "example.com/dep", report.Modules["example.com/dep"])

	require.NoError(t, toolchain.Get(ctx, dir, "example.com/dep@v1.0.1"))
	_, misses := cacheDelta(toolchain, func() {
		report, err = toolchain.Compile(ctx, dir, BuildTarget{}, "amd64")
	})
	require.NoError(t, err)
	assert.Empty(t, report.Failed)
	assert.Equal(t, 1, misses, "only the bumped module's package is rechecked")
}

// TestTypecheck_DependentOfBrokenPackageNotReported: failures surface on the
// deepest broken package only - its importers are skipped, not reported.
func TestTypecheck_DependentOfBrokenPackageNotReported(t *testing.T) {
	toolchain, dir := typecheckFixture(t, map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.21\n",
		"a/a.go":     "package a\n\nfunc A() int { return missing }\n",
		"b/b.go":     "package b\n\nimport \"example.com/m/a\"\n\nfunc B() int { return a.A() }\n",
		"main.go":    "package main\n\nimport \"example.com/m/b\"\n\nfunc main() { _ = b.B() }\n",
		"c/c.go":     "package c\n\nfunc C() { x := 1 }\n",
		"cmd/x/x.go": "package main\n\nimport _ \"example.com/m/c\"\n\nfunc main() {}\n",
	})
	ctx := t.Context()

	report, err := toolchain.Compile(ctx, dir, BuildTarget{}, "amd64")
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com/m/a", "example.com/m/c"}, slices.Sorted(maps.Keys(report.Failed)))
	assert.Contains(t, report.Failed["example.com/m/a"][0], "a.go:3:23: undefined: missing")
	assert.True(t, filepath.IsAbs(strings.SplitN(report.Failed["example.com/m/a"][0], ":", 2)[0]), "absolute file names")
	assert.Contains(t, report.Failed["example.com/m/c"][0], "declared and not used: x", "soft errors count, as in gc")
	assert.Contains(t, report.Modules, "example.com/m/b", "a skipped importer is still in the graph")
	assert.Equal(t, []string{"example.com/m/a", "example.com/m/c"}, slices.Sorted(maps.Keys(report.Imports)), "Imports only for failed packages")
}

// TestTypecheck_FilePatternUsesToolchainLanguage: a file pattern (main.go)
// makes go list synthesize command-line-arguments with no Module; cmd/go
// compiles it at the toolchain's language version, not go1.16, so generics
// in it are fine (aws-load-balancer-controller's `packages: main.go`). The
// same file in a go 1.16 module, listed as a package, is held to go1.16.
func TestTypecheck_FilePatternUsesToolchainLanguage(t *testing.T) {
	toolchain, dir := typecheckFixture(t, map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.16\n",
		"main.go": "package main\n\nfunc id[T any](v T) T { return v }\n\nfunc main() { _ = id(1) }\n",
	})

	report, err := toolchain.Compile(t.Context(), dir, BuildTarget{Patterns: []string{"main.go"}}, "amd64")
	require.NoError(t, err)
	assert.Empty(t, report.Failed, "command-line-arguments: toolchain language, generics allowed")
	assert.NotContains(t, report.Modules, "command-line-arguments", "no module")

	report, err = toolchain.Compile(t.Context(), dir, BuildTarget{}, "amd64")
	require.NoError(t, err)
	require.Contains(t, report.Failed, "example.com/m")
	assert.Contains(t, strings.Join(report.Failed["example.com/m"], "\n"), "go1.18", "module package: its go directive's language")
}

// TestTypecheck_ImportCUnderCgo: cgo files are type-checked with a fake "C"
// package, with no C toolchain needed (std's runtime/cgo included).
func TestTypecheck_ImportCUnderCgo(t *testing.T) {
	toolchain, dir := typecheckFixture(t, map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.21\n",
		"cgo.go":  "package main\n\n// #include <stdio.h>\nimport \"C\"\n\nfunc hello() { C.puts(C.CString(\"hi\")) }\n",
		"main.go": "package main\n\nimport _ \"os/user\"\n\nfunc main() { hello() }\n",
	})

	report, err := toolchain.Compile(t.Context(), dir, BuildTarget{Env: BuildEnv{CGO: "1"}}, "amd64")
	require.NoError(t, err)
	assert.Empty(t, report.Failed)
}

// TestTypecheckEligible: the engine is only used when neither the listing's
// GOROOT nor any module's go directive is newer than choam's go/types.
func TestTypecheckEligible(t *testing.T) {
	goroot := func(version string) string {
		root := t.TempDir()
		writeFixtureFile(t, filepath.Join(root, "VERSION"), version+"\ntime 2026-01-01T00:00:00Z\n")
		return filepath.Join(root, "src", "runtime")
	}
	runtimePkg := func(version string) goListPackage {
		return goListPackage{ImportPath: "runtime", Standard: true, Dir: goroot(version)}
	}
	modulePkg := func(goVersion string) goListPackage {
		return goListPackage{ImportPath: "example.com/x", Module: &goListModule{Path: "example.com/x", Version: "v1.0.0", GoVersion: goVersion}}
	}

	version, err := typecheckEligible([]goListPackage{runtimePkg("go1.27.2"), modulePkg("1.27")}, "1.27.0")
	require.NoError(t, err)
	assert.Equal(t, "1.27.2", version)

	const remedy = "run a choam built with that Go or newer, e.g. go run github.com/isometry/choam@latest"
	for name, tc := range map[string]struct {
		pkgs   []goListPackage
		host   string
		tooNew string // the full message when ErrToolchainTooNew, else ""
	}{
		"toolchain newer":       {[]goListPackage{runtimePkg("go1.28.0")}, "1.27.2", "toolchain go 1.28.0 is newer than choam's go/types (go1.27.2): " + remedy},
		"go directive newer":    {[]goListPackage{runtimePkg("go1.27.2"), modulePkg("1.28")}, "1.27.2", "module example.com/x's go directive (go 1.28) is newer than choam's go/types (go1.27.2): " + remedy},
		"devel toolchain":       {[]goListPackage{runtimePkg("devel go1.28-abcdef")}, "1.27.2", ""},
		"devel host":            {[]goListPackage{runtimePkg("go1.27.2")}, "devel go1.28-abcdef", ""},
		"no runtime in listing": {[]goListPackage{modulePkg("1.21")}, "1.27.2", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := typecheckEligible(tc.pkgs, tc.host)
			require.Error(t, err)
			if tc.tooNew != "" {
				assert.ErrorIs(t, err, ErrToolchainTooNew)
				assert.EqualError(t, err, tc.tooNew)
			} else {
				assert.NotErrorIs(t, err, ErrToolchainTooNew, "an unknown version is a plain error: %v", err)
			}
		})
	}

	_, err = (&GoToolchain{}).typecheck(t.Context(), []goListPackage{runtimePkg("go1.999.0")}, "amd64")
	assert.ErrorIs(t, err, ErrToolchainTooNew, "an ineligible graph is an error, not a verdict")

	_, err = (&GoToolchain{}).typecheck(t.Context(), []goListPackage{runtimePkg(runtime.Version())}, "nosucharch")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrToolchainTooNew)
	assert.Contains(t, err.Error(), "no gc sizes for GOARCH=nosucharch")
}

// TestTypecheck_LockstepBreak: on the otel-like lockstep break the engine
// reports exactly the lagging module's package, with gc's diagnostic (one
// line for the two same-line uses, as gc dedups) located in its module-cache
// copy.
func TestTypecheck_LockstepBreak(t *testing.T) {
	toolchain, dir := otelLikeFixture(t)
	ctx := t.Context()
	target := BuildTarget{Tags: []string{"netgo", "osusergo"}}

	report, err := toolchain.Compile(ctx, dir, target, "amd64")
	require.NoError(t, err)
	assert.Empty(t, report.Failed, "pristine fixture type-checks")

	require.NoError(t, toolchain.Get(ctx, dir, "example.com/api@v0.21.0"))
	require.NoError(t, toolchain.ModTidy(ctx, dir))

	report, err = toolchain.Compile(ctx, dir, target, "amd64")
	require.NoError(t, err)
	require.Equal(t, []string{"example.com/exporter"}, slices.Sorted(maps.Keys(report.Failed)))
	lines := report.Failed["example.com/exporter"]
	require.Len(t, lines, 1)
	assert.True(t, strings.HasSuffix(lines[0], filepath.FromSlash("/example.com/exporter@v0.19.0/otlp.go")+":5:19: undefined: api.KeyValue"), lines[0])
	assert.Equal(t, map[string]string{"example.com/app": "", "example.com/exporter": "example.com/exporter", "example.com/api": "example.com/api"}, report.Modules)
	assert.Equal(t, map[string][]string{"example.com/exporter": {"example.com/api"}}, report.Imports)
}

// TestTypecheck_CgoLimitation_CTypedErrorNotCaught pins an ACCEPTED
// limitation: cgo files are checked against a fake "C" package (no C
// toolchain runs), every C.x has an invalid type and cgoArtefact drops the
// resulting "invalid type/operand" errors, so an error whose root cause is
// a C-typed expression - in the cgo package or in an importer of its C-typed
// API - is not caught (real cgo fails each case below except the "ok" one,
// which guards against the artefacts becoming false positives). Go-side errors
// in cgo packages are caught (see TestTypecheck_CgoPackageLockstepBreak).
func TestTypecheck_CgoLimitation_CTypedErrorNotCaught(t *testing.T) {
	const preamble = "package main\n\n// static int add(int a, int b) { return a + b; }\n// struct pt { int x; };\nimport \"C\"\n\n"
	const cgoLib = "package lib\n\n// static int num(void) { return 7; }\nimport \"C\"\n\nfunc Num() C.int { return C.num() }\n"
	for name, files := range map[string]map[string]string{
		"go string to C int":           {"cgo.go": preamble + "func main() { _ = C.add(\"x\", 2) }\n"},
		"wrong C struct field":         {"cgo.go": preamble + "func main() { var p C.struct_pt; _ = p.y }\n"},
		"C result used as Go string":   {"cgo.go": preamble + "func s() string { return C.add(1, 2) }\n\nfunc main() { _ = s() }\n"},
		"exported C type misused":      {"lib/lib.go": cgoLib, "main.go": "package main\n\nimport \"example.com/m/lib\"\n\nvar _ int = lib.Num()\n\nfunc main() {}\n"},
		"exported C type converted ok": {"lib/lib.go": cgoLib, "main.go": "package main\n\nimport \"example.com/m/lib\"\n\nvar _ = int(lib.Num())\n\nfunc main() {}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			files["go.mod"] = "module example.com/m\n\ngo 1.21\n"
			toolchain, dir := typecheckFixture(t, files)
			report, err := toolchain.Compile(t.Context(), dir, BuildTarget{Env: BuildEnv{CGO: "1"}}, "amd64")
			require.NoError(t, err)
			assert.Empty(t, report.Failed)
		})
	}
}

// TestTypecheck_CgoPackageLockstepBreak: an API-breaking bump of a Go
// dependency of a cgo package is flagged on the cgo package.
func TestTypecheck_CgoPackageLockstepBreak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping go toolchain integration test in -short mode")
	}
	dep := func(fn string) map[string]string {
		return map[string]string{"go.mod": "module example.com/dep\n\ngo 1.21\n", "dep.go": "package dep\n\nfunc " + fn + "() int { return 1 }\n"}
	}
	useFileProxy(t, writeFileProxy(t, map[string]map[string]string{
		"example.com/dep@v1.0.0": dep("Value"),
		"example.com/dep@v1.1.0": dep("Get"),
	}))
	dir := newFixtureModule(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n",
		"cgo.go":  "package main\n\n// static int add(int a, int b) { return a + b; }\nimport \"C\"\n\nimport \"example.com/dep\"\n\nfunc sum() int { return int(C.add(C.int(dep.Value()), 2)) }\n",
		"main.go": "package main\n\nfunc main() { _ = sum() }\n",
	})
	toolchain, err := NewToolchain(t.Context(), 2*time.Minute)
	require.NoError(t, err)
	ctx, target := t.Context(), BuildTarget{Env: BuildEnv{CGO: "1"}}

	require.NoError(t, toolchain.Get(ctx, dir, "example.com/dep@v1.1.0"))
	report, err := toolchain.Compile(ctx, dir, target, "amd64")
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com/app"}, slices.Sorted(maps.Keys(report.Failed)))
	assert.Contains(t, strings.Join(report.Failed["example.com/app"], "\n"), "undefined: dep.Value")
}
