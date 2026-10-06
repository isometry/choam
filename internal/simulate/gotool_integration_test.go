package simulate

import (
	"context"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

// TestRunLoop_RealToolchain exercises the loop end-to-end with the real go
// tool, module proxy, and OSV API. Guarded: skipped under -short, when no go
// binary is available, or unless CHOAM_NETWORK_TESTS is set.
func TestRunLoop_RealToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short mode")
	}
	if os.Getenv("CHOAM_NETWORK_TESTS") == "" {
		t.Skip("set CHOAM_NETWORK_TESTS=1 to run network integration tests")
	}

	toolchain, err := NewToolchain(t.Context(), 2*time.Minute)
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}

	// A tiny module pinned to an old golang.org/x/text with known advisories
	// (e.g. GO-2021-0113, fixed in v0.3.7; GO-2022-1059, fixed in v0.3.8).
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(
		"module example.com/simfixture\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.5\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(
		"package main\n\nimport (\n\t\"fmt\"\n\n\t\"golang.org/x/text/language\"\n)\n\nfunc main() {\n\tfmt.Println(language.English)\n}\n"), 0o644))

	// Populate go.sum so the pristine snapshot is complete.
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	scanner := scan.NewVulnerabilityScanner(&http.Client{Timeout: 30 * time.Second})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	result, err := RunLoop(ctx, toolchain, scanner, dir, ModrootRequest{
		Modroot:  ".",
		Baseline: map[string]string{"golang.org/x/text": "v0.3.5"},
	}, Options{})
	require.NoError(t, err)

	assert.True(t, result.Converged, "loop must reach a fixpoint")
	// x/text must have been raised past every known advisory.
	for _, residual := range result.Residuals {
		assert.NotEqual(t, "golang.org/x/text", residual.Module,
			"x/text advisories are all fixed upstream; none may remain residual")
	}
	var raised bool
	for _, dep := range result.FinalDeps {
		if dep == "golang.org/x/text@v0.3.5" {
			t.Errorf("x/text left at vulnerable v0.3.5")
		}
		if len(dep) > len("golang.org/x/text@") && dep[:len("golang.org/x/text@")] == "golang.org/x/text@" {
			raised = true
		}
	}
	assert.True(t, raised, "expected a raised golang.org/x/text entry in FinalDeps, got %v", result.FinalDeps)
}

// TestGoToolchain_ReplaceRoundTrip exercises Replace/Replaces against the
// real go tool (no network needed - pure go.mod edits).
func TestGoToolchain_ReplaceRoundTrip(t *testing.T) {
	toolchain, err := NewToolchain(t.Context(), time.Minute)
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(
		"module example.com/replacefixture\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.5\n\nreplace example.com/local => ./local\n"), 0o644))

	replaces, err := toolchain.Replaces(t.Context(), dir)
	require.NoError(t, err)
	require.Contains(t, replaces, "example.com/local")
	assert.Equal(t, "", replaces["example.com/local"].Version, "local target must carry empty version")

	require.NoError(t, toolchain.Replace(t.Context(), dir, "golang.org/x/text", "golang.org/x/text", "v0.3.8"))
	// Re-applying must not error (dropreplace-first parity with gobump).
	require.NoError(t, toolchain.Replace(t.Context(), dir, "golang.org/x/text", "golang.org/x/text", "v0.3.8"))

	replaces, err = toolchain.Replaces(t.Context(), dir)
	require.NoError(t, err)
	require.Contains(t, replaces, "golang.org/x/text")
	assert.Equal(t, ReplaceTarget{Path: "golang.org/x/text", Version: "v0.3.8"}, replaces["golang.org/x/text"])
	assert.Contains(t, replaces, "example.com/local", "unrelated directives untouched")
}

// TestGoToolchain_LinkedModules exercises the reachability query against the
// real go tool and module proxy: a module that is imported only by tests
// must be absent from the linked set, and GOOS=linux must not break listing.
func TestGoToolchain_LinkedModules(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short mode")
	}
	if os.Getenv("CHOAM_NETWORK_TESTS") == "" {
		t.Skip("set CHOAM_NETWORK_TESTS=1 to run network integration tests")
	}

	toolchain, err := NewToolchain(t.Context(), 2*time.Minute)
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(
		"module example.com/linkedfixture\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/text v0.14.0\n\tgithub.com/google/go-cmp v0.6.0\n)\n"), 0o644))
	// main.go links x/text; go-cmp is imported ONLY by the test file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(
		"package main\n\nimport (\n\t\"fmt\"\n\n\t\"golang.org/x/text/language\"\n)\n\nfunc main() {\n\tfmt.Println(language.English)\n}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main_test.go"), []byte(
		"package main\n\nimport (\n\t\"testing\"\n\n\t\"github.com/google/go-cmp/cmp\"\n)\n\nfunc TestDiff(t *testing.T) {\n\tif d := cmp.Diff(1, 1); d != \"\" {\n\t\tt.Fatal(d)\n\t}\n}\n"), 0o644))

	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	linked, linkedPackages, err := toolchain.Linked(t.Context(), dir, nil) // nil -> ./...
	require.NoError(t, err)

	assert.Contains(t, linked, "golang.org/x/text", "main-linked module must be reachable")
	assert.NotContains(t, linked, "github.com/google/go-cmp",
		"test-only module must be excluded (buildinfo parity)")

	// Package granularity: the imported subpackage is linked; a subpackage
	// of the same module that nothing imports is not.
	assert.Contains(t, linkedPackages, "golang.org/x/text/language",
		"imported package must be in the linked package set")
	assert.NotContains(t, linkedPackages, "golang.org/x/text/number",
		"never-imported subpackage of a linked module must be absent")
}

// TestGoToolchain_DepGoVersionsAndLinkedStd exercises DepGoVersions and
// LinkedStd against the real go tool with a dependency-free fixture module -
// no go.sum, no network: `go list -m -json all` reports only the (skipped)
// main module, and `go list -deps` walks the standard library only.
func TestGoToolchain_DepGoVersionsAndLinkedStd(t *testing.T) {
	toolchain, err := NewToolchain(t.Context(), time.Minute)
	if err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(
		"module example.com/stdlibfixture\n\ngo 1.21\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(
		"package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() {\n\tfmt.Fprintln(os.Stdout, \"hi\")\n}\n"), 0o644))

	versions, err := toolchain.DepGoVersions(t.Context(), dir)
	require.NoError(t, err)
	assert.Empty(t, versions, "dependency-free module has no non-main modules to report")

	std, err := toolchain.LinkedStd(t.Context(), dir, nil) // nil -> ./...
	require.NoError(t, err)
	assert.Contains(t, std, "fmt")
	assert.Contains(t, std, "os")
}

// writeFileProxy builds a file:// GOPROXY serving the given module versions
// (module@version -> file name -> content; go.mod is required), so a real go
// toolchain can resolve and compile against them with no network access.
func writeFileProxy(t *testing.T, modules map[string]map[string]string) string {
	t.Helper()
	proxy := t.TempDir()
	src := t.TempDir()
	lists := make(map[string][]string)
	for coord, files := range modules {
		modPath, version, ok := strings.Cut(coord, "@")
		require.True(t, ok, coord)
		dir := filepath.Join(src, filepath.FromSlash(modPath)+"@"+version)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		for name, content := range files {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
		}

		escaped, err := module.EscapePath(modPath)
		require.NoError(t, err)
		versionDir := filepath.Join(proxy, filepath.FromSlash(escaped), "@v")
		require.NoError(t, os.MkdirAll(versionDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(versionDir, version+".mod"), []byte(files["go.mod"]), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(versionDir, version+".info"),
			[]byte(`{"Version":"`+version+`","Time":"2024-01-01T00:00:00Z"}`), 0o644))
		zipFile, err := os.Create(filepath.Join(versionDir, version+".zip"))
		require.NoError(t, err)
		require.NoError(t, modzip.CreateFromDir(zipFile, module.Version{Path: modPath, Version: version}, dir))
		require.NoError(t, zipFile.Close())
		lists[versionDir] = append(lists[versionDir], version)
	}
	for versionDir, versions := range lists {
		require.NoError(t, os.WriteFile(filepath.Join(versionDir, "list"), []byte(strings.Join(versions, "\n")+"\n"), 0o644))
	}
	return proxy
}

// otelLikeFixture reproduces the opentofu otel-log break with real modules:
// example.com/api v0.21.0 drops the KeyValue type example.com/exporter
// v0.19.0/v0.20.0 compile against; exporter v0.21.0 is the first release
// whose go.mod requires (and code uses) the new api. The main module links
// exporter; raising api alone resolves and tidies cleanly but no longer
// compiles.
func otelLikeFixture(t *testing.T) (toolchain *GoToolchain, dir string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping go toolchain integration test in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}

	exporter := func(apiVersion, apiType string) map[string]string {
		return map[string]string{
			"go.mod":  "module example.com/exporter\n\ngo 1.21\n\nrequire example.com/api " + apiVersion + "\n",
			"otlp.go": "package exporter\n\nimport \"example.com/api\"\n\nfunc Record() api." + apiType + " { return api." + apiType + "{} }\n",
		}
	}
	proxy := writeFileProxy(t, map[string]map[string]string{
		"example.com/api@v0.19.0": {
			"go.mod": "module example.com/api\n\ngo 1.21\n",
			"api.go": "package api\n\ntype KeyValue struct{ Key, Value string }\n",
		},
		"example.com/api@v0.21.0": {
			"go.mod": "module example.com/api\n\ngo 1.21\n",
			"api.go": "package api\n\ntype Attr struct{ Key, Value string }\n",
		},
		"example.com/exporter@v0.19.0": exporter("v0.19.0", "KeyValue"),
		"example.com/exporter@v0.20.0": exporter("v0.19.0", "KeyValue"),
		"example.com/exporter@v0.21.0": exporter("v0.21.0", "Attr"),
	})

	useFileProxy(t, proxy)
	dir = newFixtureModule(t, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.21\n\nrequire example.com/exporter v0.19.0\n",
		"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/exporter\"\n)\n\nfunc main() { fmt.Println(exporter.Record()) }\n",
	})

	toolchain, err := NewToolchain(t.Context(), 2*time.Minute)
	require.NoError(t, err)
	return toolchain, dir
}

// useFileProxy points the go tool at a file:// GOPROXY (see writeFileProxy)
// with checksum verification off and a private module cache, for the rest
// of the test.
func useFileProxy(t *testing.T, proxy string) {
	t.Helper()
	modCache := t.TempDir()
	t.Setenv("GOPROXY", "file://"+filepath.ToSlash(proxy))
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOMODCACHE", modCache)
	t.Setenv("GONOSUMDB", "")
	t.Setenv("GOPRIVATE", "")
	t.Cleanup(func() {
		// The module cache is read-only; clean it before TempDir removal.
		cmd := exec.Command("go", "clean", "-modcache")
		cmd.Env = os.Environ()
		_ = cmd.Run()
	})
}

// newFixtureModule writes a main module (file name -> content; go.mod
// required) and tidies it so the pristine snapshot carries a complete
// go.sum.
func newFixtureModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return dir
}

// TestGoToolchain_CompileReportsLockstepBreak: the compile primitive must
// see what resolution cannot - per-package errors located in the mod-cache
// copy of the lagging module - while a clean graph reports nothing.
func TestGoToolchain_CompileReportsLockstepBreak(t *testing.T) {
	toolchain, dir := otelLikeFixture(t)
	ctx := t.Context()

	report, err := toolchain.Compile(ctx, dir, nil, []string{"netgo", "osusergo"})
	require.NoError(t, err)
	assert.Empty(t, report.Failed, "pristine fixture compiles")
	assert.Equal(t, "", report.Modules["example.com/app"], "main-module package maps to the empty module")
	assert.Equal(t, "example.com/exporter", report.Modules["example.com/exporter"])

	require.NoError(t, toolchain.Get(ctx, dir, "example.com/api@v0.21.0"))
	require.NoError(t, toolchain.ModTidy(ctx, dir), "MVS has no upper bounds: the raise tidies cleanly")

	report, err = toolchain.Compile(ctx, dir, nil, nil)
	require.NoError(t, err)
	require.Contains(t, report.Failed, "example.com/exporter")
	assert.Contains(t, strings.Join(report.Failed["example.com/exporter"], "\n"), "undefined: api.KeyValue")
	assert.NotContains(t, report.Failed, "example.com/app", "dependents of a broken package are not compiled")
	assert.Contains(t, report.Imports["example.com/exporter"], "example.com/api")
	assert.Contains(t, slices.Collect(maps.Values(report.FileModules)), "example.com/exporter@v0.19.0",
		"mod-cache error paths map back to module@version")

	versions, err := toolchain.ModuleVersions(ctx, dir, "example.com/exporter")
	require.NoError(t, err)
	assert.Equal(t, []string{"v0.19.0", "v0.20.0", "v0.21.0"}, versions)
	requires, err := toolchain.ModuleRequires(ctx, dir, "example.com/exporter", "v0.21.0")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"example.com/api": "v0.21.0"}, requires)
}

// TestRunLoop_CompileGateRepairsLockstepBreak drives the whole loop with the
// real toolchain: the api fix alone would ship a build that does not
// compile; the gate must add the minimal coherent exporter (v0.21.0 - not
// v0.20.0, whose go.mod still requires the old api).
func TestRunLoop_CompileGateRepairsLockstepBreak(t *testing.T) {
	toolchain, dir := otelLikeFixture(t)
	sc := &fakeScanner{advisories: []fakeAdvisory{{module: "example.com/api", id: "GO-API", fixed: "v0.21.0"}}}

	result, err := RunLoop(t.Context(), toolchain, sc, dir, ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/api", Version: "v0.21.0", FromCVE: true, VulnIDs: []string{"GO-API"}, Severity: "HIGH"},
		},
		Baseline: map[string]string{"example.com/api": "v0.19.0", "example.com/exporter": "v0.19.0"},
		Tags:     []string{"netgo", "osusergo"},
	}, Options{})
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"example.com/api@v0.21.0", "example.com/exporter@v0.21.0"}, result.FinalDeps)
	assert.Empty(t, result.Residuals)
	assert.Equal(t, "v0.21.0", result.Resolved["example.com/exporter"])
}
