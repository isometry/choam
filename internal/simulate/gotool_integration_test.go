package simulate

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
