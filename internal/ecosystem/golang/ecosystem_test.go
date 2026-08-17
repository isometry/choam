package golang

import (
	"context"
	"strings"
	"testing"

	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

func TestEcosystem_BumpCoords(t *testing.T) {
	eco := New()
	info := &GoModInfo{
		AllRequirements: map[string]string{
			"github.com/cli/go-gh/v2":      "v2.10.0",
			"github.com/stretchr/testify":  "v1.8.4",
			"software.sslmate.com/src/foo": "v0.7.0",
		},
		Replacements: map[string]*modfile.Replace{},
	}
	deps := &ecosystem.ModuleDeps{Raw: info}

	t.Run("v2+ module named without suffix by OSV normalizes to go.mod path", func(t *testing.T) {
		bump := scan.SecurityBump{Name: "github.com/cli/go-gh", FixedVersion: "v2.11.1", VulnIDs: []string{"GO-2024-0001"}}
		coords := eco.BumpCoords(t.Context(), []scan.SecurityBump{bump}, deps)
		require.Len(t, coords, 1)
		assert.Equal(t, bump, coords["github.com/cli/go-gh/v2"])
	})

	t.Run("plain module maps identity", func(t *testing.T) {
		coords := eco.BumpCoords(t.Context(), []scan.SecurityBump{
			{Name: "github.com/stretchr/testify", FixedVersion: "v1.9.0"},
		}, deps)
		require.Len(t, coords, 1)
		assert.Contains(t, coords, "github.com/stretchr/testify")
	})

	t.Run("module absent from go.mod still yields a key", func(t *testing.T) {
		coords := eco.BumpCoords(t.Context(), []scan.SecurityBump{
			{Name: "github.com/unknown/module", FixedVersion: "v1.0.0"},
		}, deps)
		require.Len(t, coords, 1)
		assert.Contains(t, coords, "github.com/unknown/module")
	})

	t.Run("nil Raw returns nil", func(t *testing.T) {
		coords := eco.BumpCoords(t.Context(), []scan.SecurityBump{
			{Name: "github.com/any/module", FixedVersion: "v1.0.0"},
		}, &ecosystem.ModuleDeps{})
		assert.Nil(t, coords)
	})
}

// TestEcosystem_AnalyzeAndScanPackages exercises the public Ecosystem surface
// with realistic go.mod/go.sum content, in particular the replace-directive
// resolution that ScanPackages owns (relocated here from the old
// scan.ScanGoMod, whose test suite was deleted with it). The fixture is a
// pre-1.17 module so the go.sum merge path stays covered - modern modules
// skip it (see TestEcosystem_Analyze_ModernGoIgnoresGoSumOnlyModules).
func TestEcosystem_AnalyzeAndScanPackages(t *testing.T) {
	goMod := `module example.com/app

go 1.16

require (
	github.com/direct/dep v1.2.3
	github.com/exact/dep v1.0.0
	github.com/local/dep v1.0.0
	github.com/moved/dep v1.0.0
)

replace github.com/local/dep => ../local

replace github.com/moved/dep => github.com/fork/dep v2.0.0

replace github.com/exact/dep v1.0.0 => github.com/exact/fork v1.5.0
`
	// go.sum contributes indirect deps; a lower duplicate proves highest-wins.
	goSum := `github.com/direct/dep v1.2.3 h1:hash=
github.com/direct/dep v1.2.3/go.mod h1:hash=
github.com/indirect/dep v0.8.0 h1:hash=
github.com/indirect/dep v0.9.0 h1:hash=
github.com/indirect/dep v0.9.0/go.mod h1:hash=
`

	eco := New()
	deps, err := eco.Analyze(context.Background(), map[string][]byte{
		"go.mod": []byte(goMod),
		"go.sum": []byte(goSum),
	})
	require.NoError(t, err)

	byName := make(map[string]ecosystem.Dep, len(deps.Deps))
	for _, dep := range deps.Deps {
		byName[dep.Name] = dep
	}

	direct, ok := byName["github.com/direct/dep"]
	require.True(t, ok)
	assert.False(t, direct.Indirect)

	indirect, ok := byName["github.com/indirect/dep"]
	require.True(t, ok)
	assert.True(t, indirect.Indirect)
	assert.Equal(t, "v0.9.0", indirect.Version, "go.sum duplicate versions - highest wins")

	pkgs := eco.ScanPackages(t.Context(), deps)
	byPkg := make(map[string]scan.Package, len(pkgs))
	for _, pkg := range pkgs {
		byPkg[pkg.Name] = pkg
		assert.Equal(t, "Go", pkg.Ecosystem)
		assert.False(t, strings.HasPrefix(pkg.Name, "std"), "stdlib must never be scanned")
	}

	// Local-path replace: skipped entirely (no meaningful version to query).
	assert.NotContains(t, byPkg, "github.com/local/dep")

	// Module->module replace: scanned under the replacement name and version.
	assert.NotContains(t, byPkg, "github.com/moved/dep")
	require.Contains(t, byPkg, "github.com/fork/dep")
	assert.Equal(t, "v2.0.0", byPkg["github.com/fork/dep"].Version)

	// Versioned exact replace: same substitution, keyed by module@version.
	assert.NotContains(t, byPkg, "github.com/exact/dep")
	require.Contains(t, byPkg, "github.com/exact/fork")
	assert.Equal(t, "v1.5.0", byPkg["github.com/exact/fork"].Version)

	// Unreplaced deps scan as-is.
	require.Contains(t, byPkg, "github.com/direct/dep")
	assert.Equal(t, "v1.2.3", byPkg["github.com/direct/dep"].Version)
	require.Contains(t, byPkg, "github.com/indirect/dep")
	assert.Equal(t, "v0.9.0", byPkg["github.com/indirect/dep"].Version)
}

func TestEcosystem_Analyze_MissingGoMod(t *testing.T) {
	eco := New()
	_, err := eco.Analyze(context.Background(), map[string][]byte{})
	require.Error(t, err)
}

// TestEcosystem_ScanPackages_VersionlessReplaceFallsBackToOriginal covers the
// module->module replace-without-version branch. It's unreachable via parsed
// go.mod text (modfile requires a version-less replacement to be a directory
// path, which the local-path skip then catches), so it's exercised with a
// hand-built GoModInfo: the emitted package must carry the replacement's
// path but the ORIGINAL requirement's version.
func TestEcosystem_ScanPackages_VersionlessReplaceFallsBackToOriginal(t *testing.T) {
	info := &GoModInfo{
		AllRequirements: map[string]string{
			"github.com/moved/dep": "v1.4.0",
		},
		Replacements: map[string]*modfile.Replace{
			"github.com/moved/dep": {
				Old: module.Version{Path: "github.com/moved/dep"},
				New: module.Version{Path: "github.com/fork/dep"}, // no version
			},
		},
	}

	pkgs := New().ScanPackages(t.Context(), &ecosystem.ModuleDeps{Raw: info})
	require.Len(t, pkgs, 1)
	assert.Equal(t, "github.com/fork/dep", pkgs[0].Name)
	assert.Equal(t, "v1.4.0", pkgs[0].Version, "version-less replacement falls back to the original version")
}

// TestEcosystem_Analyze_ModernGoIgnoresGoSumOnlyModules: from go 1.17, graph
// pruning guarantees go.mod's require block lists every linkable module, so
// go.sum-only entries (pure module-graph hashes, e.g. terraform's
// hjson-go/v4) must not be analyzed or scanned - they can never ship.
func TestEcosystem_Analyze_ModernGoIgnoresGoSumOnlyModules(t *testing.T) {
	goMod := `module example.com/app

go 1.22

require github.com/direct/dep v1.2.3
`
	goSum := `github.com/direct/dep v1.2.3 h1:hash=
github.com/direct/dep v1.2.3/go.mod h1:hash=
github.com/graph/only v4.0.0 h1:hash=
github.com/graph/only v4.0.0/go.mod h1:hash=
`

	eco := New()
	deps, err := eco.Analyze(context.Background(), map[string][]byte{
		"go.mod": []byte(goMod),
		"go.sum": []byte(goSum),
	})
	require.NoError(t, err)

	for _, dep := range deps.Deps {
		assert.NotEqual(t, "github.com/graph/only", dep.Name, "go.sum-only module must not be analyzed for go>=1.17")
	}

	for _, pkg := range eco.ScanPackages(t.Context(), deps) {
		assert.NotEqual(t, "github.com/graph/only", pkg.Name, "go.sum-only module must not be scanned for go>=1.17")
	}
}
