package simulate

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Linkage replay fixtures (flux-shaped): the main package embeds files the
// build generates (`//go:embed gen/*.txt`, gen/ absent from the checkout).

const (
	modUsed     = "example.com/used"     // imported by the embedding main package
	modTestOnly = "example.com/testonly" // imported by main_test.go only
	modWinOnly  = "example.com/winonly"  // all files //go:build windows
	advUsed     = "GO-TEST-USED"
	advTestOnly = "GO-TEST-TESTONLY"
)

func linkageModules() map[string]map[string]string {
	modules := make(map[string]map[string]string)
	for _, version := range []string{"v1.0.0", "v1.0.1"} {
		modules[modUsed+"@"+version] = stubModule(modUsed, "used.go", "package used\n\nfunc Name() string { return \"used\" }\n", nil)
		modules[modTestOnly+"@"+version] = stubModule(modTestOnly, "testonly.go", "package testonly\n\nfunc Name() string { return \"t\" }\n", nil)
	}
	modules[modWinOnly+"@v1.0.0"] = stubModule(modWinOnly, "win.go", "//go:build windows\n\npackage winonly\n\nfunc Name() string { return \"win\" }\n", nil)
	return modules
}

// linkageCase builds the replay case: extraImport is an additional import
// of the main package ("" for none).
func linkageCase(name, extraImport string) replayCase {
	requires := "\t" + modUsed + " v1.0.0\n\t" + modTestOnly + " v1.0.0\n"
	imports := "\t\"" + modUsed + "\"\n"
	if extraImport != "" {
		requires += "\t" + extraImport + " v1.0.0\n"
		imports += "\t_ \"" + extraImport + "\"\n"
	}
	advisories := []fakeAdvisory{
		{module: modUsed, id: advUsed, fixed: "v1.0.1", severity: "HIGH", imports: []scan.VulnerableImport{{Path: modUsed}}},
		{module: modTestOnly, id: advTestOnly, fixed: "v1.0.1", severity: "HIGH", imports: []scan.VulnerableImport{{Path: modTestOnly}}},
	}
	sc := func() *fakeScanner { return &fakeScanner{advisories: advisories} }
	c := replayCase{
		name:    name,
		modules: linkageModules(),
		main: map[string]string{
			"go.mod": "module example.com/app\n\ngo 1.21\n\nrequire (\n" + requires + ")\n",
			"main.go": "package main\n\nimport (\n\t_ \"embed\"\n\t\"fmt\"\n\n" + imports + ")\n\n" +
				"//go:embed gen/*.txt\nvar manifests string\n\nfunc main() { fmt.Println(manifests, used.Name()) }\n",
			"main_test.go": "package main\n\nimport (\n\t\"testing\"\n\n\t\"" + modTestOnly + "\"\n)\n\n" +
				"func TestName(t *testing.T) { _ = testonly.Name() }\n",
		},
		sc: sc,
		req: ModrootRequest{
			Modroot:     ".",
			Baseline:    map[string]string{modUsed: "v1.0.0", modTestOnly: "v1.0.0"},
			Tags:        replayTags,
			VulnImports: vulnImportsOf(sc()),
		},
	}
	if extraImport != "" {
		c.req.Baseline[extraImport] = "v1.0.0"
	}
	c.req.Seeds = baselineSeeds(c, nil)
	return c
}

// TestGoToolchain_LinkedToleratesUnmatchedEmbed: an unmatched go:embed
// pattern no longer hides the import graph - Linked lists it from the
// imports and reports the gap, deterministically.
func TestGoToolchain_LinkedToleratesUnmatchedEmbed(t *testing.T) {
	c := linkageCase("embed", "")
	f := c.fixture(t)
	_, err := os.Stat(filepath.Join(f.dir, "gen"))
	require.True(t, os.IsNotExist(err), "the embedded files are absent")

	first, err := f.tc.Linked(t.Context(), f.dir, BuildTarget{Tags: replayTags})
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"example.com/app": {}, modUsed: {}}, first.Modules)
	assert.Equal(t, map[string]struct{}{"example.com/app": {}, modUsed: {}}, first.Packages)
	assert.Equal(t, []UnmatchedEmbed{{Package: "example.com/app", Pattern: "gen/*.txt"}}, first.Embeds,
		"both arches' gap merged into one")
	std, err := f.tc.LinkedStd(t.Context(), f.dir, BuildTarget{Tags: replayTags})
	require.NoError(t, err)
	assert.Contains(t, std, "fmt")
	assert.Contains(t, std, "embed")

	for i := range 20 {
		again, err := f.tc.Linked(t.Context(), f.dir, BuildTarget{Tags: replayTags})
		require.NoError(t, err)
		assert.Equal(t, first, again, "run %d", i)
	}
}

// TestReplay_UnmatchedEmbed: with the embed gap tolerated, reachability is
// known: the advisory in the embedding package's import is a linked fix,
// the test-only one is unlinked; the gap is reported. The type-check does
// not resolve //go:embed, so the embedding package is checked like any
// other: no baseline failure, no gate blind spot.
func TestReplay_UnmatchedEmbed(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		c := linkageCase("embed", "")
		f := c.fixture(t)
		result, err := c.run(t, f, eng, false)
		require.NoError(t, err)
		logResult(t, result)

		assert.Empty(t, result.LinkageError)
		assert.Equal(t, []UnmatchedEmbed{{Package: "example.com/app", Pattern: "gen/*.txt"}}, result.UnmatchedEmbeds)
		require.NotNil(t, result.Linked, "reachability known")
		assert.Equal(t, []string{modUsed + "@v1.0.1"}, result.FinalDeps)
		assert.Equal(t, []string{modUsed}, result.CVEBackedModules)
		i := slices.IndexFunc(result.Dropped, func(d DroppedCandidate) bool { return d.Module == modTestOnly })
		require.GreaterOrEqual(t, i, 0, "the test-only advisory is shed as unlinked")
		assert.Contains(t, result.Dropped[i].Reason, "module not linked")
		assert.Empty(t, result.Residuals)

		assert.Zero(t, result.GateUnchecked, "the embed gap is not a type-check failure")
		assert.Empty(t, result.GateUncheckedFirst)
	})
}

// TestReplay_LinkageUnavailable: a non-embed load error (a package whose
// files all build only on windows) still fails reachability OPEN - the
// test-only advisory is fixed as if linked - with the precise cause.
func TestReplay_LinkageUnavailable(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		c := linkageCase("unavailable", modWinOnly)
		f := c.fixture(t)
		result, err := c.run(t, f, eng, false)
		require.NoError(t, err)
		logResult(t, result)

		assert.Nil(t, result.Linked, "fail open")
		assert.Nil(t, result.LinkedPackages)
		assert.Empty(t, result.UnmatchedEmbeds)
		assert.Contains(t, result.LinkageError, "GOARCH=amd64: go list -deps: package "+modWinOnly+": build constraints exclude all Go files")
		assert.NotContains(t, result.LinkageError, "\n")
		assert.Equal(t, []string{modTestOnly + "@v1.0.1", modUsed + "@v1.0.1"}, sortedCopy(result.FinalDeps),
			"unknown reachability treats every advisory as linked")
	})
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}
