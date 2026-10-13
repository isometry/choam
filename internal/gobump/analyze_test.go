package gobump

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/isometry/choam/internal/config"
	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitCoordVersion(t *testing.T) {
	tests := []struct {
		dep, wantCoord, wantVersion string
	}{
		{"golang.org/x/net@v0.56.0", "golang.org/x/net", "v0.56.0"},
		{"serde@1.0.200", "serde", "1.0.200"},
		{"io.netty@netty-codec-http@4.1.94.Final", "io.netty@netty-codec-http", "4.1.94.Final"},
	}

	for _, tt := range tests {
		t.Run(tt.dep, func(t *testing.T) {
			coord, version, ok := splitCoordVersion(tt.dep)
			require.True(t, ok)
			assert.Equal(t, tt.wantCoord, coord)
			assert.Equal(t, tt.wantVersion, version)
		})
	}

	t.Run("no @ at all", func(t *testing.T) {
		_, _, ok := splitCoordVersion("malformed")
		assert.False(t, ok)
	})
}

func TestRecordSecurityFixes_Attribution(t *testing.T) {
	lang := LanguageAnalysis{
		Language: "go",
		ByModroot: []ModrootAnalysis{{
			Modroot: ".",
			ScanResult: &scan.ScanResult{SecurityBumps: []scan.SecurityBump{
				{Name: "github.com/foo/bar", CurrentVersion: "v2.0.0", VulnIDs: []string{"GO-1"}, Severity: "CRITICAL"},
				{Name: "github.com/foo/baz", CurrentVersion: "v1.0.0", VulnIDs: []string{"GO-2"}},
			}},
		}},
	}
	gp := NewProcessor("test.yaml", "test", "1.0.0", 0)
	NewApplier(nil).recordSecurityFixes(gp, lang, []string{
		"github.com/foo/bar/v2@v2.1.0", // OSV name lacks the /vN suffix
		"github.com/foo/baz@v1.1.0",    // bump without severity data
		"github.com/other/mod@v1.0.0",  // no scan bump at all
	})

	require.Len(t, gp.SecurityFixes, 3)
	assert.Equal(t, SecurityFix{Module: "github.com/foo/bar/v2", Vulnerability: "GO-1", OldVersion: "v2.0.0", NewVersion: "v2.1.0", Severity: "CRITICAL"}, gp.SecurityFixes[0])
	assert.Equal(t, SecurityFix{Module: "github.com/foo/baz", Vulnerability: "GO-2", OldVersion: "v1.0.0", NewVersion: "v1.1.0", Severity: "varies"}, gp.SecurityFixes[1])
	assert.Equal(t, SecurityFix{Module: "github.com/other/mod", Vulnerability: "security vulnerability", OldVersion: "vulnerable", NewVersion: "v1.0.0", Severity: "varies"}, gp.SecurityFixes[2])
}

func TestLookupModule(t *testing.T) {
	byModule := map[string]int{"github.com/foo/bar": 1, "github.com/foo/bar/v3": 3}

	for module, want := range map[string]int{
		"github.com/foo/bar":    1,
		"github.com/foo/bar/v3": 3, // exact key wins over the trimmed alias
		"github.com/foo/bar/v2": 1, // falls back to the OSV name
	} {
		got, ok := lookupModule(byModule, module)
		assert.True(t, ok, module)
		assert.Equal(t, want, got, module)
	}
	_, ok := lookupModule(byModule, "github.com/other/mod")
	assert.False(t, ok)
}

func TestExistingDepsForModroots(t *testing.T) {
	loader := config.NewLoader()
	steps, err := loader.FindBumpSteps([]byte(certManagerLikeYAML))
	require.NoError(t, err)

	got := existingDepsForModroots([]string{"cmd/a", "cmd/b", ".", "test/e2e"}, steps)

	assert.Equal(t, []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0"}, got["cmd/a"])
	assert.Equal(t, []string{"github.com/foo/baz@v2.2.2", "golang.org/x/net@v0.55.0"}, got["test/e2e"])
	// "cmd/b" and "." are covered by both steps - deduplicated union of both.
	assert.ElementsMatch(t, []string{
		"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0", "github.com/foo/baz@v2.2.2",
	}, got["cmd/b"])
	assert.ElementsMatch(t, []string{
		"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0", "github.com/foo/baz@v2.2.2",
	}, got["."])
}

// fakeRawGitHubTransport serves goMod for any raw.githubusercontent.com
// request whose path ends in "/go.mod", and empty content for anything else
// (go.sum) - so performAnalysis's manifest fetch never touches the real
// network. Any request to a different host fails outright, so a fallback to
// the GitHub Contents API (see internal/github/searcher.go) is a hard test
// failure rather than a silent real network call.
type fakeRawGitHubTransport struct {
	goMod []byte
}

func (f fakeRawGitHubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "raw.githubusercontent.com" {
		return nil, fmt.Errorf("unexpected request to %s in test", req.URL)
	}
	body := []byte{}
	if strings.HasSuffix(req.URL.Path, "/go.mod") {
		body = f.goMod
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

// TestPerformAnalysis_ReplacesPassThroughDepsFiltered locks the deps-vs-
// replaces asymmetry at the analysis seam: a deps entry for a module absent
// from the fetched go.mod is dropped by Ecosystem.FilterBumps, while a
// replaces entry for that same absent module flows into DesiredReplaces
// untouched (performAnalysis never filters replaces - see
// ModrootAnalysis.DesiredReplaces). This is exactly the asymmetry omnibump
// requires (AUTO-954): a bare require would be pruned back out by go mod
// tidy, but a replace directive survives it.
func TestPerformAnalysis_ReplacesPassThroughDepsFiltered(t *testing.T) {
	goModContent := []byte("module example.com/thing\n\ngo 1.21\n")
	httpClient := &http.Client{Transport: fakeRawGitHubTransport{goMod: goModContent}}

	v := &VulnerabilityChecker{Analyzer: NewAnalyzer(httpClient)}
	eco := ecogolang.New()
	gp := newTestProcessor(t, singleGoBumpYAML)

	bumpSteps := []config.BumpStep{
		{
			Action:   "go/bump",
			Language: "go",
			Modroots: []string{"."},
			Deps:     []string{"example.com/absent@v1.0.0"},
			Replaces: []string{"example.com/absent=example.com/absent@v1.0.0"},
		},
	}
	langUnits := []analysisUnit{{Modroot: "."}}

	result, err := v.performAnalysis(t.Context(), eco, "go", "https://github.com/testorg/testrepo", "v0.0.0", langUnits, bumpSteps, gp)
	require.NoError(t, err)
	require.Len(t, result.Analysis.ByModroot, 1)

	m := result.Analysis.ByModroot[0]
	assert.Empty(t, m.DesiredDeps, "deps entry for a module absent from go.mod must be filtered out")
	assert.Equal(t, []string{"example.com/absent=example.com/absent@v1.0.0"}, m.DesiredReplaces,
		"replaces entry for the same absent module must pass through untouched")
}

func TestNewlyAddedDeps(t *testing.T) {
	existing := []string{"golang.org/x/net@v0.54.0", "github.com/foo/bar@v1.0.0"}
	desired := []string{"golang.org/x/net@v0.55.0", "github.com/foo/bar@v1.0.0", "github.com/foo/baz@v2.0.0"}

	added := newlyAddedDeps(existing, desired)
	assert.ElementsMatch(t, []string{"golang.org/x/net@v0.55.0", "github.com/foo/baz@v2.0.0"}, added)
}

// TestAddedAcrossRoots_ExcludesCoherenceOnlyCoUpdates guards the accounting
// fix for Go's co-update discovery: a dependency added purely to keep the
// module graph coherent (no CVE of its own - see
// ModrootAnalysis.SecurityBumpModules) must not be credited toward
// SecurityFixes/epoch-bump accounting, even though it does appear in
// DesiredDeps and does get written to the bump step.
func TestAddedAcrossRoots_ExcludesCoherenceOnlyCoUpdates(t *testing.T) {
	byModroot := []ModrootAnalysis{
		{
			Modroot:      ".",
			ExistingDeps: []string{"github.com/a/pkg@v1.0.0", "github.com/b/pkg@v1.0.0"},
			DesiredDeps:  []string{"github.com/a/pkg@v1.1.0", "github.com/b/pkg@v1.2.0"},
			// Only a/pkg was actually OSV-flagged; b/pkg@v1.2.0 was folded
			// in purely as a co-update sibling.
			SecurityBumpModules: []string{"github.com/a/pkg"},
		},
	}

	added := addedAcrossRoots(byModroot)
	assert.Equal(t, []string{"github.com/a/pkg@v1.1.0"}, added)
}

// TestAddedAcrossRoots_NoSecurityBumpModulesExcludesEverything covers the
// degenerate case (e.g. a language/test fixture that never sets
// SecurityBumpModules): with no known security-flagged modules, nothing is
// credited as a security fix, even if deps changed.
func TestAddedAcrossRoots_NoSecurityBumpModulesExcludesEverything(t *testing.T) {
	byModroot := []ModrootAnalysis{
		{
			Modroot:      ".",
			ExistingDeps: []string{"github.com/a/pkg@v1.0.0"},
			DesiredDeps:  []string{"github.com/a/pkg@v1.1.0"},
		},
	}

	added := addedAcrossRoots(byModroot)
	assert.Empty(t, added)
}

// TestRecordHygieneBumps: only newly written entries the simulation
// marked as hygiene are recorded - once per module@version across modroots,
// with the analysis's prior version and severity - and never as security
// fixes; JSON/YAML carry them under their own keys.
func TestRecordHygieneBumps(t *testing.T) {
	hygiene := []simulate.HygieneModule{{Module: "golang.org/x/text", Version: "v0.36.0", VulnIDs: []string{"GO-2026-5970"}}}
	scanResult := &scan.ScanResult{
		Vulnerabilities: []scan.Vulnerability{{ID: "GO-2026-5970", Module: "golang.org/x/text", Severity: "MEDIUM"}},
		SecurityBumps:   []scan.SecurityBump{{Name: "golang.org/x/text", CurrentVersion: "v0.30.0", FixedVersion: "v0.36.0", VulnIDs: []string{"GO-2026-5970"}}},
	}
	modroot := func(root string, existing []string) ModrootAnalysis {
		return ModrootAnalysis{Modroot: root, ScanResult: scanResult, ExistingDeps: existing,
			DesiredDeps: []string{"golang.org/x/text@v0.36.0", "example.com/sec@v1.1.0"}, HygieneModules: hygiene}
	}
	gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{{Language: "go",
		ByModroot: []ModrootAnalysis{modroot(".", nil), modroot("sub", nil), modroot("same", []string{"golang.org/x/text@v0.36.0"})}}}}

	recordHygieneBumps(gp, gp.VulnerabilityAnalysis.ByLanguage[0])
	require.Len(t, gp.HygieneBumps, 1)
	assert.Equal(t, SecurityFix{Module: "golang.org/x/text", Vulnerability: "GO-2026-5970", OldVersion: "v0.30.0", NewVersion: "v0.36.0", Severity: "MEDIUM"},
		gp.HygieneBumps[0])
	assert.Empty(t, gp.SecurityFixes)

	gp.MarkActualChangesApplied()
	result := gp.ToResult()
	assert.Equal(t, 1, result.HygieneModulesBumped)
	assert.Zero(t, result.ModulesBumped, "BUMPED stays security-only")
	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"hygiene_bumps":[{"module":"golang.org/x/text"`)
	assert.Contains(t, string(out), `"hygiene_modules_bumped":1`)

	empty, err := json.Marshal(NewProcessor("/t.yaml", "pkg", "1.0.0", 1).ToResult())
	require.NoError(t, err)
	assert.NotContains(t, string(empty), "hygiene", "no new keys without hygiene bumps")
}
