package gobump

import (
	"fmt"
	"strings"
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/ecosystem"
	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReconcileBumpSteps_JavaGrammar guards against a regression where
// newlyAddedDeps/recordSecurityFixes split on the FIRST "@" - which would
// mis-parse Maven's "groupId@artifactId@version" grammar (treating
// "artifactId@version" as the version). The general reconcile/coalesce
// machinery itself is grammar-blind; this only exercises the reporting path.
func TestReconcileBumpSteps_JavaGrammar(t *testing.T) {
	gp := newTestProcessor(t, noBumpStepYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "java",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:             ".",
					ExistingDeps:        nil,
					DesiredDeps:         []string{"io.netty@netty-codec-http@4.1.94.Final"},
					SecurityBumpModules: []string{"io.netty@netty-codec-http"},
					// Rendered coordinate -> OSV bump (colon-named), as
					// performAnalysis populates via Ecosystem.BumpCoords.
					SecurityBumpsByCoord: map[string]scan.SecurityBump{
						"io.netty@netty-codec-http": {
							Name:           "io.netty:netty-codec-http",
							Ecosystem:      "Maven",
							CurrentVersion: "4.1.90.Final",
							FixedVersion:   "4.1.94.Final",
							VulnIDs:        []string{"GHSA-xxxx-yyyy"},
							Severity:       "HIGH",
						},
					},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Language: "java", Modroots: []string{"."}}},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "java", steps[0].Language)
	assert.Equal(t, []string{"io.netty@netty-codec-http@4.1.94.Final"}, steps[0].Deps)

	require.Len(t, gp.SecurityFixes, 1)
	assert.Equal(t, "io.netty@netty-codec-http", gp.SecurityFixes[0].Module)
	assert.Equal(t, "4.1.94.Final", gp.SecurityFixes[0].NewVersion)
	// Advisory attribution must flow from SecurityBumpsByCoord, not fall
	// back to the "security vulnerability"/"vulnerable" placeholders (the
	// OSV colon-format name can never match the rendered coordinate).
	assert.Equal(t, "GHSA-xxxx-yyyy", gp.SecurityFixes[0].Vulnerability)
	assert.Equal(t, "4.1.90.Final", gp.SecurityFixes[0].OldVersion)
	// The scan bump's severity is reported, not a placeholder.
	assert.Equal(t, "HIGH", gp.SecurityFixes[0].Severity)
}

func TestCoalesceModroots(t *testing.T) {
	byModroot := []ModrootAnalysis{
		{Modroot: "cmd/a", DesiredDeps: []string{"a@v1", "b@v1"}},
		{Modroot: "cmd/c", DesiredDeps: []string{"a@v1", "b@v1"}}, // same set as cmd/a, different root order
		{Modroot: ".", DesiredDeps: []string{"a@v1", "b@v1", "c@v1"}},
		{Modroot: "cmd/empty", DesiredDeps: nil}, // no bump needed - omitted
	}

	groups := coalesceModroots(byModroot)
	require.Len(t, groups, 2)

	assert.Equal(t, []string{"cmd/a", "cmd/c"}, groups[0].Modroots)
	assert.Equal(t, []string{"a@v1", "b@v1"}, groups[0].Deps)

	assert.Equal(t, []string{"."}, groups[1].Modroots)
	assert.Equal(t, []string{"a@v1", "b@v1", "c@v1"}, groups[1].Deps)
}

func TestSameRootSet(t *testing.T) {
	assert.True(t, sameRootSet([]string{"a", "b", "c"}, []string{"c", "a", "b"}))
	assert.False(t, sameRootSet([]string{"a", "b"}, []string{"a", "b", "c"}))
}

// TestReconcileBumpSteps_FastPathUpdatesInPlace covers the common case: a
// single go/bump step whose one modroot's deps changed. The step's action
// and modroot are left untouched; only deps are rewritten.
func TestReconcileBumpSteps_FastPathUpdatesInPlace(t *testing.T) {
	gp := newTestProcessor(t, singleGoBumpYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:             ".",
					ExistingDeps:        []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:         []string{"golang.org/x/net@v0.56.0"},
					SecurityBumpModules: []string{"golang.org/x/net"},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)
	assert.True(t, gp.ActualChangesApplied)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "go/bump", steps[0].Action) // action preserved
	assert.Equal(t, []string{"."}, steps[0].Modroots)
	assert.Equal(t, []string{"golang.org/x/net@v0.56.0"}, steps[0].Deps)

	require.Len(t, gp.SecurityFixes, 1)
	assert.Equal(t, "golang.org/x/net", gp.SecurityFixes[0].Module)
}

// TestReconcileBumpSteps_CoUpdateNotCreditedAsSecurityFix is an end-to-end
// version of TestAddedAcrossRoots_ExcludesCoherenceOnlyCoUpdates: a modroot
// whose DesiredDeps include both a genuine OSV fix and a coherence-only
// co-update sibling writes both deps to the bump step, but gp.SecurityFixes
// only credits the genuine fix.
func TestReconcileBumpSteps_CoUpdateNotCreditedAsSecurityFix(t *testing.T) {
	gp := newTestProcessor(t, singleGoBumpYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:      ".",
					ExistingDeps: []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:  []string{"golang.org/x/net@v0.56.0", "github.com/co-updated/sibling@v1.2.0"},
					// Only x/net was OSV-flagged; the sibling was folded in
					// purely by Go's co-update discovery.
					SecurityBumpModules: []string{"golang.org/x/net"},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.ElementsMatch(t, []string{"golang.org/x/net@v0.56.0", "github.com/co-updated/sibling@v1.2.0"}, steps[0].Deps)

	// Both deps were written, but only the genuine CVE fix is credited.
	require.Len(t, gp.SecurityFixes, 1)
	assert.Equal(t, "golang.org/x/net", gp.SecurityFixes[0].Module)
}

// TestReconcileBumpSteps_DivergentRootsSplitInPlace covers the cert-manager
// case: modroots whose desired dependency sets diverge must end up in
// separate steps rather than being merged into one (which would let omnibump
// inject a dependency into a modroot that never had it). Existing steps are
// edited in place and never merged: each root belongs to the first step
// covering it, a step whose own roots diverge is split into copies of itself
// directly after it, and a root shared with a later step leaves that step.
func TestReconcileBumpSteps_DivergentRootsSplitInPlace(t *testing.T) {
	gp := newTestProcessor(t, certManagerLikeYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{Modroot: "cmd/a", ExistingDeps: []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0"},
					DesiredDeps: []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.56.0"}},
				{Modroot: "test/e2e", ExistingDeps: []string{"github.com/foo/baz@v2.2.2", "golang.org/x/net@v0.55.0"},
					DesiredDeps: []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.56.0"}},
				// cmd/b and "." genuinely need the fuller set (they depend on baz too).
				{Modroot: "cmd/b", ExistingDeps: []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0", "github.com/foo/baz@v2.2.2"},
					DesiredDeps: []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.56.0", "github.com/foo/baz@v2.2.2"}},
				{Modroot: ".", ExistingDeps: []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0", "github.com/foo/baz@v2.2.2"},
					DesiredDeps: []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.56.0", "github.com/foo/baz@v2.2.2"}},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"cmd/a"}}}, // non-empty is all that matters here
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)
	assert.True(t, gp.ActualChangesApplied)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 3)

	// Step 1 keeps its action and position, now covering only cmd/a; its
	// copy follows it for the fuller set; step 2 keeps only test/e2e.
	assert.Equal(t, "go/bump", steps[0].Action)
	assert.Equal(t, []string{"cmd/a"}, steps[0].Modroots)
	assert.Equal(t, []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.56.0"}, steps[0].Deps)

	assert.Equal(t, "go/bump", steps[1].Action)
	assert.Equal(t, []string{"cmd/b", "."}, steps[1].Modroots)
	assert.Equal(t, []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.56.0", "github.com/foo/baz@v2.2.2"}, steps[1].Deps)

	assert.Equal(t, "bump", steps[2].Action)
	assert.Equal(t, []string{"test/e2e"}, steps[2].Modroots)
	assert.Equal(t, []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.56.0"}, steps[2].Deps)
}

// TestReconcileBumpSteps_InsertsWhenNoStepExists covers a plain Go project
// with a go/build step but no bump step yet.
func TestReconcileBumpSteps_InsertsWhenNoStepExists(t *testing.T) {
	gp := newTestProcessor(t, noBumpStepYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{Modroot: ".", ExistingDeps: nil, DesiredDeps: []string{"golang.org/x/net@v0.56.0"}},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)
	assert.True(t, gp.ActualChangesApplied)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "bump", steps[0].Action)
	assert.Equal(t, []string{"."}, steps[0].Modroots)
	assert.Equal(t, []string{"golang.org/x/net@v0.56.0"}, steps[0].Deps)
	assert.NotContains(t, string(gp.GetCurrentYAML()), "modroot") // single "." root omits the field
}

// TestReconcileBumpSteps_MultiLanguageIndependence covers a package with two
// languages: each gets its own step(s) in its own grammar, and reconciling
// one language never disturbs the other's existing step.
func TestReconcileBumpSteps_MultiLanguageIndependence(t *testing.T) {
	const multiLangYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: bump
    with:
      language: rust
      deps: |-
        serde@1.0.100
`
	gp := newTestProcessor(t, multiLangYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{
			{
				Language: "go",
				ByModroot: []ModrootAnalysis{
					{Modroot: ".", ExistingDeps: nil, DesiredDeps: []string{"golang.org/x/net@v0.56.0"}},
				},
			},
			{
				Language: "rust",
				ByModroot: []ModrootAnalysis{
					{Modroot: ".", ExistingDeps: []string{"serde@1.0.100"}, DesiredDeps: []string{"serde@1.0.200"}},
				},
			},
		},
		BumpActions: []BumpAction{
			{Action: "needs_bump", Language: "go", Modroots: []string{"."}},
			{Action: "needs_bump", Language: "rust", Modroots: []string{"."}},
		},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 2)

	byLang := make(map[string]config.BumpStep, len(steps))
	for _, step := range steps {
		byLang[step.Language] = step
	}

	require.Contains(t, byLang, "go")
	assert.Equal(t, []string{"golang.org/x/net@v0.56.0"}, byLang["go"].Deps)

	require.Contains(t, byLang, "rust")
	assert.Equal(t, "bump", byLang["rust"].Action) // the existing rust step's deps updated in place
	assert.Equal(t, []string{"serde@1.0.200"}, byLang["rust"].Deps)
}

func TestReconcileBumpSteps_FastPathWritesReplaces(t *testing.T) {
	gp := newTestProcessor(t, singleGoBumpYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:             ".",
					ExistingDeps:        []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:         []string{"golang.org/x/net@v0.56.0"},
					DesiredReplaces:     []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"},
					SecurityBumpModules: []string{"golang.org/x/net", "github.com/aws/aws-sdk-go"},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "go/bump", steps[0].Action) // edited in place
	assert.Equal(t, []string{"golang.org/x/net@v0.56.0"}, steps[0].Deps)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, steps[0].Replaces)

	// A promoted replace that fixes a CVE is credited as a security fix.
	modules := make([]string, 0, len(gp.SecurityFixes))
	for _, fix := range gp.SecurityFixes {
		modules = append(modules, fix.Module)
	}
	assert.Contains(t, modules, "github.com/aws/aws-sdk-go")
}

func TestReconcileBumpSteps_NewStepsCoalesceByReplaces(t *testing.T) {
	// Two roots no step covers, with identical deps but divergent replaces,
	// must land in separate new steps; the existing step (covering a root
	// that was not analyzed) is left exactly as it was.
	gp := newTestProcessor(t, singleGoBumpYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:         "cmd/a",
					DesiredDeps:     []string{"golang.org/x/net@v0.56.0"},
					DesiredReplaces: []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"},
				},
				{
					Modroot:     "cmd/b",
					DesiredDeps: []string{"golang.org/x/net@v0.56.0"},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"cmd/a", "cmd/b"}}},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(string(gp.GetCurrentYAML()), singleGoBumpYAML[strings.Index(singleGoBumpYAML, "  - uses: go/build"):]),
		"the existing steps are untouched")

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 3)

	byRoot := make(map[string]config.BumpStep)
	for _, step := range steps {
		for _, root := range step.Modroots {
			byRoot[root] = step
		}
	}
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, byRoot["cmd/a"].Replaces)
	assert.Empty(t, byRoot["cmd/b"].Replaces)
	assert.NotEqual(t, byRoot["cmd/a"].Index, byRoot["cmd/b"].Index)
	assert.Equal(t, []string{"golang.org/x/net@v0.55.0"}, byRoot["."].Deps)
}

// TestReconcileBumpSteps_PreservesBlankLineConvention: every step choam adds
// - a split copy or a new step - follows the file's blank-line convention.
// Step 1 splits three ways (cmd/a, cmd/b and the unanalyzed "." which keeps
// its existing deps); step 2 keeps test/e2e.
func TestReconcileBumpSteps_PreservesBlankLineConvention(t *testing.T) {
	gp := newTestProcessor(t, certManagerLikeYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{Modroot: "cmd/a", ExistingDeps: []string{"github.com/foo/bar@v1.1.1"},
					DesiredDeps: []string{"github.com/foo/bar@v1.2.0"}},
				{Modroot: "cmd/b", ExistingDeps: []string{"github.com/foo/bar@v1.1.1"},
					DesiredDeps: []string{"github.com/foo/bar@v1.2.0", "golang.org/x/net@v0.56.0"}},
				{Modroot: "test/e2e", ExistingDeps: []string{"github.com/foo/baz@v2.2.2"},
					DesiredDeps: []string{"github.com/foo/baz@v2.3.0"}},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"cmd/a", "cmd/b", "test/e2e"}}},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 4)
	assert.Equal(t, []string{"cmd/a"}, steps[0].Modroots)
	assert.Equal(t, []string{"cmd/b"}, steps[1].Modroots)
	assert.Equal(t, []string{"."}, steps[2].Modroots)
	assert.Equal(t, []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0"}, steps[2].Deps, "an unanalyzed root keeps its deps")
	assert.Equal(t, []string{"test/e2e"}, steps[3].Modroots)

	lines := strings.Split(string(gp.GetCurrentYAML()), "\n")
	bumpSteps := 0
	for i, line := range lines {
		if strings.HasPrefix(line, "  - uses: bump") || strings.HasPrefix(line, "  - uses: go/bump") {
			bumpSteps++
			require.Greater(t, i, 0)
			assert.Equal(t, "", strings.TrimSpace(lines[i-1]),
				"bump step at line %d must be preceded by a blank line", i+1)
		}
	}
	assert.Equal(t, 4, bumpSteps)
}

// TestCoalesceModroots_IgnoresGoVersion: freshly written steps are
// `uses: bump`, which has no go-version input, so divergent go-versions never
// split a group.
func TestCoalesceModroots_IgnoresGoVersion(t *testing.T) {
	byModroot := []ModrootAnalysis{
		{Modroot: "cmd/a", DesiredDeps: []string{"a@v1"}, RequiredGoVersion: "1.26"},
		{Modroot: "cmd/b", DesiredDeps: []string{"a@v1"}},
		{Modroot: "cmd/c", DesiredDeps: []string{"a@v1"}, ExistingGoVersion: "1.26"},
	}

	groups := coalesceModroots(byModroot)
	require.Len(t, groups, 1)
	assert.Equal(t, []string{"cmd/a", "cmd/b", "cmd/c"}, groups[0].Modroots)
}

// TestReconcileBumpSteps_BumpStepNeverCarriesGoVersion: a `uses: bump` step
// (whose pipeline has no go-version input) never gains go-version from a
// required Go raise, and a stale one is removed when choam rewrites the step;
// a go/bump step keeps today's behaviour (see the FastPath* tests).
func TestReconcileBumpSteps_BumpStepNeverCarriesGoVersion(t *testing.T) {
	const bumpYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  # keep me
  - uses: bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
%s`
	for name, goVersionLine := range map[string]string{"absent": "", "stale": "      go-version: \"1.24\"\n"} {
		t.Run(name, func(t *testing.T) {
			gp := newTestProcessor(t, fmt.Sprintf(bumpYAML, goVersionLine))
			loader := config.NewLoader()
			steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
			require.NoError(t, err)
			analysis := &VulnerabilityAnalysis{
				ByLanguage: []LanguageAnalysis{{
					Language: "go",
					ByModroot: []ModrootAnalysis{{
						Modroot:           ".",
						ExistingDeps:      []string{"golang.org/x/net@v0.55.0"},
						DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
						ExistingGoVersion: existingGoVersionsForModroots([]string{"."}, steps)["."],
						RequiredGoVersion: "1.26",
					}},
				}},
				BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
			}

			require.NoError(t, NewGoBumpApplier(nil).reconcileBumpSteps(t.Context(), gp, analysis, loader))

			content := string(gp.GetCurrentYAML())
			assert.Contains(t, content, "golang.org/x/net@v0.56.0")
			assert.Contains(t, content, "# keep me", "the step is edited in place")
			assert.NotContains(t, content, "go-version")
		})
	}
}

// TestReconcileBumpSteps_FastPathEmitsGoVersion: the in-place edit upserts
// go-version into the existing step when the analysis demands a raise, and
// re-running the applier on the already-updated YAML is byte-stable.
func TestReconcileBumpSteps_FastPathEmitsGoVersion(t *testing.T) {
	gp := newTestProcessor(t, singleGoBumpYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:             ".",
					ExistingDeps:        []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:         []string{"golang.org/x/net@v0.56.0"},
					RequiredGoVersion:   "1.26",
					SecurityBumpModules: []string{"golang.org/x/net"},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
	}

	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, analysis, loader))

	firstPass := string(gp.GetCurrentYAML())
	assert.Contains(t, firstPass, `go-version: "1.26"`)

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "go/bump", steps[0].Action, "the step is edited in place")
	assert.Equal(t, "1.26", steps[0].GoVersion)

	// Second run, as a real re-run would see it: existing deps/go-version now
	// come from the updated YAML, the analysis still computes the same
	// requirement. Must be a byte-for-byte no-op.
	secondAnalysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:             ".",
					ExistingDeps:        []string{"golang.org/x/net@v0.56.0"},
					DesiredDeps:         []string{"golang.org/x/net@v0.56.0"},
					ExistingGoVersion:   existingGoVersionsForModroots([]string{"."}, steps)["."],
					RequiredGoVersion:   "1.26",
					SecurityBumpModules: []string{"golang.org/x/net"},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
	}
	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, secondAnalysis, loader))
	assert.Equal(t, firstPass, string(gp.GetCurrentYAML()), "double-running the applier must be byte-stable")
}

// TestReconcileBumpSteps_NeverLowersGoVersion: an existing step's go-version
// above the computed requirement is kept, byte-for-byte.
func TestReconcileBumpSteps_NeverLowersGoVersion(t *testing.T) {
	const pinnedGoVersionYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      go-version: "1.26"
`
	gp := newTestProcessor(t, pinnedGoVersionYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:           ".",
					ExistingDeps:      []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					ExistingGoVersion: "1.26",
					RequiredGoVersion: "1.25", // computed LOWER than the existing value
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
	}

	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, analysis, loader))

	content := string(gp.GetCurrentYAML())
	assert.Contains(t, content, `go-version: "1.26"`)
	assert.NotContains(t, content, "1.25")

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "1.26", steps[0].GoVersion)
}

// TestReconcileBumpSteps_FastPathDivergentGoVersionsWriteMax: divergent
// per-root effective go-versions must NOT split the step - go-version is a
// floor, so the in-place edit writes the max across all covered roots into
// the single existing step in place, preserving its comments. Falling back
// to rebuild here would destroy user comments, violating the
// comment-preservation invariant.
func TestReconcileBumpSteps_FastPathDivergentGoVersionsWriteMax(t *testing.T) {
	const divergentGoVersionYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  # keep me
  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      modroot: |-
        .
        cmd/a
`
	gp := newTestProcessor(t, divergentGoVersionYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:           ".",
					ExistingDeps:      []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					RequiredGoVersion: "1.24",
				},
				{
					Modroot:           "cmd/a",
					ExistingDeps:      []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					RequiredGoVersion: "1.26",
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{".", "cmd/a"}}},
	}

	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, analysis, loader))

	firstPass := string(gp.GetCurrentYAML())
	assert.Contains(t, firstPass, `go-version: "1.26"`, "single step must satisfy the most demanding root")
	assert.Contains(t, firstPass, "# keep me", "the in-place edit must preserve comments")

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1, "must stay a single step, not split by divergent go-version")
	assert.Equal(t, "go/bump", steps[0].Action)
	assert.ElementsMatch(t, []string{".", "cmd/a"}, steps[0].Modroots)
	assert.Equal(t, "1.26", steps[0].GoVersion)

	// Second run, as a real re-run would see it: ExistingGoVersion now comes
	// from the just-written max, so fastPathGoVersion returns "" for both
	// roots. Must be byte-for-byte stable.
	secondAnalysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:           ".",
					ExistingDeps:      []string{"golang.org/x/net@v0.56.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					ExistingGoVersion: existingGoVersionsForModroots([]string{"."}, steps)["."],
					RequiredGoVersion: "1.24",
				},
				{
					Modroot:           "cmd/a",
					ExistingDeps:      []string{"golang.org/x/net@v0.56.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					ExistingGoVersion: existingGoVersionsForModroots([]string{"cmd/a"}, steps)["cmd/a"],
					RequiredGoVersion: "1.26",
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{".", "cmd/a"}}},
	}
	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, secondAnalysis, loader))
	assert.Equal(t, firstPass, string(gp.GetCurrentYAML()), "re-running on divergent-go-version roots must be byte-stable")
}

// TestReconcileBumpSteps_FastPathDivergentGoVersionsNeverLowers: even with
// diverging per-root effective go-versions, an existing step's go-version
// above the computed maximum is kept, byte-for-byte - maxEffectiveGoVersion
// feeds fastPathGoVersion, which never lowers an existing value.
func TestReconcileBumpSteps_FastPathDivergentGoVersionsNeverLowers(t *testing.T) {
	const pinnedDivergentGoVersionYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      modroot: |-
        .
        cmd/a
      go-version: "1.27"
`
	gp := newTestProcessor(t, pinnedDivergentGoVersionYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:           ".",
					ExistingDeps:      []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					ExistingGoVersion: "1.27",
					RequiredGoVersion: "1.24",
				},
				{
					Modroot:           "cmd/a",
					ExistingDeps:      []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					RequiredGoVersion: "1.26",
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{".", "cmd/a"}}},
	}

	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, analysis, loader))

	content := string(gp.GetCurrentYAML())
	assert.Contains(t, content, `go-version: "1.27"`)
	assert.NotContains(t, content, "1.26")

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "1.27", steps[0].GoVersion)
}

// TestReconcileBumpSteps_TemplatedGoVersionWarnedNotRewritten: a step whose
// go-version is a template expression is never overwritten - the analysis
// requirement is surfaced as a message instead.
func TestReconcileBumpSteps_TemplatedGoVersionWarnedNotRewritten(t *testing.T) {
	const templatedGoVersionYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      go-version: ${{vars.go-version}}
`
	gp := newTestProcessor(t, templatedGoVersionYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:           ".",
					ExistingDeps:      []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					RequiredGoVersion: "1.26",
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"."}}},
	}

	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, analysis, loader))

	content := string(gp.GetCurrentYAML())
	assert.Contains(t, content, "go-version: ${{vars.go-version}}", "templated value must survive untouched")
	assert.NotContains(t, content, `go-version: "1.26"`)

	var warned bool
	for _, msg := range gp.GetMessages() {
		if strings.Contains(msg, "not a plain version") {
			warned = true
		}
	}
	assert.True(t, warned, "expected a templated-go-version warning, got %v", gp.GetMessages())
}

// TestReconcileBumpSteps_SeparateStepsEditedInPlace: two existing go/bump
// steps whose roots end up wanting identical deps are NOT merged; each is
// edited in place and keeps its own options (here a templated go-version,
// which a go/bump step that is not migrated keeps untouched).
func TestReconcileBumpSteps_SeparateStepsEditedInPlace(t *testing.T) {
	const twoStepsYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      modroot: |-
        cmd/a
      go-version: ${{vars.go-ver}}

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      modroot: |-
        cmd/b
`
	gp := newTestProcessor(t, twoStepsYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{Modroot: "cmd/a", DesiredDeps: []string{"golang.org/x/net@v0.56.0"}},
				{Modroot: "cmd/b", DesiredDeps: []string{"golang.org/x/net@v0.56.0"}},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"cmd/a", "cmd/b"}}},
	}

	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, analysis, loader))

	assert.Equal(t, strings.ReplaceAll(twoStepsYAML, "v0.55.0", "v0.56.0"), string(gp.GetCurrentYAML()))
}

// TestReconcileBumpSteps_GeneralPathNeverWritesGoVersion: two roots wanting
// the same deps share one fresh `uses: bump` step whatever their effective
// go-versions - that pipeline has no go-version input.
func TestReconcileBumpSteps_GeneralPathNeverWritesGoVersion(t *testing.T) {
	gp := newTestProcessor(t, noBumpStepYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{Modroot: "cmd/a", DesiredDeps: []string{"golang.org/x/net@v0.56.0"}, RequiredGoVersion: "1.26"},
				{Modroot: "cmd/b", DesiredDeps: []string{"golang.org/x/net@v0.56.0"}},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"cmd/a", "cmd/b"}}},
	}

	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, analysis, loader))

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.ElementsMatch(t, []string{"cmd/a", "cmd/b"}, steps[0].Modroots)
	assert.Equal(t, "", steps[0].GoVersion)
	assert.NotContains(t, string(gp.GetCurrentYAML()), "go-version")

	// Second run, as a re-run would see it: nothing changes - must be
	// byte-stable.
	firstPass := string(gp.GetCurrentYAML())
	secondAnalysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:           "cmd/a",
					ExistingDeps:      []string{"golang.org/x/net@v0.56.0"},
					DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
					ExistingGoVersion: existingGoVersionsForModroots([]string{"cmd/a"}, steps)["cmd/a"],
					RequiredGoVersion: "1.26",
				},
				{
					Modroot:      "cmd/b",
					ExistingDeps: []string{"golang.org/x/net@v0.56.0"},
					DesiredDeps:  []string{"golang.org/x/net@v0.56.0"},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"cmd/a", "cmd/b"}}},
	}
	require.NoError(t, applier.reconcileBumpSteps(t.Context(), gp, secondAnalysis, loader))
	assert.Equal(t, firstPass, string(gp.GetCurrentYAML()), "re-running must be byte-stable")
}

// TestApplyGoBumpChanges_GoVersionAndPinWiring: the full apply-phase wiring
// in one pass - a simulated modroot with a required Go raise updates its bump
// step's deps, upserts go-version, and raises the file's too-old go-package
// pin, all in the same apply phase (fallback, applier, pin stage).
func TestApplyGoBumpChanges_GoVersionAndPinWiring(t *testing.T) {
	const wiringYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/build
    with:
      go-package: go-1.22
      packages: ./cmd/app

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
`
	gp := newTestProcessor(t, wiringYAML)
	gp.Config = &melange.Configuration{}

	deps, err := golangDeps(t, "module example.com/app\n\ngo 1.22\n")
	require.NoError(t, err)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{
					Modroot:             ".",
					Deps:                deps,
					ExistingDeps:        []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps:         []string{"golang.org/x/net@v0.56.0"},
					RequiredGoVersion:   "1.26",
					Simulated:           true,
					SecurityBumpModules: []string{"golang.org/x/net"},
				},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Language: "go", Modroots: []string{"."}}},
	}

	require.NoError(t, runApplyPhase(t, gp, analysis))

	content := string(gp.GetCurrentYAML())
	assert.Contains(t, content, "golang.org/x/net@v0.56.0")
	assert.Contains(t, content, `go-version: "1.26"`)
	assert.Contains(t, content, "go-package: go-1.26", "pin floor = max(baseline 1.22, required 1.26)")
	assert.NotContains(t, content, "go-1.22")
	assert.True(t, gp.ActualChangesApplied)
}

// golangDeps parses a go.mod through the golang ecosystem, for analyses that
// need a pristine modfile behind ModrootAnalysis.Deps.
func golangDeps(t *testing.T, goMod string) (*ecosystem.ModuleDeps, error) {
	t.Helper()
	return ecogolang.New().Analyze(t.Context(), map[string][]byte{"go.mod": []byte(goMod)})
}

// TestReconcileBumpSteps_CompactFileStaysCompact: a melange file without the
// blank-line convention must not gain blank lines through reconciliation.
func TestReconcileBumpSteps_CompactFileStaysCompact(t *testing.T) {
	compactYAML := `package:
  name: example
  version: "1.0.0"
  epoch: 0
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}
  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      modroot: |-
        cmd/a
        cmd/b
`
	gp := newTestProcessor(t, compactYAML)
	loader := config.NewLoader()
	applier := NewGoBumpApplier(nil)

	analysis := &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{Modroot: "cmd/a", ExistingDeps: []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps: []string{"golang.org/x/net@v0.56.0"}},
				{Modroot: "cmd/b", ExistingDeps: []string{"golang.org/x/net@v0.55.0"},
					DesiredDeps: []string{"golang.org/x/net@v0.56.0", "github.com/foo/bar@v1.0.0"}},
			},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Modroots: []string{"cmd/a", "cmd/b"}}},
	}

	err := applier.reconcileBumpSteps(t.Context(), gp, analysis, loader)
	require.NoError(t, err)

	content := string(gp.GetCurrentYAML())
	pipelinePart := content[strings.Index(content, "pipeline:"):]
	assert.NotContains(t, pipelinePart, "\n\n", "compact pipeline must not gain blank lines")

	steps, err := loader.FindBumpSteps(gp.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 2)
}
