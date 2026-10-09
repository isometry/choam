package gobump

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSeedCandidates_EqualRungsDeterministic: the jenkins-operator shape.
// OSV spells the docker/distribution fix v2.8.2, the YAML pin is
// v2.8.2+incompatible: the seed's ladder must hold one rung for both,
// spelled +incompatible, whatever order the scan reported things in.
func TestSeedCandidates_EqualRungsDeterministic(t *testing.T) {
	const docker = "github.com/docker/distribution"
	vulns := []scan.Vulnerability{
		{ID: "GHSA-hqxw-f8mx-cpmw", Module: docker, FixedVersion: "v2.8.2", Severity: "HIGH"},
		{ID: "GO-2026-0001", Module: docker, FixedVersion: "v2.8.1+incompatible", Severity: "LOW"},
		{ID: "GO-2026-0002", Module: "golang.org/x/crypto", FixedVersion: "v0.56.0"},
	}
	want := []simulate.Rung{
		{Version: "v2.8.2+incompatible", VulnIDs: []string{"GHSA-hqxw-f8mx-cpmw"}, Severity: "HIGH"},
		{Version: "v2.8.1+incompatible", VulnIDs: []string{"GO-2026-0001"}, Severity: "LOW"},
	}
	rng := rand.New(rand.NewPCG(11, 12))
	for range 500 {
		shuffledVulns := slices.Clone(vulns)
		rng.Shuffle(len(shuffledVulns), func(i, j int) { shuffledVulns[i], shuffledVulns[j] = shuffledVulns[j], shuffledVulns[i] })
		seeds := seedCandidates(ModrootAnalysis{
			ExistingDeps: []string{docker + "@v2.8.2+incompatible"},
			DesiredDeps:  []string{docker + "@v2.8.2+incompatible"},
			ScanResult: &scan.ScanResult{
				Vulnerabilities: shuffledVulns,
				SecurityBumps: []scan.SecurityBump{{Name: docker, CurrentVersion: "v2.8.0+incompatible", FixedVersion: "v2.8.2",
					VulnIDs: []string{"GHSA-hqxw-f8mx-cpmw", "GO-2026-0001"}, Severity: "HIGH"}},
			},
		})
		require.Len(t, seeds, 1)
		require.Equal(t, "v2.8.2+incompatible", seeds[0].Version)
		require.Equal(t, want, seeds[0].Rungs)
	}
}

// TestApplyGoBumpChanges_SecondPassIsNoOp: re-running the applier on its own
// output with the same proven deps (in another order, as the next analysis
// would list them) changes nothing: haveDepsChanged is false, the YAML is
// byte-identical, and nothing triggers an epoch bump.
func TestApplyGoBumpChanges_SecondPassIsNoOp(t *testing.T) {
	const docker = "github.com/docker/distribution"
	pass := func(yamlContent string, existing, desired []string) *GoBumpProcessor {
		gp := newTestProcessor(t, yamlContent)
		analysis := &VulnerabilityAnalysis{
			ByLanguage: []LanguageAnalysis{{
				Language: "go",
				ByModroot: []ModrootAnalysis{{
					Modroot:             ".",
					ExistingDeps:        existing,
					DesiredDeps:         desired,
					Simulated:           true,
					SecurityBumpModules: []string{docker, "golang.org/x/crypto"},
				}},
			}},
			BumpActions: []BumpAction{{Action: "needs_bump", Language: "go", Modroots: []string{"."}}},
		}
		require.NoError(t, NewGoBumpApplier(nil).applyGoBumpChanges(t.Context(), gp, analysis))
		return gp
	}
	desired := []string{docker + "@v2.8.2+incompatible", "golang.org/x/crypto@v0.56.0"}

	first := pass(singleGoBumpYAML, []string{"golang.org/x/net@v0.55.0"}, desired)
	require.True(t, first.ActualChangesApplied)
	written := string(first.GetCurrentYAML())

	steps, err := newMelangeLoader().FindBumpSteps(first.GetCurrentYAML())
	require.NoError(t, err)
	require.Len(t, steps, 1)
	require.False(t, haveDepsChanged(steps[0].Deps, desired))

	second := pass(written, steps[0].Deps, []string{desired[1], desired[0]})
	assert.False(t, second.ActualChangesApplied, "second pass must not rewrite the step")
	assert.Empty(t, second.SecurityFixes, "nothing to credit, so no epoch bump")
	assert.Equal(t, written, string(second.GetCurrentYAML()))
}
