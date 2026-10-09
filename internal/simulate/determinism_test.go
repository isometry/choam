package simulate

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"
)

// Determinism: OSV spells the docker/distribution fix v2.8.2 while the
// YAML pin (and Go) spell it v2.8.2+incompatible. Semver calls them equal,
// so every merge of the two must collapse them into one rung spelled with
// the build metadata, whatever order they arrive in.

const shuffleRuns = 500

const dockerModule = "github.com/docker/distribution"

func dockerRungs() []Rung {
	return []Rung{
		{Version: "v2.8.2", VulnIDs: []string{"GHSA-hqxw-f8mx-cpmw"}, Severity: "HIGH"},
		{Version: "v2.8.2+incompatible"},
		{Version: "v2.8.1+incompatible"},
	}
}

var wantDockerRungs = []Rung{
	{Version: "v2.8.2+incompatible", VulnIDs: []string{"GHSA-hqxw-f8mx-cpmw"}, Severity: "HIGH"},
	{Version: "v2.8.1+incompatible"},
}

func shuffled[T any](rng *rand.Rand, in []T) []T {
	out := slices.Clone(in)
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func TestMergeRungs_EqualVersionsCollapseDeterministically(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for range shuffleRuns {
		in := shuffled(rng, dockerRungs())
		split := rng.IntN(len(in) + 1)
		got := mergeRungs(in[:split], in[split:])
		require.Equal(t, wantDockerRungs, got, "input %v", in)
	}
}

func TestFixRungs_EqualVersionsCollapseDeterministically(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	vulns := []scan.Vulnerability{
		{ID: "GHSA-hqxw-f8mx-cpmw", Module: dockerModule, FixedVersion: "v2.8.2", Severity: "HIGH"},
		{ID: "GO-OTHER", Module: "example.com/other", FixedVersion: "v1.0.0"},
	}
	for range shuffleRuns {
		also := shuffled(rng, []string{"v2.8.2+incompatible", "v2.8.1+incompatible"})
		got := FixRungs(shuffled(rng, vulns), dockerModule, nil, also...)
		require.Equal(t, wantDockerRungs, got, "also %v", also)
	}
}

func TestLadder_EqualRungMergedIntoTop(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	l := &loop{baselineResolved: map[string]string{dockerModule: "v2.8.0+incompatible"}}
	for range shuffleRuns {
		for _, version := range []string{"v2.8.2", "v2.8.2+incompatible"} {
			c := &candState{Candidate: Candidate{Module: dockerModule, Version: version, FromCVE: true,
				Rungs: shuffled(rng, dockerRungs())}}
			require.Equal(t, wantDockerRungs, l.ladder(c), "candidate version %s, rungs %v", version, c.Rungs)
		}
	}
}

func TestStepDown_LandsOnCanonicalRung(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	for range shuffleRuns {
		l := &loop{req: ModrootRequest{Baseline: map[string]string{dockerModule: "v2.8.0+incompatible"}}}
		rungs := append(shuffled(rng, dockerRungs()), Rung{Version: "v2.8.3+incompatible", VulnIDs: []string{"GO-NEWER"}})
		c := &candState{Candidate: Candidate{Module: dockerModule, Version: "v2.8.3+incompatible", FromCVE: true,
			VulnIDs: []string{"GHSA-hqxw-f8mx-cpmw", "GO-NEWER"}, Rungs: shuffled(rng, rungs)}}
		l.stepDown(t.Context(), c, "fix unresolvable")
		require.Equal(t, "v2.8.2+incompatible", c.Version)
		require.Equal(t, wantDockerRungs, c.Rungs)
		require.Equal(t, []string{"GHSA-hqxw-f8mx-cpmw"}, c.VulnIDs)
	}
}

func TestAddCandidate_EqualVersionPrefersBuildMetadata(t *testing.T) {
	for _, order := range [][2]string{{"v2.8.2", "v2.8.2+incompatible"}, {"v2.8.2+incompatible", "v2.8.2"}} {
		l := &loop{byModule: make(map[string]*candState)}
		l.addCandidate(Candidate{Module: dockerModule, Version: order[0]}, true)
		c := l.addCandidate(Candidate{Module: dockerModule, Version: order[1], FromCVE: true}, false)
		assert.Equal(t, "v2.8.2+incompatible", c.Version, "order %v", order)
		assert.Len(t, l.cands, 1)
	}
}

func TestCompareResiduals_TotalOrder(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 10))
	residuals := []Residual{
		{Module: "a", FixedVersion: "v1.1.0", VulnIDs: []string{"GO-2"}, Reason: "x"},
		{Module: "a", FixedVersion: "v1.1.0", VulnIDs: []string{"GO-1"}, Reason: "x"},
		{Module: "a", FixedVersion: "v1.0.0", VulnIDs: []string{"GO-3"}, Reason: "y"},
		{Module: "a", FixedVersion: "v1.1.0", VulnIDs: []string{"GO-1"}, Reason: "w"},
		{Module: "b", VulnIDs: []string{"GO-4"}, Reason: "no released fix"},
	}
	want := slices.Clone(residuals)
	slices.SortStableFunc(want, compareResiduals)
	for range shuffleRuns {
		got := shuffled(rng, residuals)
		slices.SortStableFunc(got, compareResiduals)
		require.Equal(t, want, got)
	}
}

// TestRunLoop_SecondPassMatches_GateRejectedPin is the jenkins-operator
// non-idempotency: an existing pin (k, no advisory) moves the graph so o's
// vulnerable package is unlinked and o's fix is shed; the compile gate then
// rejects k and o's code is linked again. The next run no longer carries the
// k pin, so it must already have been resolved the same way: both passes
// write o's fix and leave nothing residual.
func TestRunLoop_SecondPassMatches_GateRejectedPin(t *testing.T) {
	jws := scan.VulnerableImport{Path: "example.com/o/jws"}
	newTC := func() *fakeCompiler {
		return &fakeCompiler{
			fakeToolchain: &fakeToolchain{
				base: map[string]string{"example.com/k": "v1.0.0", "example.com/o": "v1.0.0"},
				linkedPkgsFn: func(applied map[string]string) []string {
					if semver.Compare(applied["example.com/k"], "v1.1.0") >= 0 {
						return []string{"example.com/k"}
					}
					return []string{"example.com/k", jws.Path}
				},
			},
			compileFn: brokenAbove("example.com/k", "v1.1.0"),
		}
	}
	sc := &fakeScanner{advisories: []fakeAdvisory{
		{module: "example.com/o", id: "GO-O", fixed: "v1.1.0", imports: []scan.VulnerableImport{jws}},
	}}
	oSeed := Candidate{Module: "example.com/o", Version: "v1.1.0", FromCVE: true, VulnIDs: []string{"GO-O"}}
	run := func(seeds []Candidate) *ModrootResult {
		result, err := RunLoop(t.Context(), newTC(), sc, newTestModuleDir(t), ModrootRequest{
			Modroot:     ".",
			Seeds:       seeds,
			VulnImports: map[string][]string{"GO-O": {jws.Path}},
			Baseline:    map[string]string{"example.com/k": "v1.0.0", "example.com/o": "v1.0.0"},
		}, Options{})
		require.NoError(t, err)
		return result
	}

	first := run([]Candidate{{Module: "example.com/k", Version: "v1.1.0"}, oSeed})
	second := run([]Candidate{oSeed})
	assert.Equal(t, []string{"example.com/o@v1.1.0"}, first.FinalDeps)
	assert.Equal(t, second.FinalDeps, first.FinalDeps)
	assert.Equal(t, second.Residuals, first.Residuals)
	assert.Empty(t, first.RemainingVulnIDs)
}

// TestRunLoop_UnsustainedPinStepsDownToFixRung is the jenkins-operator
// client_golang shape: the existing YAML pin (v1.23.0, the top rung) is
// reverted by the tidy, but the advisory's own fix (v1.11.0) is sustained.
// The candidate must step down to it - the outcome a run without the pin
// reaches - rather than be dropped with its advisory left residual.
func TestRunLoop_UnsustainedPinStepsDownToFixRung(t *testing.T) {
	tc := &fakeToolchain{
		base:   map[string]string{"example.com/c": "v1.0.0"},
		capped: map[string]string{"example.com/c": "v1.12.0"},
	}
	result, err := RunLoop(t.Context(), tc, &fakeScanner{}, newTestModuleDir(t), ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{{Module: "example.com/c", Version: "v1.23.0", FromCVE: true, VulnIDs: []string{"GO-C"},
			Rungs: []Rung{{Version: "v1.23.0"}, {Version: "v1.11.0", VulnIDs: []string{"GO-C"}}}}},
		Baseline: map[string]string{"example.com/c": "v1.0.0"},
	}, Options{})
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com/c@v1.11.0"}, result.FinalDeps)
	assert.Empty(t, result.Residuals)
}
