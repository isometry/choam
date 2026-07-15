package gobump

import (
	"context"
	"errors"
	"strings"
	"testing"

	omnibumpgolang "github.com/chainguard-dev/omnibump/pkg/languages/golang"
	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

type fakeBumpSimulator struct {
	results  map[string]*simulate.ModrootResult
	err      error
	gotReqs  []simulate.ModrootRequest
	gotRepo  string
	gotTag   string
	gotSHA   string
	simCalls int
}

func (f *fakeBumpSimulator) Simulate(_ context.Context, repoURL, tag, expectedCommit string, reqs []simulate.ModrootRequest) (map[string]*simulate.ModrootResult, error) {
	f.simCalls++
	f.gotRepo, f.gotTag, f.gotSHA = repoURL, tag, expectedCommit
	f.gotReqs = reqs
	if f.err != nil {
		return nil, f.err
	}
	return f.results, nil
}

func newSimulationProcessor() *GoBumpProcessor {
	gp := NewGoBumpProcessor("/tmp/test.yaml", "test-package", "1.0.0", 1)
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{
		RepoURL:        "https://github.com/example/repo",
		Tag:            "v1.0.0",
		ExpectedCommit: "abc123",
		ByLanguage: []LanguageAnalysis{
			{
				Language: "go",
				ByModroot: []ModrootAnalysis{
					{
						Modroot:       ".",
						BuildPackages: []string{"./cmd/app"},
						ExistingDeps:  []string{"example.com/old@v1.0.0"},
						DesiredDeps:   []string{"example.com/old@v1.2.0", "example.com/pin@v0.9.0"},
						ScanResult: &scan.ScanResult{
							Vulnerabilities: []scan.Vulnerability{
								{ID: "GO-OLD-1", Module: "example.com/old", Ecosystem: "Go", CurrentVersion: "v1.0.0", FixedVersion: "v1.2.0"},
							},
							SecurityBumps: []scan.SecurityBump{
								{Name: "example.com/old", Ecosystem: "Go", CurrentVersion: "v1.0.0", FixedVersion: "v1.2.0", VulnIDs: []string{"GO-OLD-1"}},
							},
						},
						SecurityBumpModules: []string{"example.com/old"},
					},
				},
			},
		},
		VulnerabilitiesFound: 2,
		BumpActions: []BumpAction{
			{Action: "needs_bump", Language: "go", Modroots: []string{"."}, Dependencies: []string{"example.com/old@v1.2.0"}},
		},
	}
	return gp
}

func newStageWithFake(fake *fakeBumpSimulator) *SimulationStage {
	stage := NewSimulationStage(nil, ProcessorOptions{Validate: true})
	stage.newSimulator = func(ProcessorOptions, *Analyzer) (bumpSimulator, error) {
		return fake, nil
	}
	return stage
}

func TestSimulationStage_RewritesDesiredDeps(t *testing.T) {
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot:          ".",
				FinalDeps:        []string{"example.com/old@v1.3.0"},
				CVEBackedModules: []string{"example.com/old"},
				Converged:        true,
				Iterations:       2,
				Residuals: []simulate.Residual{
					{Module: "example.com/nofix", Reason: "no released fix", VulnIDs: []string{"GO-NOFIX-1"}},
				},
				Dropped: []simulate.DroppedCandidate{
					{Module: "example.com/pin", Version: "v0.9.0", Reason: "redundant: module graph resolves identically without it"},
				},
			},
		},
	}
	stage := newStageWithFake(fake)
	gp := newSimulationProcessor()

	shouldRun, err := stage.ShouldRun(t.Context(), gp)
	require.NoError(t, err)
	require.True(t, shouldRun)

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.Equal(t, "https://github.com/example/repo", fake.gotRepo)
	assert.Equal(t, "v1.0.0", fake.gotTag)
	assert.Equal(t, "abc123", fake.gotSHA)

	// Seeds must carry CVE provenance from the scan result.
	require.Len(t, fake.gotReqs, 1)
	assert.Equal(t, []string{"./cmd/app"}, fake.gotReqs[0].Packages, "build packages must thread into the simulation request")
	assert.Equal(t, map[string]struct{}{"GO-OLD-1": {}}, fake.gotReqs[0].BaselineVulnIDs,
		"baseline advisory IDs must thread into the simulation request")
	seeds := fake.gotReqs[0].Seeds
	require.Len(t, seeds, 2)
	assert.Equal(t, simulate.Candidate{Module: "example.com/old", Version: "v1.2.0", FromCVE: true, VulnIDs: []string{"GO-OLD-1"}}, seeds[0])
	assert.Equal(t, simulate.Candidate{Module: "example.com/pin", Version: "v0.9.0"}, seeds[1])

	modroot := gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
	assert.Equal(t, []string{"example.com/old@v1.3.0"}, modroot.DesiredDeps)
	assert.Equal(t, []string{"example.com/old"}, modroot.SecurityBumpModules)
	assert.True(t, modroot.Simulated)
	assert.True(t, modroot.SimulationConverged)

	// Actions rebuilt from the validated deps.
	require.Len(t, gp.VulnerabilityAnalysis.BumpActions, 1)
	assert.Equal(t, []string{"example.com/old@v1.3.0"}, gp.VulnerabilityAnalysis.BumpActions[0].Dependencies)

	assert.True(t, gp.Validated)
	require.Len(t, gp.Residuals, 1)
	assert.Equal(t, "example.com/nofix", gp.Residuals[0].Module)
}

func TestSimulationStage_DegradesOnSimulatorError(t *testing.T) {
	fake := &fakeBumpSimulator{err: errors.New("clone failed")}
	stage := newStageWithFake(fake)
	gp := newSimulationProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.False(t, gp.Validated)
	// Pre-simulation candidates pass through untouched.
	modroot := gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
	assert.Equal(t, []string{"example.com/old@v1.2.0", "example.com/pin@v0.9.0"}, modroot.DesiredDeps)
	assert.False(t, modroot.Simulated)
	require.NotEmpty(t, gp.Messages)
	assert.Contains(t, gp.Messages[len(gp.Messages)-1], "NOT validated")
}

func TestSimulationStage_DegradesWhenToolchainMissing(t *testing.T) {
	stage := NewSimulationStage(nil, ProcessorOptions{Validate: true})
	stage.newSimulator = func(ProcessorOptions, *Analyzer) (bumpSimulator, error) {
		return nil, errors.New("go toolchain not found in PATH")
	}
	gp := newSimulationProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))
	assert.False(t, gp.Validated)
}

func TestSimulationStage_ShouldRunGates(t *testing.T) {
	fake := &fakeBumpSimulator{}

	t.Run("disabled by options", func(t *testing.T) {
		stage := NewSimulationStage(nil, ProcessorOptions{Validate: false})
		gp := newSimulationProcessor()
		shouldRun, err := stage.ShouldRun(t.Context(), gp)
		require.NoError(t, err)
		assert.False(t, shouldRun)
	})

	t.Run("no repo coordinates", func(t *testing.T) {
		stage := newStageWithFake(fake)
		gp := newSimulationProcessor()
		gp.VulnerabilityAnalysis.RepoURL = ""
		shouldRun, err := stage.ShouldRun(t.Context(), gp)
		require.NoError(t, err)
		assert.False(t, shouldRun)
	})

	t.Run("no go actions", func(t *testing.T) {
		stage := newStageWithFake(fake)
		gp := newSimulationProcessor()
		gp.VulnerabilityAnalysis.BumpActions = []BumpAction{
			{Action: "needs_bump", Language: "rust", Modroots: []string{"."}},
		}
		shouldRun, err := stage.ShouldRun(t.Context(), gp)
		require.NoError(t, err)
		assert.False(t, shouldRun)
	})
}

func TestTrimMajorSuffix(t *testing.T) {
	assert.Equal(t, "github.com/foo/bar", trimMajorSuffix("github.com/foo/bar/v2"))
	assert.Equal(t, "github.com/foo/bar/v2x", trimMajorSuffix("github.com/foo/bar/v2x"))
	assert.Equal(t, "gopkg.in/yaml.v2", trimMajorSuffix("gopkg.in/yaml.v2"))
	assert.Equal(t, "example.com/verystuff", trimMajorSuffix("example.com/verystuff"))
	assert.Equal(t, "module", trimMajorSuffix("module"))
}

func TestSimulationStage_ReplacesFoldBackAndSeeds(t *testing.T) {
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot:          ".",
				FinalDeps:        []string{"example.com/old@v1.2.0"},
				FinalReplaces:    []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.55.0"},
				CVEBackedModules: []string{"example.com/old", "github.com/aws/aws-sdk-go"},
				Converged:        true,
				Iterations:       1,
			},
		},
	}
	stage := newStageWithFake(fake)
	gp := newSimulationProcessor()
	modroot := &gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
	modroot.ExistingReplaces = []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}
	modroot.DesiredReplaces = modroot.ExistingReplaces
	modroot.ScanResult.SecurityBumps = append(modroot.ScanResult.SecurityBumps,
		scan.SecurityBump{Name: "github.com/aws/aws-sdk-go", Ecosystem: "Go", FixedVersion: "v1.55.0", VulnIDs: []string{"GO-AWS-1"}})

	require.NoError(t, stage.Apply(t.Context(), gp))

	// Replace seeds come first, with CVE provenance mapped from the scan.
	require.NotEmpty(t, fake.gotReqs)
	seeds := fake.gotReqs[0].Seeds
	require.NotEmpty(t, seeds)
	assert.Equal(t, simulate.Candidate{
		Module: "github.com/aws/aws-sdk-go", Version: "v1.34.0",
		FromCVE: true, VulnIDs: []string{"GO-AWS-1"},
		Replace: true, ReplaceOld: "github.com/aws/aws-sdk-go",
	}, seeds[0])

	// Fold-back updates DesiredReplaces and the rebuilt action carries them.
	updated := gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.55.0"}, updated.DesiredReplaces)
	require.Len(t, gp.VulnerabilityAnalysis.BumpActions, 1)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.55.0"}, gp.VulnerabilityAnalysis.BumpActions[0].Replaces)
}

func TestSimulationStage_ReplacesOnlyChangeTriggersAction(t *testing.T) {
	// A promotion with unchanged deps must still produce a BumpAction, or
	// the applier never writes it.
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot:          ".",
				FinalDeps:        []string{"example.com/old@v1.2.0", "example.com/pin@v0.9.0"}, // == existing DesiredDeps
				FinalReplaces:    []string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"},
				CVEBackedModules: []string{"example.com/old"},
				Converged:        true,
				Iterations:       1,
			},
		},
	}
	stage := newStageWithFake(fake)
	gp := newSimulationProcessor()
	modroot := &gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
	modroot.ExistingDeps = []string{"example.com/old@v1.2.0", "example.com/pin@v0.9.0"}

	require.NoError(t, stage.Apply(t.Context(), gp))

	require.Len(t, gp.VulnerabilityAnalysis.BumpActions, 1)
	action := gp.VulnerabilityAnalysis.BumpActions[0]
	assert.Empty(t, action.Dependencies)
	assert.Equal(t, []string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"}, action.Replaces)
}

// TestSimulationStage_UnreachableReportedAndPruned: an advisory whose module
// is not linked into any build artifact must be pruned from the desired deps
// (via the loop's FinalDeps) AND reported as informational - counted neither
// fixed nor residual.
func TestSimulationStage_UnreachableReportedAndPruned(t *testing.T) {
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot:   ".",
				FinalDeps: nil, // the unreachable seed did not survive
				Converged: true, Iterations: 1,
				Dropped: []simulate.DroppedCandidate{
					{Module: "example.com/old", Version: "v1.2.0", Reason: "module not linked into build artifacts (packages: ./cmd/app)"},
				},
				Linked: map[string]struct{}{"example.com/linkedonly": {}},
			},
		},
	}
	stage := newStageWithFake(fake)
	gp := newSimulationProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))

	modroot := gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
	assert.Empty(t, modroot.DesiredDeps, "unreachable dep must be pruned")
	assert.Empty(t, gp.Residuals)
	assert.Equal(t, []string{"GO-OLD-1"}, gp.UnreachableVulnIDs)

	var found bool
	for _, msg := range gp.GetMessages() {
		if strings.Contains(msg, "vulnerable but not linked into build artifacts") &&
			strings.Contains(msg, "example.com/old") {
			found = true
		}
	}
	assert.True(t, found, "expected an info message about the unlinked module, got %v", gp.GetMessages())

	// The rebuilt action reflects the prune (desired now differs from existing).
	require.Len(t, gp.VulnerabilityAnalysis.BumpActions, 1)
	assert.Empty(t, gp.VulnerabilityAnalysis.BumpActions[0].Dependencies)

	// Accounting: found=2, residual=0, unreachable=1 -> fixed=1.
	result := gp.ToResult()
	assert.Equal(t, 1, result.VulnerabilitiesUnreachable)
	assert.Equal(t, 1, result.VulnerabilitiesFixed)
	assert.Equal(t, []string{"GO-OLD-1"}, result.UnreachableVulnIDs)
}

// TestSimulationStage_UnreachableCrossModrootDedup: an advisory unlinked in
// one modroot but linked (and handled) in another counts as reachable - it
// must not appear in the unreachable set.
func TestSimulationStage_UnreachableCrossModrootDedup(t *testing.T) {
	scanResult := &scan.ScanResult{
		SecurityBumps: []scan.SecurityBump{
			{Name: "example.com/old", Ecosystem: "Go", CurrentVersion: "v1.0.0", FixedVersion: "v1.2.0", VulnIDs: []string{"GO-OLD-1"}},
		},
	}
	coords := map[string]scan.SecurityBump{
		"example.com/old": scanResult.SecurityBumps[0],
	}

	gp := NewGoBumpProcessor("/tmp/test.yaml", "test-package", "1.0.0", 1)
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{
		RepoURL: "https://github.com/example/repo", Tag: "v1.0.0",
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{
				{Modroot: "cmd/a", ExistingDeps: nil, DesiredDeps: []string{"example.com/old@v1.2.0"},
					ScanResult: scanResult, SecurityBumpsByCoord: coords},
				{Modroot: "cmd/b", ExistingDeps: nil, DesiredDeps: []string{"example.com/old@v1.2.0"},
					ScanResult: scanResult, SecurityBumpsByCoord: coords},
			},
		}},
		VulnerabilitiesFound: 1,
		BumpActions:          []BumpAction{{Action: "needs_bump", Language: "go", Modroots: []string{"cmd/a", "cmd/b"}}},
	}

	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			// Unlinked (and pruned) in cmd/a...
			"cmd/a": {
				Modroot: "cmd/a", Converged: true, Iterations: 1,
				Dropped: []simulate.DroppedCandidate{{Module: "example.com/old", Version: "v1.2.0",
					Reason: "module not linked into build artifacts (packages: ./...)"}},
				Linked: map[string]struct{}{"example.com/other": {}},
			},
			// ...but linked and fixed in cmd/b.
			"cmd/b": {
				Modroot: "cmd/b", Converged: true, Iterations: 1,
				FinalDeps:        []string{"example.com/old@v1.2.0"},
				CVEBackedModules: []string{"example.com/old"},
				Linked:           map[string]struct{}{"example.com/old": {}},
			},
		},
	}
	stage := newStageWithFake(fake)

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.Empty(t, gp.UnreachableVulnIDs, "an ID linked in any modroot counts as reachable")
	result := gp.ToResult()
	assert.Equal(t, 0, result.VulnerabilitiesUnreachable)
	assert.Equal(t, 1, result.VulnerabilitiesFixed)
}

// coUpdateTestProcessor builds a processor whose modroot carries a parsed
// pristine go.mod (via the golang ecosystem's Analyze), as declareCoUpdates
// requires.
func coUpdateTestProcessor(t *testing.T) *GoBumpProcessor {
	t.Helper()
	goMod := `module example.com/app

go 1.22

require (
	go.opentelemetry.io/otel v1.39.0
	go.opentelemetry.io/otel/metric v1.39.0
	go.opentelemetry.io/otel/trace v1.39.0
)
`
	deps, err := ecogolang.New().Analyze(t.Context(), map[string][]byte{"go.mod": []byte(goMod)})
	require.NoError(t, err)

	gp := NewGoBumpProcessor("/tmp/test.yaml", "test-package", "1.0.0", 1)
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{
		RepoURL: "https://github.com/example/repo", Tag: "v1.0.0",
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{{
				Modroot:      ".",
				Deps:         deps,
				ExistingDeps: nil,
				DesiredDeps:  []string{"go.opentelemetry.io/otel@v1.41.0"},
				ScanResult: &scan.ScanResult{SecurityBumps: []scan.SecurityBump{
					{Name: "go.opentelemetry.io/otel", Ecosystem: "Go", CurrentVersion: "v1.39.0", FixedVersion: "v1.41.0", VulnIDs: []string{"GHSA-OTEL-1"}},
				}},
				SecurityBumpModules: []string{"go.opentelemetry.io/otel"},
			}},
		}},
		VulnerabilitiesFound: 1,
		BumpActions:          []BumpAction{{Action: "needs_bump", Language: "go", Modroots: []string{"."}}},
	}
	return gp
}

// otelResult is the proven simulation outcome for the co-update tests: otel
// bumped, its release-group siblings raised by MVS in the tidied go.mod.
func otelResult() *simulate.ModrootResult {
	return &simulate.ModrootResult{
		Modroot:          ".",
		FinalDeps:        []string{"go.opentelemetry.io/otel@v1.41.0"},
		CVEBackedModules: []string{"go.opentelemetry.io/otel"},
		Converged:        true, Iterations: 1,
		Requires: map[string]string{
			"go.opentelemetry.io/otel":        "v1.41.0",
			"go.opentelemetry.io/otel/trace":  "v1.41.0",
			"go.opentelemetry.io/otel/metric": "v1.41.0",
		},
		Linked: map[string]struct{}{
			"go.opentelemetry.io/otel":        {},
			"go.opentelemetry.io/otel/trace":  {},
			"go.opentelemetry.io/otel/metric": {},
		},
	}
}

func TestSimulationStage_DeclaresCoUpdates(t *testing.T) {
	fake := &fakeBumpSimulator{results: map[string]*simulate.ModrootResult{".": otelResult()}}
	stage := newStageWithFake(fake)
	stage.detectCoUpdates = func(_ context.Context, packagesToUpdate map[string]string, _ *modfile.File) map[string]omnibumpgolang.MissingDependency {
		if _, present := packagesToUpdate["go.opentelemetry.io/otel/trace"]; present {
			return nil // already declared - silent, fixpoint reached
		}
		return map[string]omnibumpgolang.MissingDependency{
			"go.opentelemetry.io/otel/trace": {
				Package: "go.opentelemetry.io/otel/trace", RequiredVersion: "v1.41.0",
				CurrentVersion: "v1.39.0", Reason: "version group with go.opentelemetry.io/otel",
			},
		}
	}
	gp := coUpdateTestProcessor(t)

	require.NoError(t, stage.Apply(t.Context(), gp))

	m := gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
	assert.Equal(t, []string{"go.opentelemetry.io/otel@v1.41.0", "go.opentelemetry.io/otel/trace@v1.41.0"}, m.DesiredDeps)
	assert.Equal(t, []string{"go.opentelemetry.io/otel"}, m.SecurityBumpModules, "declared co-update must not become a security module")

	var messaged bool
	for _, msg := range gp.GetMessages() {
		if strings.Contains(msg, "declared co-update: go.opentelemetry.io/otel/trace@v1.41.0") {
			messaged = true
		}
	}
	assert.True(t, messaged, "expected a declared co-update message, got %v", gp.GetMessages())

	// Accounting: the coherence pin is neither fixed nor a security fix.
	result := gp.ToResult()
	assert.Equal(t, 1, result.VulnerabilitiesFixed)

	// The rebuilt action carries the full declared list.
	require.Len(t, gp.VulnerabilityAnalysis.BumpActions, 1)
	assert.Contains(t, gp.VulnerabilityAnalysis.BumpActions[0].Dependencies, "go.opentelemetry.io/otel/trace@v1.41.0")
}

func TestSimulationStage_CoUpdateGates(t *testing.T) {
	recommend := func(module, version string) map[string]omnibumpgolang.MissingDependency {
		return map[string]omnibumpgolang.MissingDependency{
			module: {Package: module, RequiredVersion: version, CurrentVersion: "v1.39.0", Reason: "version group"},
		}
	}

	t.Run("unsustained recommendation skipped", func(t *testing.T) {
		result := otelResult()
		result.Requires["go.opentelemetry.io/otel/trace"] = "v1.40.0" // tidied require BELOW recommendation
		fake := &fakeBumpSimulator{results: map[string]*simulate.ModrootResult{".": result}}
		stage := newStageWithFake(fake)
		stage.detectCoUpdates = func(context.Context, map[string]string, *modfile.File) map[string]omnibumpgolang.MissingDependency {
			return recommend("go.opentelemetry.io/otel/trace", "v1.41.0")
		}
		gp := coUpdateTestProcessor(t)

		require.NoError(t, stage.Apply(t.Context(), gp))
		assert.Equal(t, []string{"go.opentelemetry.io/otel@v1.41.0"},
			gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0].DesiredDeps)
	})

	t.Run("unlinked recommendation skipped", func(t *testing.T) {
		result := otelResult()
		delete(result.Linked, "go.opentelemetry.io/otel/trace")
		fake := &fakeBumpSimulator{results: map[string]*simulate.ModrootResult{".": result}}
		stage := newStageWithFake(fake)
		stage.detectCoUpdates = func(context.Context, map[string]string, *modfile.File) map[string]omnibumpgolang.MissingDependency {
			return recommend("go.opentelemetry.io/otel/trace", "v1.41.0")
		}
		gp := coUpdateTestProcessor(t)

		require.NoError(t, stage.Apply(t.Context(), gp))
		assert.Equal(t, []string{"go.opentelemetry.io/otel@v1.41.0"},
			gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0].DesiredDeps)
	})

	t.Run("nil linked set fails open - appended", func(t *testing.T) {
		result := otelResult()
		result.Linked = nil
		fake := &fakeBumpSimulator{results: map[string]*simulate.ModrootResult{".": result}}
		stage := newStageWithFake(fake)
		calls := 0
		stage.detectCoUpdates = func(context.Context, map[string]string, *modfile.File) map[string]omnibumpgolang.MissingDependency {
			calls++
			if calls > 1 {
				return nil
			}
			return recommend("go.opentelemetry.io/otel/trace", "v1.41.0")
		}
		gp := coUpdateTestProcessor(t)

		require.NoError(t, stage.Apply(t.Context(), gp))
		assert.Contains(t, gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0].DesiredDeps,
			"go.opentelemetry.io/otel/trace@v1.41.0")
	})
}

func TestSimulationStage_CoUpdateDetectorFailureFailsOpen(t *testing.T) {
	fake := &fakeBumpSimulator{results: map[string]*simulate.ModrootResult{".": otelResult()}}
	stage := newStageWithFake(fake)
	stage.detectCoUpdates = func(context.Context, map[string]string, *modfile.File) map[string]omnibumpgolang.MissingDependency {
		panic("simulated proxy failure")
	}
	gp := coUpdateTestProcessor(t)

	require.NoError(t, stage.Apply(t.Context(), gp))
	assert.Equal(t, []string{"go.opentelemetry.io/otel@v1.41.0"},
		gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0].DesiredDeps)
	assert.True(t, gp.Validated, "co-update declaration failure must not degrade validation")
}

// TestSimulationStage_CoUpdateFixpoint: declaring trace triggers a new group
// recommendation for metric on the next round; both end up declared.
func TestSimulationStage_CoUpdateFixpoint(t *testing.T) {
	fake := &fakeBumpSimulator{results: map[string]*simulate.ModrootResult{".": otelResult()}}
	stage := newStageWithFake(fake)
	stage.detectCoUpdates = func(_ context.Context, packagesToUpdate map[string]string, _ *modfile.File) map[string]omnibumpgolang.MissingDependency {
		_, hasTrace := packagesToUpdate["go.opentelemetry.io/otel/trace"]
		_, hasMetric := packagesToUpdate["go.opentelemetry.io/otel/metric"]
		switch {
		case !hasTrace:
			return map[string]omnibumpgolang.MissingDependency{
				"go.opentelemetry.io/otel/trace": {Package: "go.opentelemetry.io/otel/trace", RequiredVersion: "v1.41.0"},
			}
		case !hasMetric:
			return map[string]omnibumpgolang.MissingDependency{
				"go.opentelemetry.io/otel/metric": {Package: "go.opentelemetry.io/otel/metric", RequiredVersion: "v1.41.0"},
			}
		default:
			return nil
		}
	}
	gp := coUpdateTestProcessor(t)

	require.NoError(t, stage.Apply(t.Context(), gp))
	m := gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
	assert.Equal(t, []string{
		"go.opentelemetry.io/otel@v1.41.0",
		"go.opentelemetry.io/otel/trace@v1.41.0",
		"go.opentelemetry.io/otel/metric@v1.41.0",
	}, m.DesiredDeps)
}

// TestSimulationStage_RequiredGoVersion: the simulation's MaxDepGoVersion
// lands in ModrootAnalysis.RequiredGoVersion iff it exceeds the module's own
// pristine baseline (go directive / toolchain directive max).
func TestSimulationStage_RequiredGoVersion(t *testing.T) {
	tests := []struct {
		name            string
		goMod           string // "" means no parsed go.mod (Deps stays nil)
		maxDepGoVersion string
		wantRequired    string
	}{
		{
			name:            "greater than go directive - set",
			goMod:           "module example.com/app\n\ngo 1.22\n",
			maxDepGoVersion: "1.25",
			wantRequired:    "1.25",
		},
		{
			name:            "equal to go directive - not set",
			goMod:           "module example.com/app\n\ngo 1.25\n",
			maxDepGoVersion: "1.25",
			wantRequired:    "",
		},
		{
			name:            "lower than go directive - not set",
			goMod:           "module example.com/app\n\ngo 1.25\n",
			maxDepGoVersion: "1.24",
			wantRequired:    "",
		},
		{
			name:            "unavailable from simulation - not set",
			goMod:           "module example.com/app\n\ngo 1.22\n",
			maxDepGoVersion: "",
			wantRequired:    "",
		},
		{
			name:            "toolchain directive raises the baseline - not set",
			goMod:           "module example.com/app\n\ngo 1.22\n\ntoolchain go1.25.1\n",
			maxDepGoVersion: "1.24",
			wantRequired:    "",
		},
		{
			name:            "exceeds even the toolchain directive - set",
			goMod:           "module example.com/app\n\ngo 1.22\n\ntoolchain go1.25.1\n",
			maxDepGoVersion: "1.26",
			wantRequired:    "1.26",
		},
		{
			name:            "no pristine go.mod - fail open toward emitting",
			goMod:           "",
			maxDepGoVersion: "1.25",
			wantRequired:    "1.25",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gp := newSimulationProcessor()
			if tt.goMod != "" {
				deps, err := ecogolang.New().Analyze(t.Context(), map[string][]byte{"go.mod": []byte(tt.goMod)})
				require.NoError(t, err)
				gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0].Deps = deps
			}

			fake := &fakeBumpSimulator{
				results: map[string]*simulate.ModrootResult{
					".": {
						Modroot:          ".",
						FinalDeps:        []string{"example.com/old@v1.2.0"},
						CVEBackedModules: []string{"example.com/old"},
						Converged:        true, Iterations: 1,
						MaxDepGoVersion: tt.maxDepGoVersion,
					},
				},
			}
			stage := newStageWithFake(fake)

			require.NoError(t, stage.Apply(t.Context(), gp))

			m := gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0]
			assert.Equal(t, tt.wantRequired, m.RequiredGoVersion)

			var messaged bool
			for _, msg := range gp.GetMessages() {
				if strings.Contains(msg, "require Go") {
					messaged = true
				}
			}
			assert.Equal(t, tt.wantRequired != "", messaged, "raise message iff a raise was recorded; messages: %v", gp.GetMessages())
		})
	}
}

func TestPristineGoBaseline(t *testing.T) {
	t.Run("nil deps", func(t *testing.T) {
		assert.Equal(t, "", pristineGoBaseline(&ModrootAnalysis{}))
	})

	t.Run("go directive only", func(t *testing.T) {
		deps, err := ecogolang.New().Analyze(t.Context(), map[string][]byte{"go.mod": []byte("module m\n\ngo 1.24\n")})
		require.NoError(t, err)
		assert.Equal(t, "1.24", pristineGoBaseline(&ModrootAnalysis{Deps: deps}))
	})

	t.Run("toolchain directive wins when higher", func(t *testing.T) {
		deps, err := ecogolang.New().Analyze(t.Context(), map[string][]byte{"go.mod": []byte("module m\n\ngo 1.22\n\ntoolchain go1.25.3\n")})
		require.NoError(t, err)
		assert.Equal(t, "1.25.3", pristineGoBaseline(&ModrootAnalysis{Deps: deps}))
	})
}

// TestSimulationStage_PackageUnreachableClassifiedAsInfo: the x/sys/windows
// shape end-to-end at the stage level - the module is linked but the
// advisory's vulnerable packages are not; the advisory must land in the
// unreachable info bucket (neither fixed nor residual) with the
// package-level wording.
func TestSimulationStage_PackageUnreachableClassifiedAsInfo(t *testing.T) {
	scanResult := &scan.ScanResult{
		Vulnerabilities: []scan.Vulnerability{{
			ID: "GO-2026-5024", Module: "golang.org/x/sys", Ecosystem: "Go",
			CurrentVersion: "v0.39.0", FixedVersion: "v0.44.0",
			VulnerableImports: []scan.VulnerableImport{{Path: "golang.org/x/sys/windows", GOOS: []string{"windows"}}},
		}},
		SecurityBumps: []scan.SecurityBump{
			{Name: "golang.org/x/sys", Ecosystem: "Go", CurrentVersion: "v0.39.0", FixedVersion: "v0.44.0", VulnIDs: []string{"GO-2026-5024"}},
		},
	}

	gp := NewGoBumpProcessor("/tmp/test.yaml", "test-package", "1.0.0", 1)
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{
		RepoURL: "https://github.com/example/repo", Tag: "v1.0.0",
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{{
				Modroot:              ".",
				DesiredDeps:          []string{"golang.org/x/sys@v0.44.0"},
				ScanResult:           scanResult,
				SecurityBumpsByCoord: map[string]scan.SecurityBump{"golang.org/x/sys": scanResult.SecurityBumps[0]},
			}},
		}},
		VulnerabilitiesFound: 1,
		BumpActions:          []BumpAction{{Action: "needs_bump", Language: "go", Modroots: []string{"."}}},
	}

	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot: ".", Converged: true, Iterations: 1,
				// The loop dropped the seed pre-apply (package unreachable).
				Dropped: []simulate.DroppedCandidate{
					{Module: "golang.org/x/sys", Version: "v0.44.0", Reason: "vulnerable package(s) not linked into build artifacts"},
				},
				Linked:         map[string]struct{}{"golang.org/x/sys": {}},
				LinkedPackages: map[string]struct{}{"golang.org/x/sys/unix": {}},
			},
		},
	}
	stage := newStageWithFake(fake)

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.Equal(t, []string{"GO-2026-5024"}, gp.UnreachableVulnIDs)
	assert.Empty(t, gp.Residuals)

	var messaged bool
	for _, msg := range gp.GetMessages() {
		if strings.Contains(msg, "golang.org/x/sys") &&
			strings.Contains(msg, "module is linked; the vulnerable packages are not") {
			messaged = true
		}
	}
	assert.True(t, messaged, "expected the package-level info wording, got %v", gp.GetMessages())

	// Accounting: found=1, residual=0, unreachable=1 -> fixed=0.
	result := gp.ToResult()
	assert.Equal(t, 1, result.VulnerabilitiesUnreachable)
	assert.Equal(t, 0, result.VulnerabilitiesFixed)
}

// newTwoModrootSimulationProcessor builds a VulnerabilityAnalysis with two Go
// modroots ("." and "sub"), each with its own advisory, for exercising the
// linked-stdlib union's completeness gating across modroots.
func newTwoModrootSimulationProcessor() *GoBumpProcessor {
	gp := NewGoBumpProcessor("/tmp/test.yaml", "test-package", "1.0.0", 1)
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{
		RepoURL:        "https://github.com/example/repo",
		Tag:            "v1.0.0",
		ExpectedCommit: "abc123",
		ByLanguage: []LanguageAnalysis{
			{
				Language: "go",
				ByModroot: []ModrootAnalysis{
					{
						Modroot:       ".",
						BuildPackages: []string{"./cmd/app"},
						ExistingDeps:  []string{"example.com/old@v1.0.0"},
						DesiredDeps:   []string{"example.com/old@v1.2.0"},
						ScanResult: &scan.ScanResult{
							SecurityBumps: []scan.SecurityBump{
								{Name: "example.com/old", Ecosystem: "Go", CurrentVersion: "v1.0.0", FixedVersion: "v1.2.0", VulnIDs: []string{"GO-OLD-1"}},
							},
						},
						SecurityBumpModules: []string{"example.com/old"},
					},
					{
						Modroot:       "sub",
						BuildPackages: []string{"./cmd/sub"},
						ExistingDeps:  []string{"example.com/other@v1.0.0"},
						DesiredDeps:   []string{"example.com/other@v1.2.0"},
						ScanResult: &scan.ScanResult{
							SecurityBumps: []scan.SecurityBump{
								{Name: "example.com/other", Ecosystem: "Go", CurrentVersion: "v1.0.0", FixedVersion: "v1.2.0", VulnIDs: []string{"GO-OTHER-1"}},
							},
						},
						SecurityBumpModules: []string{"example.com/other"},
					},
				},
			},
		},
		VulnerabilitiesFound: 2,
		BumpActions: []BumpAction{
			{Action: "needs_bump", Language: "go", Modroots: []string{".", "sub"}, Dependencies: []string{"example.com/old@v1.2.0", "example.com/other@v1.2.0"}},
		},
	}
	return gp
}

func TestSimulationStage_LinkedStdPackages_UnionWhenAllModrootsContribute(t *testing.T) {
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot: ".", Converged: true, Iterations: 1,
				FinalDeps:        []string{"example.com/old@v1.2.0"},
				CVEBackedModules: []string{"example.com/old"},
				StdPackages:      map[string]struct{}{"fmt": {}, "os": {}},
			},
			"sub": {
				Modroot: "sub", Converged: true, Iterations: 1,
				FinalDeps:        []string{"example.com/other@v1.2.0"},
				CVEBackedModules: []string{"example.com/other"},
				StdPackages:      map[string]struct{}{"net/http": {}},
			},
		},
	}
	stage := newStageWithFake(fake)
	gp := newTwoModrootSimulationProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.Equal(t, map[string]struct{}{"fmt": {}, "os": {}, "net/http": {}}, gp.LinkedStdPackages)
}

func TestSimulationStage_LinkedStdPackages_NilWhenModrootSkipped(t *testing.T) {
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot: ".", Converged: true, Iterations: 1,
				FinalDeps:        []string{"example.com/old@v1.2.0"},
				CVEBackedModules: []string{"example.com/old"},
				StdPackages:      map[string]struct{}{"fmt": {}, "os": {}},
			},
			// "sub" absent from results: an unsimulated/skipped modroot.
		},
	}
	stage := newStageWithFake(fake)
	gp := newTwoModrootSimulationProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.Nil(t, gp.LinkedStdPackages, "a skipped modroot must invalidate the union - partial data must not masquerade as complete")
}

func TestSimulationStage_LinkedStdPackages_NilWhenModrootStdWalkFailedOpen(t *testing.T) {
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot: ".", Converged: true, Iterations: 1,
				FinalDeps:        []string{"example.com/old@v1.2.0"},
				CVEBackedModules: []string{"example.com/old"},
				StdPackages:      map[string]struct{}{"fmt": {}, "os": {}},
			},
			"sub": {
				Modroot: "sub", Converged: true, Iterations: 1,
				FinalDeps:        []string{"example.com/other@v1.2.0"},
				CVEBackedModules: []string{"example.com/other"},
				StdPackages:      nil, // this modroot's stdlib walk failed open
			},
		},
	}
	stage := newStageWithFake(fake)
	gp := newTwoModrootSimulationProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.Nil(t, gp.LinkedStdPackages, "one modroot's failed-open stdlib walk must invalidate the whole union")
}
