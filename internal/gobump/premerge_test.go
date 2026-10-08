package gobump

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defectPreLoopMerge: the analysis collapses an existing YAML pin and the
// OSV fix for the same module into one (the higher) version before the
// simulation sees it, so the lower fix rung is unavailable as a fallback.
const defectPreLoopMerge = "stage3: FilterBumps/seedCandidates merge the YAML pin (otel/sdk@v1.43.0) " +
	"and the OSV fix (v1.45.0) into one seed at v1.45.0; the v1.43.0 rung is erased"

// knownDefect mirrors internal/simulate's helper of the same name (test
// helpers cannot cross packages): body pins the correct behaviour and must
// still FAIL; the suite goes red when it starts passing. Flip by renaming
// the call to assertFixed.
func knownDefect(t *testing.T, defect string, body func(t require.TestingT)) {
	t.Helper()
	t.Run("known_defect", func(t *testing.T) {
		rec := &defectRecorder{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			body(rec)
		}()
		<-done
		if !rec.failed {
			t.Errorf("known defect appears FIXED - flip knownDefect to assertFixed: %s", defect)
			return
		}
		t.Logf("known defect still present: %s\n  %s", defect, strings.Join(rec.errors, "\n  "))
	})
}

func assertFixed(t *testing.T, _ string, body func(t require.TestingT)) {
	t.Helper()
	body(t)
}

type defectRecorder struct {
	mu     sync.Mutex
	failed bool
	errors []string
}

func (r *defectRecorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func (r *defectRecorder) FailNow() {
	r.mu.Lock()
	r.failed = true
	r.mu.Unlock()
	runtime.Goexit()
}

// TestSeedCandidates_PreLoopMergeKeepsFixRungs (d): opentofu-1.12 declares
// otel/sdk@v1.43.0 and OSV reports two otel/sdk advisories fixed at
// v1.43.0 (HIGH) and v1.45.0 (LOW). The relax-one-rung fallback needs both
// versions, so both must still be observable in what the simulation is
// seeded with. The assertion is deliberately shape-agnostic (any rendering
// of the module's seeds that mentions both versions passes), so a later
// stage may carry the rungs in a new Candidate field.
func TestSeedCandidates_PreLoopMergeKeepsFixRungs(t *testing.T) {
	const sdk = "go.opentelemetry.io/otel/sdk"
	goMod := "module github.com/opentofu/opentofu\n\ngo 1.21\n\nrequire " + sdk + " v1.42.0\n"
	eco := ecogolang.New()
	deps, err := eco.Analyze(t.Context(), map[string][]byte{"go.mod": []byte(goMod)})
	require.NoError(t, err)

	scanResult := &scan.ScanResult{
		Vulnerabilities: []scan.Vulnerability{
			{ID: "GHSA-hfvc-g4fc-pqhx", Module: sdk, Ecosystem: "Go", CurrentVersion: "v1.42.0", FixedVersion: "v1.43.0", Severity: "HIGH"},
			{ID: "GHSA-8wmf-6v46-5gfg", Module: sdk, Ecosystem: "Go", CurrentVersion: "v1.42.0", FixedVersion: "v1.45.0", Severity: "LOW"},
		},
		SecurityBumps: []scan.SecurityBump{{
			Name: sdk, Ecosystem: "Go", CurrentVersion: "v1.42.0", FixedVersion: "v1.45.0",
			VulnIDs: []string{"GHSA-8wmf-6v46-5gfg", "GHSA-hfvc-g4fc-pqhx"}, Severity: "HIGH",
		}},
	}
	existing := []string{sdk + "@v1.43.0"}

	desired, _ := eco.FilterBumps(t.Context(), existing, scanResult.SecurityBumps, deps)
	seeds := seedCandidates(ModrootAnalysis{Modroot: ".", Deps: deps, ScanResult: scanResult, ExistingDeps: existing, DesiredDeps: desired})
	var sdkSeeds []simulate.Candidate
	for _, seed := range seeds {
		if seed.Module == sdk {
			sdkSeeds = append(sdkSeeds, seed)
		}
	}
	t.Logf("desired deps: %v; otel/sdk seeds: %+v", desired, sdkSeeds)

	assertFixed(t, defectPreLoopMerge, func(t require.TestingT) {
		require.NotEmpty(t, sdkSeeds, "otel/sdk must be seeded")
		rendered := fmt.Sprintf("%+v", sdkSeeds)
		for _, rung := range []string{"v1.45.0", "v1.43.0"} {
			assert.Contains(t, rendered, rung, "fix rung %s must reach the simulation seeds", rung)
		}
	})
}

func TestKnownDefectHelper(t *testing.T) {
	knownDefect(t, "helper self-test", func(t require.TestingT) { require.Equal(t, 1, 2) })
	ran := false
	assertFixed(t, "helper self-test", func(require.TestingT) { ran = true })
	require.True(t, ran)
}
