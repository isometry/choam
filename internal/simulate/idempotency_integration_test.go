package simulate

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"
)

// TestReplay_Idempotent: every replay fixture, under both engines, must
// produce byte-identical results on repeated runs from the same input, and
// a second run seeded the way the next `choam bump` would seed it (the
// written FinalDeps as existing YAML pins, merged with the baseline scan's
// bumps) must write nothing new.
func TestReplay_Idempotent(t *testing.T) {
	const runs = 5
	for _, c := range replayCases() {
		for _, noTidy := range []bool{false, true} {
			if noTidy && !c.noTidyVariant {
				continue
			}
			name := c.name
			if noTidy {
				name += "-notidy"
			}
			t.Run(name, func(t *testing.T) {
				forEachEngine(t, func(t *testing.T, eng Engine) {
					f := c.fixture(t)
					var first *ModrootResult
					var want []byte
					for i := range runs {
						result, err := c.run(t, f.fresh(t), eng, noTidy)
						require.NoError(t, err)
						got := goldenJSON(t, result)
						if i == 0 {
							first, want = result, got
							continue
						}
						require.Equal(t, string(want), string(got), "run %d differs from run 1", i+1)
					}

					next := c
					next.req.Seeds = nextRunSeeds(t, c, first.FinalDeps)
					second, err := next.run(t, f.fresh(t), eng, noTidy)
					require.NoError(t, err)
					logResult(t, second)
					assert.ElementsMatch(t, first.FinalDeps, second.FinalDeps, "second run must keep the written deps")
					assert.Equal(t, first.FinalReplaces, second.FinalReplaces)
					assert.Equal(t, first.Residuals, second.Residuals)
					assert.Equal(t, first.RemainingVulnIDs, second.RemainingVulnIDs)
					assert.Equal(t, first.HygieneModules, second.HygieneModules, "hygiene bumps are re-derived identically")
				})
			})
		}
	}
}

// fresh is a copy of the fixture whose checkout is a new copy of the
// pristine module (RunLoop leaves its final state on disk).
func (f replayFixture) fresh(t *testing.T) replayFixture {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(f.pristine)
	require.NoError(t, err)
	for _, e := range entries {
		copyFile(t, filepath.Join(f.pristine, e.Name()), filepath.Join(dir, e.Name()))
	}
	f.dir = dir
	return f
}

// nextRunSeeds mirrors what the next run's analysis hands the loop
// (gobump's FilterBumps + seedCandidates): the baseline scan's bumps merged
// with the existing pins (written deps), the higher version per module,
// CVE-backed with the bump's advisories and a ladder of per-advisory fixes
// plus the pins. Replace seeds carry over unchanged.
func nextRunSeeds(t *testing.T, c replayCase, existing []string) []Candidate {
	t.Helper()
	scanResult, err := c.sc().ScanPackages(t.Context(), packagesFor(c.req.Baseline))
	require.NoError(t, err)

	pins := make(map[string]string)
	for _, dep := range existing {
		at := strings.LastIndex(dep, "@")
		require.Positive(t, at, dep)
		pins[dep[:at]] = dep[at+1:]
	}
	desired := maps.Clone(pins)
	for _, bump := range scanResult.SecurityBumps {
		if semver.Compare(bump.FixedVersion, desired[bump.Name]) > 0 {
			desired[bump.Name] = bump.FixedVersion
		}
	}

	var seeds []Candidate
	for _, seed := range c.req.Seeds {
		if seed.Replace {
			seeds = append(seeds, seed)
		}
	}
	for _, module := range sortedKeys(desired) {
		candidate := Candidate{Module: module, Version: desired[module]}
		if i := slices.IndexFunc(scanResult.SecurityBumps, func(b scan.SecurityBump) bool { return b.Name == module }); i >= 0 {
			bump := scanResult.SecurityBumps[i]
			candidate.FromCVE, candidate.VulnIDs, candidate.Severity = true, bump.VulnIDs, bump.Severity
			also := []string{candidate.Version}
			if pin, ok := pins[module]; ok {
				also = append(also, pin)
			}
			if rungs := FixRungs(scanResult.Vulnerabilities, module, bump.VulnIDs, also...); len(rungs) > 1 {
				candidate.Rungs = rungs
			}
		}
		seeds = append(seeds, candidate)
	}
	return seeds
}
