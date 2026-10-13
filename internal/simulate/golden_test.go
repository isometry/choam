package simulate

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"

	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files under internal/testdata/golden/")

// goldenResult is the part of a ModrootResult that must be byte-stable for
// a given fixture: everything written to the spec or reported, nothing that
// depends on the host toolchain.
type goldenResult struct {
	Converged        bool               `json:"converged"`
	FinalDeps        []string           `json:"final_deps"`
	FinalReplaces    []string           `json:"final_replaces"`
	CVEBackedModules []string           `json:"cve_backed_modules"`
	Resolved         map[string]string  `json:"resolved"`
	Residuals        []Residual         `json:"residuals"`
	Dropped          []DroppedCandidate `json:"dropped"`
	RemainingVulnIDs []string           `json:"remaining_vuln_ids"`
	HygieneModules   []HygieneModule    `json:"hygiene_modules,omitempty"`
	HygieneSkipped   string             `json:"hygiene_skipped,omitempty"`
}

func goldenJSON(t tb, result *ModrootResult) []byte {
	t.Helper()
	out, err := json.MarshalIndent(goldenResult{
		Converged:        result.Converged,
		FinalDeps:        result.FinalDeps,
		FinalReplaces:    result.FinalReplaces,
		CVEBackedModules: result.CVEBackedModules,
		Resolved:         result.Resolved,
		Residuals:        result.Residuals,
		Dropped:          result.Dropped,
		RemainingVulnIDs: result.RemainingVulnIDs,
		HygieneModules:   result.HygieneModules,
		HygieneSkipped:   result.HygieneSkipped,
	}, "", "  ")
	require.NoError(t, err)
	return append(out, '\n')
}

// assertGolden compares result against internal/testdata/golden/<name>.json
// (go test -run ... -update rewrites it).
func assertGolden(t tb, name string, result *ModrootResult) {
	t.Helper()
	path := filepath.Join("..", "testdata", "golden", name+".json")
	got := goldenJSON(t, result)
	if *updateGolden {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file (run with -update)")
	require.Equal(t, string(want), string(got), "golden mismatch for %s (run with -update after verifying)", name)
}
