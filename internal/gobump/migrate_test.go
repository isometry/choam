package gobump

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files under testdata/")

// bumpedEntry is the fake simulation outcome the migration tests use: every
// x/net and x/text pin moves one patch forward.
func bumpedEntry(entry string) string {
	entry = strings.ReplaceAll(entry, "golang.org/x/net@v0.55.0", "golang.org/x/net@v0.56.0")
	return strings.ReplaceAll(entry, "golang.org/x/text@v0.38.0", "golang.org/x/text@v0.39.0")
}

func mapEntries(entries []string, fn func(string) string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, fn(e))
	}
	return out
}

// migrationAnalysis builds the Go analysis the check + simulation phases
// would hand the applier for yamlContent: units (and so engines) come from
// the real discovery with the real migration plans; each root's desired set
// is its current one passed through bump (a simulated root, unchanged roots
// listed in unchanged).
func migrationAnalysis(t *testing.T, yamlContent string, bump func(string) string, baselineTidies bool, unchanged ...string) (*VulnerabilityAnalysis, *melange.Configuration) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o644))
	cfg, err := melange.ParseConfiguration(t.Context(), path)
	require.NoError(t, err)

	loader := config.NewLoader()
	steps, err := loader.FindBumpSteps([]byte(yamlContent))
	require.NoError(t, err)
	units := discoverAnalysisUnits(t.Context(), cfg, steps, planMigrations(t.Context(), []byte(yamlContent), steps, nil))

	roots := unitRoots(units["go"])
	existingDeps := existingDepsForModroots(roots, steps)
	existingReplaces := existingReplacesForModroots(roots, steps)
	existingGoVersions := existingGoVersionsForModroots(roots, steps)
	lang := LanguageAnalysis{Language: "go"}
	var actions []BumpAction
	for _, unit := range units["go"] {
		fn := bump
		for _, root := range unchanged {
			if root == unit.Modroot {
				fn = func(s string) string { return s }
			}
		}
		m := ModrootAnalysis{
			Modroot:           unit.Modroot,
			BumpEngine:        unit.Engine,
			BumpMigrating:     unit.Migrating,
			BumpNoTidy:        unit.NoTidy,
			GoPackageMinor:    unit.GoMinor,
			ExistingDeps:      existingDeps[unit.Modroot],
			DesiredDeps:       mapEntries(existingDeps[unit.Modroot], fn),
			ExistingReplaces:  existingReplaces[unit.Modroot],
			DesiredReplaces:   mapEntries(existingReplaces[unit.Modroot], fn),
			ExistingGoVersion: existingGoVersions[unit.Modroot],
			Simulated:         true,
			BaselineTidies:    baselineTidies,
		}
		lang.ByModroot = append(lang.ByModroot, m)
		if haveDepsChanged(m.ExistingDeps, m.DesiredDeps) || haveDepsChanged(m.ExistingReplaces, m.DesiredReplaces) {
			actions = append(actions, BumpAction{Action: "needs_bump", Language: "go", Modroots: []string{m.Modroot}})
		}
	}
	return &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{lang}, BumpActions: actions}, cfg
}

// runApplier runs the apply phase over yamlContent and returns the result.
func runApplier(t *testing.T, yamlContent string, analysis *VulnerabilityAnalysis, cfg *melange.Configuration) *GoBumpProcessor {
	t.Helper()
	gp := newTestProcessor(t, yamlContent)
	gp.Config = cfg
	require.NoError(t, NewGoBumpApplier(nil).applyGoBumpChanges(t.Context(), gp, analysis))
	return gp
}

// TestMigration_Matrix runs the go/bump -> bump migration over the input
// matrix (testdata/migrate/<case>.in.yaml) and compares the written YAML
// byte-for-byte with <case>.golden.yaml (go test -run TestMigration_Matrix
// -update rewrites them). Every golden file shows comments, unrelated steps
// and subpackages untouched; each case also checks its messages, that the
// rewrite alone never bumps the epoch, and that a second run is a no-op.
func TestMigration_Matrix(t *testing.T) {
	cases := []struct {
		name           string
		baselineTidies bool
		unchanged      []string // modroots whose deps do not change
		migrated       bool
		messages       []string
	}{
		{name: "plain", migrated: true, messages: []string{"migrated pipeline[2] uses: go/bump -> uses: bump"}},
		{name: "goversion-pinned", migrated: true, messages: []string{"dropped go-version 1.24.13 from pipeline[1]", "go-package pin go-1.24"}},
		{name: "goversion-unpinned", migrated: true, messages: []string{
			"added go-package: go-1.26 to go/build (pipeline, modroot .)",
			"added go-package: go-1.26 to go/build (subpackage example-cli, modroot .)",
			"dropped go-version 1.26.8"}},
		{name: "goversion-templated", messages: []string{"not migrated to uses: bump: go-version \"${{vars.go-version}}\" does not map"}},
		{name: "goversion-nobuild", messages: []string{"not migrated to uses: bump: go-version \"1.26.5\" cannot be expressed as a go-package pin: no go/build or go/install step"}},
		{name: "goversion-envpin", migrated: true, messages: []string{"Go version expressed by environment package go-1.26"}},
		{name: "tidy-false", baselineTidies: true, migrated: true, messages: []string{"tidy: false may no longer be needed (omnibump tidies without -go"}},
		{name: "replaces", migrated: true, messages: []string{"with 1 dependencies and 1 replaces"}},
		{name: "work", messages: []string{"not migrated to uses: bump: work: true has no uses: bump equivalent"}},
		{name: "options", migrated: true, messages: []string{"migrated pipeline[1]"}},
		{name: "multi", unchanged: []string{"cli"}, migrated: true, messages: []string{"migrated pipeline[1]"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inPath := filepath.Join("testdata", "migrate", tc.name+".in.yaml")
			goldenPath := filepath.Join("testdata", "migrate", tc.name+".golden.yaml")
			in, err := os.ReadFile(inPath)
			require.NoError(t, err)

			analysis, cfg := migrationAnalysis(t, string(in), bumpedEntry, tc.baselineTidies, tc.unchanged...)
			gp := runApplier(t, string(in), analysis, cfg)
			out := gp.GetCurrentYAML()

			if *updateGolden {
				require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
			}
			golden, err := os.ReadFile(goldenPath)
			require.NoError(t, err)
			assert.Equal(t, string(golden), string(out))

			msgs := strings.Join(gp.GetMessages(), "\n")
			for _, want := range tc.messages {
				assert.Contains(t, msgs, want)
			}
			assert.Equal(t, tc.migrated, strings.Contains(msgs, "migrated pipeline["), "messages:\n%s", msgs)
			if !tc.baselineTidies {
				assert.NotContains(t, msgs, "may no longer be needed")
			}

			// The written file is valid melange and still parses as before.
			outPath := filepath.Join(t.TempDir(), "out.yaml")
			require.NoError(t, os.WriteFile(outPath, out, 0o644))
			_, err = melange.ParseConfiguration(t.Context(), outPath)
			require.NoError(t, err)

			// No advisory was credited (no SecurityBumpModules): the rewrite
			// - migration included - must not bump the epoch.
			assert.True(t, gp.ActualChangesApplied)
			assert.Empty(t, gp.SecurityFixes)
			assert.False(t, epochWouldBump(t, gp), "a rewrite without fixes never bumps the epoch")

			// Second run over the written file: nothing left to change.
			again, cfg2 := migrationAnalysis(t, string(out), func(s string) string { return s }, tc.baselineTidies)
			assert.Empty(t, again.BumpActions)
			gp2 := newTestProcessor(t, string(out))
			gp2.Config = cfg2
			require.NoError(t, NewGoBumpApplier(nil).reconcileBumpSteps(t.Context(), gp2, again, config.NewLoader()))
			assert.Equal(t, string(out), string(gp2.GetCurrentYAML()), "a second run is a no-op")
			assert.False(t, gp2.ActualChangesApplied)
		})
	}
}

// TestMigration_UnchangedStepNotTouched: a go/bump step whose result is "up
// to date" is not rewritten - no drive-by migration.
func TestMigration_UnchangedStepNotTouched(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("testdata", "migrate", "goversion-unpinned.in.yaml"))
	require.NoError(t, err)
	analysis, cfg := migrationAnalysis(t, string(in), bumpedEntry, false, ".")
	require.Empty(t, analysis.BumpActions)
	analysis.BumpActions = []BumpAction{{Action: "needs_bump", Language: "go", Modroots: []string{"."}}} // force the applier to run
	gp := runApplier(t, string(in), analysis, cfg)
	assert.Equal(t, string(in), string(gp.GetCurrentYAML()))
	assert.False(t, gp.ActualChangesApplied)
}

// TestMigration_EngineChosenBeforeSimulation: the simulated engine is the
// one the written step will run - omnibump for a go/bump step that will
// migrate (with the Go minor its new pin selects), gobump for one that
// cannot.
func TestMigration_EngineChosenBeforeSimulation(t *testing.T) {
	for name, want := range map[string]struct {
		migrating bool
		goMinor   string
	}{
		"plain":               {migrating: true},
		"goversion-unpinned":  {migrating: true, goMinor: "1.26"},
		"goversion-envpin":    {migrating: true, goMinor: "1.26"},
		"goversion-templated": {},
		"work":                {},
	} {
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join("testdata", "migrate", name+".in.yaml"))
			require.NoError(t, err)
			analysis, _ := migrationAnalysis(t, string(in), bumpedEntry, false)
			m := analysis.ByLanguage[0].ByModroot[0]
			assert.Equal(t, want.migrating, m.BumpMigrating)
			assert.Equal(t, want.migrating, m.BumpEngine.String() == "omnibump")
			assert.Equal(t, want.goMinor, m.GoPackageMinor)
		})
	}
}

// TestMigration_UnvalidatedStepNotMigrated: without a simulation (or with
// the simulation degraded) a go/bump step keeps its action.
func TestMigration_UnvalidatedStepNotMigrated(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("testdata", "migrate", "plain.in.yaml"))
	require.NoError(t, err)
	analysis, cfg := migrationAnalysis(t, string(in), bumpedEntry, false)
	analysis.ByLanguage[0].ByModroot[0].Simulated = false
	gp := runApplier(t, string(in), analysis, cfg)
	out := string(gp.GetCurrentYAML())
	assert.Contains(t, out, "- uses: go/bump # legacy wrapper")
	assert.Contains(t, out, "golang.org/x/net@v0.56.0")
	messagesContain(t, gp, "not migrated to uses: bump: modroot . was not validated with the omnibump engine")
}

// epochWouldBump evaluates the real pipeline's epoch stage gate for gp.
func epochWouldBump(t *testing.T, gp *GoBumpProcessor) bool {
	t.Helper()
	for _, stage := range NewGoBumpPipeline(NewAnalyzer(nil), ProcessorOptions{}).Stages {
		if stage.Name() != "epoch" {
			continue
		}
		run, err := stage.ShouldRun(t.Context(), processor.Processor(gp))
		require.NoError(t, err)
		return run
	}
	t.Fatal("no epoch stage")
	return false
}
