package gobump

import (
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runApplyPhase runs the apply phase's three steps directly, without
// ShouldRun gating - the Go-only go-version fallback, the applier and the
// Go-only go-package pin reconciliation, in pipeline order.
func runApplyPhase(t *testing.T, gp *Processor, analysis *VulnerabilityAnalysis) error {
	t.Helper()
	if err := NewGoVersionFallbackStage(nil).fallbackGoVersions(t.Context(), gp, analysis); err != nil {
		return err
	}
	if err := NewApplier(nil).applyChanges(t.Context(), gp, analysis); err != nil {
		return err
	}
	return NewGoPackagePinStage(nil).reconcileGoPackagePins(t.Context(), gp, goPinFloors(analysis))
}

// TestNewPipeline_StageOrder pins the stage order: the go-version
// fallback before the applier (its RequiredGoVersion feeds
// fastPathGoVersion and the pin floors), the go-package pin stage after the
// applier (it edits the rewritten YAML) and before the stdlib stage (which
// reads RaisedPinMinors).
func TestNewPipeline_StageOrder(t *testing.T) {
	pipeline := NewPipeline(NewAnalyzer(nil), Options{})
	names := make([]string, 0, len(pipeline.Stages))
	for _, stage := range pipeline.Stages {
		names = append(names, stage.Name())
	}
	assert.Equal(t, []string{
		"vulnerability_check",
		"bump_simulation",
		"go_version_fallback",
		"bump_apply",
		"go_package_pins",
		"stdlib_check",
		"apk_advisories",
		"epoch",
		"validation",
		"file_writer",
	}, names)
	assert.True(t, pipeline.Options.StopOnError, "a failing stage (e.g. the pin stage) stops the run")
}

// shouldRunAnalysis builds a one-language, one-modroot analysis with the
// apply gate open (a vulnerability and a bump action).
func shouldRunAnalysis(language string, m ModrootAnalysis) *VulnerabilityAnalysis {
	return &VulnerabilityAnalysis{
		VulnerabilitiesFound: 1,
		ByLanguage:           []LanguageAnalysis{{Language: language, ByModroot: []ModrootAnalysis{m}}},
		BumpActions:          []BumpAction{{Action: "needs_bump", Language: language, Modroots: []string{m.Modroot}}},
	}
}

// TestGoStages_ShouldRun: each Go-only stage runs exactly when its code ran
// inside the applier before: the fallback for Go modroots the simulation
// did not prove (validated ones are skipped), the pin stage whenever the
// applier runs and there are Go modroots - whether or not the applier
// changed anything - and neither for other languages or without bump actions.
func TestGoStages_ShouldRun(t *testing.T) {
	desired := []string{"golang.org/x/net@v0.56.0"}
	tests := []struct {
		name         string
		analysis     *VulnerabilityAnalysis
		wantApplier  bool
		wantFallback bool
		wantPins     bool
	}{
		{name: "no analysis", analysis: nil},
		{name: "go, no vulnerabilities", analysis: func() *VulnerabilityAnalysis {
			a := shouldRunAnalysis("go", ModrootAnalysis{Modroot: ".", DesiredDeps: desired})
			a.VulnerabilitiesFound = 0
			return a
		}()},
		{name: "go, no bump actions", analysis: func() *VulnerabilityAnalysis {
			a := shouldRunAnalysis("go", ModrootAnalysis{Modroot: ".", DesiredDeps: desired})
			a.BumpActions = nil
			return a
		}()},
		{name: "go, validated by simulation",
			analysis:    shouldRunAnalysis("go", ModrootAnalysis{Modroot: ".", DesiredDeps: desired, Simulated: true}),
			wantApplier: true, wantPins: true},
		{name: "go, degraded or --no-validate",
			analysis:    shouldRunAnalysis("go", ModrootAnalysis{Modroot: ".", DesiredDeps: desired}),
			wantApplier: true, wantFallback: true, wantPins: true},
		{name: "go, degraded, replaces only",
			analysis:    shouldRunAnalysis("go", ModrootAnalysis{Modroot: ".", DesiredReplaces: []string{"a=b@v1.0.0"}}),
			wantApplier: true, wantFallback: true, wantPins: true},
		{name: "go, degraded, required version already known",
			analysis:    shouldRunAnalysis("go", ModrootAnalysis{Modroot: ".", DesiredDeps: desired, RequiredGoVersion: "1.26"}),
			wantApplier: true, wantPins: true},
		{name: "go, degraded, nothing desired (no Go bumps to apply)",
			analysis:    shouldRunAnalysis("go", ModrootAnalysis{Modroot: "."}),
			wantApplier: true, wantPins: true},
		{name: "rust, unvalidated",
			analysis:    shouldRunAnalysis("rust", ModrootAnalysis{Modroot: ".", DesiredDeps: []string{"serde@1.0.1"}}),
			wantApplier: true},
		{name: "java, unvalidated",
			analysis:    shouldRunAnalysis("java", ModrootAnalysis{Modroot: ".", DesiredDeps: []string{"g@a@1.0.1"}}),
			wantApplier: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gp := NewProcessor("/test/example.yaml", "example", "1.0.0", 0)
			gp.VulnerabilityAnalysis = tt.analysis
			for _, check := range []struct {
				stage processor.Stage
				want  bool
			}{
				{NewApplier(nil), tt.wantApplier},
				{NewGoVersionFallbackStage(nil), tt.wantFallback},
				{NewGoPackagePinStage(nil), tt.wantPins},
			} {
				got, err := check.stage.ShouldRun(t.Context(), gp)
				require.NoError(t, err)
				assert.Equal(t, check.want, got, check.stage.Name())
			}
		})
	}
}

// runApplyStages runs the fallback, applier and pin stages through their
// ShouldRun/Apply, as the pipeline does.
func runApplyStages(t *testing.T, gp *Processor) {
	t.Helper()
	for _, stage := range []interface {
		processor.Stage
		processor.ApplyStage
	}{NewGoVersionFallbackStage(nil), NewApplier(nil), NewGoPackagePinStage(nil)} {
		run, err := stage.ShouldRun(t.Context(), gp)
		require.NoError(t, err)
		if run {
			require.NoError(t, stage.Apply(t.Context(), gp))
		}
	}
}

// TestApplyPhase_OutcomeMessageLast: the apply phase's outcome message is
// reported once, after the pin stage's messages when that stage runs (a pin
// raise alone is an applied change) and by the applier otherwise.
func TestApplyPhase_OutcomeMessageLast(t *testing.T) {
	t.Run("go: after the pin raise", func(t *testing.T) {
		const yamlContent = `package:
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

  - uses: bump
    with:
      deps: |-
        golang.org/x/net@v0.56.0
`
		gp := newTestProcessor(t, yamlContent)
		gp.Config = &melange.Configuration{}
		gp.VulnerabilityAnalysis = shouldRunAnalysis("go", ModrootAnalysis{
			Modroot:           ".",
			ExistingDeps:      []string{"golang.org/x/net@v0.56.0"},
			DesiredDeps:       []string{"golang.org/x/net@v0.56.0"},
			RequiredGoVersion: "1.26",
			Simulated:         true,
		})
		runApplyStages(t, gp)

		messages := gp.GetMessages()
		require.GreaterOrEqual(t, len(messages), 2)
		assert.Contains(t, messages[len(messages)-2], "raised go-package pin go-1.22 -> go-1.26")
		assert.Equal(t, "bump changes applied", messages[len(messages)-1], "deps unchanged: the pin raise alone is the applied change")
		assert.Contains(t, string(gp.GetCurrentYAML()), "go-package: go-1.26")
	})

	t.Run("rust: from the applier", func(t *testing.T) {
		const yamlContent = `package:
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
        serde@1.0.1
`
		gp := newTestProcessor(t, yamlContent)
		gp.VulnerabilityAnalysis = shouldRunAnalysis("rust", ModrootAnalysis{
			Modroot:      ".",
			ExistingDeps: []string{"serde@1.0.1"},
			DesiredDeps:  []string{"serde@1.0.2"},
		})
		runApplyStages(t, gp)

		messages := gp.GetMessages()
		require.NotEmpty(t, messages)
		assert.Equal(t, "bump changes applied", messages[len(messages)-1])
		assert.Equal(t, 1, countMessage(messages, "bump changes applied"))
		assert.Contains(t, string(gp.GetCurrentYAML()), "serde@1.0.2")
		assert.Nil(t, gp.RaisedPinMinors, "the pin stage did not run")
	})
}

func countMessage(messages []string, want string) int {
	n := 0
	for _, m := range messages {
		if m == want {
			n++
		}
	}
	return n
}
