package gobump

import (
	"context"
	"fmt"
	"slices"

	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/simulate"
)

// goStepRewrite is the Go-only part of rewriteStep: the in-place update of a
// `uses: go/bump` step's first group - migrating it to `uses: bump` when it
// can (see migrationFor), else raising its go-version when the group needs a
// higher one (see fastPathGoVersion) - and, for a `uses: bump` step, the
// removal of a stale go-version (the bump pipeline has no such input).
func (g *GoBumpApplier) goStepRewrite(ctx context.Context, gp *GoBumpProcessor, loader *config.Loader, yamlContent []byte, edit stepEdit) ([]byte, error) {
	step, first := edit.step, edit.groups[0]
	if step.Action != "go/bump" {
		updated, err := updateStepInPlace(loader, yamlContent, step, first, "")
		if err != nil {
			return nil, err
		}
		if updated, err = loader.RemovePipelineWithFieldLines(updated, step.Index, "go-version"); err != nil {
			return nil, fmt.Errorf("removing go-version from %s pipeline[%d]: %w", step.Action, step.Index, err)
		}
		return updated, nil
	}

	migrate, plan := g.migrationFor(ctx, gp, yamlContent, edit)
	var goVersion string
	if !migrate {
		goVersion = g.fastPathGoVersion(gp, step, maxEffectiveGoVersion(edit.owned))
	}
	updated, err := updateStepInPlace(loader, yamlContent, step, first, goVersion)
	if err != nil {
		return nil, err
	}
	if !migrate {
		return updated, nil
	}
	if updated, err = migrateStep(gp, updated, step, plan); err != nil {
		return nil, fmt.Errorf("migrating go/bump pipeline[%d]: %w", step.Index, err)
	}
	if step.NoTidy && anyBaselineTidies(edit.owned) {
		gp.AddMessage(fmt.Sprintf("pipeline[%d]: tidy: false may no longer be needed (omnibump tidies without -go; the upstream module tidies under omnibump) - left as written", step.Index))
	}
	return updated, nil
}

// migrationFor decides whether a go/bump step being rewritten migrates to
// `uses: bump`: its plan allows it (see planMigration) AND every modroot it
// owns was simulated with the omnibump engine - so what is written is what
// was validated. A step that does not migrate gets a message saying why.
func (g *GoBumpApplier) migrationFor(ctx context.Context, gp *GoBumpProcessor, yamlContent []byte, edit stepEdit) (bool, migrationPlan) {
	step := edit.step
	plan := planMigration(ctx, yamlContent, step, g.Analyzer.releaseIndex())
	if !plan.ok {
		gp.AddMessage(fmt.Sprintf("go/bump pipeline[%d] not migrated to uses: bump: %s", step.Index, plan.reason))
		return false, plan
	}
	for _, m := range edit.owned {
		if !m.Simulated || m.BumpEngine != simulate.EngineOmnibump {
			gp.AddMessage(fmt.Sprintf("go/bump pipeline[%d] not migrated to uses: bump: modroot %s was not validated with the omnibump engine", step.Index, m.Modroot))
			return false, plan
		}
	}
	return true, plan
}

// anyBaselineTidies reports whether any of the modroots tidies under omnibump.
func anyBaselineTidies(roots []*ModrootAnalysis) bool {
	for _, m := range roots {
		if m.BaselineTidies {
			return true
		}
	}
	return false
}

// fastPathGoVersion decides the go-version argument for the in-place update
// of a go/bump step that is not migrated: the group's effective value when
// it genuinely raises the step's current one, "" (leave the field untouched,
// byte-for-byte) when the step already carries an equal-or-higher value - so
// re-running the applier on already-updated YAML never churns it, and an
// existing value is NEVER lowered. A step value goversion can't order
// (templated expression) is warned about, never overwritten.
func (g *GoBumpApplier) fastPathGoVersion(gp *GoBumpProcessor, step config.BumpStep, effective string) string {
	if effective == "" {
		return ""
	}
	switch {
	case step.GoVersion == "":
		return effective
	case !goversion.IsValid(step.GoVersion):
		gp.AddMessage(fmt.Sprintf("%s pipeline[%d] go-version %q is not a plain version (templated?); required Go %s - not rewritten, update it manually",
			step.Action, step.Index, step.GoVersion, effective))
		return ""
	case goversion.Compare(effective, step.GoVersion) > 0:
		return effective
	default:
		return ""
	}
}

// effectiveGoVersion is the go-version a modroot's go/bump step should end
// up carrying: the max of what its existing steps already declare and what
// the proven/probed candidate set requires. Max never picks the lower of two
// valid values, so an existing value is never lowered. "" for non-Go
// modroots (both fields are Go-only) and when neither side has a value.
func effectiveGoVersion(m ModrootAnalysis) string {
	return goversion.Max(m.ExistingGoVersion, m.RequiredGoVersion)
}

// maxEffectiveGoVersion returns the highest effective go-version
// (effectiveGoVersion) across the given modroots, "" if none has one: a step
// covering several roots must satisfy all of them, and go-version is a floor,
// so raising to the maximum is always safe - fastPathGoVersion still
// enforces never-lower against the step's current value on top of this.
func maxEffectiveGoVersion(roots []*ModrootAnalysis) string {
	var max string
	for _, m := range roots {
		max = goversion.Max(max, effectiveGoVersion(*m))
	}
	return max
}

// existingGoVersionsForModroots returns, for each modroot, the highest
// with.go-version carried by any existing go/bump step that covers it (""
// when none). It mirrors existingDepsForModroots' matching semantics (a step
// covers a root when its modroot list contains it), but only go/bump steps
// count: go-version is a gobump input, and the `uses: bump` pipeline has no
// such input (omnibump never sees it). Values goversion can't order
// (templated expressions) are ignored here; the reconciler warns about them
// instead of editing (see fastPathGoVersion). Only go/bump steps that are not
// migrated to `uses: bump` keep and raise their go-version.
func existingGoVersionsForModroots(modroots []string, bumpSteps []config.BumpStep) map[string]string {
	result := make(map[string]string, len(modroots))
	for _, root := range modroots {
		var highest string
		for _, step := range bumpSteps {
			if step.Action != "go/bump" || step.GoVersion == "" || !slices.Contains(step.Modroots, root) {
				continue
			}
			highest = goversion.Max(highest, step.GoVersion)
		}
		result[root] = highest
	}
	return result
}
