package gobump

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/logging"
)

// applyChanges reconciles the package's bump/go-bump pipeline steps
// with the desired per-modroot dependency sets computed during the check
// phase. (The Go-only stages around it - GoVersionFallbackStage before,
// GoPackagePinStage after - handle go-version and go-package pins.)
func (g *Applier) applyChanges(ctx context.Context, gp *Processor, analysis *VulnerabilityAnalysis) error {
	if len(analysis.BumpActions) == 0 {
		logging.From(ctx).Debug("skipping apply - no actions to apply")
		return nil
	}

	loader := newMelangeLoader()

	if err := g.reconcileBumpSteps(ctx, gp, analysis, loader); err != nil {
		return fmt.Errorf("reconciling bump steps: %w", err)
	}

	return nil
}

// reconcileBumpSteps writes the desired per-modroot dependency sets back into
// the package's bump/go-bump pipeline steps, one language at a time (see
// reconcileLanguageBumpSteps).
func (g *Applier) reconcileBumpSteps(ctx context.Context, gp *Processor, analysis *VulnerabilityAnalysis, loader *config.Loader) error {
	for _, langAnalysis := range analysis.ByLanguage {
		if len(langAnalysis.ByModroot) == 0 {
			continue
		}
		if err := g.reconcileLanguageBumpSteps(ctx, gp, langAnalysis, loader); err != nil {
			return fmt.Errorf("reconciling %s bump steps: %w", langAnalysis.Language, err)
		}
	}
	return nil
}

// stepEdit is one existing bump step's reconciliation: the modroots it owns
// (it is the first step covering them) grouped by identical desired
// deps/replaces.
type stepEdit struct {
	step    config.BumpStep
	groups  []modrootGroup
	owned   []*ModrootAnalysis
	changed bool
}

// reconcileLanguageBumpSteps writes one language's desired per-modroot
// dependency sets back into its own bump/go-bump pipeline steps, leaving
// every other language's steps untouched.
//
// Existing steps are edited IN PLACE: each keeps its position, its comments
// and every `with:` option choam does not manage (tidy, tidy-compat, work,
// show-diff, name, if, ...); only deps/replaces (and, for a migrated go/bump
// step, uses/language/go-version - see migrateStep) change. A step is only
// touched when its own content changes. Each analyzed modroot belongs to the
// first step covering it; a multi-modroot step whose roots now diverge keeps
// the first group and gets a clone (same options) per further group directly
// after it; roots left with nothing to declare leave the step's modroot list,
// and a step left with nothing at all is removed. Existing steps are never
// merged. Modroots no step covers get fresh `uses: bump` steps (coalesced by
// identical sets) after the first git-checkout. Deps are written in the
// order the simulation applied them (see simulate.ModrootResult.FinalDeps).
func (g *Applier) reconcileLanguageBumpSteps(ctx context.Context, gp *Processor, langAnalysis LanguageAnalysis, loader *config.Loader) error {
	yamlContent := gp.GetCurrentYAML()
	existingSteps, err := stepsForLanguage(loader, yamlContent, langAnalysis.Language)
	if err != nil {
		return err
	}

	owner := stepOwners(existingSteps)
	edits := planEdits(existingSteps, langAnalysis, owner)

	hasBlankLines := loader.HasBlankLinesBetweenPipelineSteps(yamlContent)
	yamlContent, edited, err := g.applyEdits(ctx, gp, yamlContent, edits, hasBlankLines)
	if err != nil {
		return err
	}
	yamlContent, inserted, err := insertUnowned(gp, loader, yamlContent, langAnalysis, owner, hasBlankLines)
	if err != nil {
		return err
	}

	if !edited && !inserted {
		return nil
	}
	gp.SetCurrentYAML(yamlContent)
	gp.MarkActualChangesApplied()
	g.recordSecurityFixes(gp, langAnalysis, addedAcrossRoots(langAnalysis.ByModroot))
	recordHygieneBumps(gp, langAnalysis)
	return nil
}

// stepsForLanguage returns the bump steps in yamlContent whose effective
// language is language, in document order.
func stepsForLanguage(loader *config.Loader, yamlContent []byte, language string) ([]config.BumpStep, error) {
	allSteps, err := loader.FindBumpSteps(yamlContent)
	if err != nil {
		return nil, fmt.Errorf("finding existing bump steps: %w", err)
	}
	var steps []config.BumpStep
	for _, step := range allSteps {
		if step.EffectiveLanguage() == language {
			steps = append(steps, step)
		}
	}
	return steps, nil
}

// stepOwners maps each modroot to the index (in steps) of the first step
// covering it.
func stepOwners(steps []config.BumpStep) map[string]int {
	owner := make(map[string]int)
	for i, step := range steps {
		for _, root := range step.Modroots {
			if _, ok := owner[root]; !ok {
				owner[root] = i
			}
		}
	}
	return owner
}

// planEdits builds one stepEdit per existing step owning at least one
// analyzed modroot, in step order: its owned modroots grouped by identical
// desired deps/replaces, and whether its content changes.
func planEdits(existingSteps []config.BumpStep, langAnalysis LanguageAnalysis, owner map[string]int) []stepEdit {
	byRoot := make(map[string]*ModrootAnalysis, len(langAnalysis.ByModroot))
	for i := range langAnalysis.ByModroot {
		byRoot[langAnalysis.ByModroot[i].Modroot] = &langAnalysis.ByModroot[i]
	}

	edits := make([]stepEdit, 0, len(existingSteps))
	for i, step := range existingSteps {
		edit := stepEdit{step: step}
		analyzed := false
		for _, root := range step.Modroots {
			if owner[root] != i {
				continue
			}
			m, ok := byRoot[root]
			if !ok {
				// Not analyzed (its manifest could not be fetched or
				// parsed): it keeps exactly what the step declares today.
				m = &ModrootAnalysis{Modroot: root, ExistingDeps: step.Deps, DesiredDeps: step.Deps,
					ExistingReplaces: step.Replaces, DesiredReplaces: step.Replaces}
			} else {
				analyzed = true
			}
			edit.owned = append(edit.owned, m)
		}
		if !analyzed {
			continue
		}
		ownedAnalyses := make([]ModrootAnalysis, len(edit.owned))
		for j, m := range edit.owned {
			ownedAnalyses[j] = *m
		}
		edit.groups = coalesceModroots(ownedAnalyses)
		switch len(edit.groups) {
		case 0:
			edit.changed = len(step.Deps) > 0 || len(step.Replaces) > 0
		case 1:
			group := edit.groups[0]
			edit.changed = !sameRootSet(group.Modroots, step.Modroots) ||
				haveDepsChanged(step.Deps, group.Deps) || haveDepsChanged(step.Replaces, group.Replaces)
		default:
			edit.changed = true
		}
		edits = append(edits, edit)
	}
	return edits
}

// applyEdits rewrites every changed edit's step, from the last step
// backwards: removals and clones only shift the indices of steps already
// handled. Reports whether anything changed.
func (g *Applier) applyEdits(ctx context.Context, gp *Processor, yamlContent []byte, edits []stepEdit, hasBlankLines bool) ([]byte, bool, error) {
	slices.SortFunc(edits, func(a, b stepEdit) int { return cmp.Compare(b.step.Index, a.step.Index) })
	changed := false
	for _, edit := range edits {
		if !edit.changed {
			continue
		}
		updated, err := g.rewriteStep(ctx, gp, yamlContent, edit, hasBlankLines)
		if err != nil {
			return nil, false, err
		}
		yamlContent = updated
		changed = true
	}
	return yamlContent, changed, nil
}

// insertUnowned adds fresh `uses: bump` steps (coalesced by identical sets)
// after the first git-checkout for the modroots no existing step covers.
// Reports whether anything was inserted.
func insertUnowned(gp *Processor, loader *config.Loader, yamlContent []byte, langAnalysis LanguageAnalysis, owner map[string]int, hasBlankLines bool) ([]byte, bool, error) {
	var unowned []ModrootAnalysis
	for _, m := range langAnalysis.ByModroot {
		if _, ok := owner[m.Modroot]; !ok {
			unowned = append(unowned, m)
		}
	}
	groups := coalesceModroots(unowned)
	if len(groups) == 0 {
		return yamlContent, false, nil
	}
	gitCheckoutIndices, err := loader.FindPipelinesByUse(yamlContent, "git-checkout")
	if err != nil {
		return nil, false, fmt.Errorf("finding git-checkout pipeline: %w", err)
	}
	insertPos := 0
	if len(gitCheckoutIndices) > 0 {
		insertPos = gitCheckoutIndices[0] + 1
	}
	for _, group := range groups {
		spec := config.BumpStepSpec{
			Action:   "bump",
			Language: langAnalysis.Language,
			Modroots: group.Modroots,
			Deps:     group.Deps,
			Replaces: group.Replaces,
		}
		updated, err := loader.InsertBumpPipelineStep(yamlContent, insertPos, spec, hasBlankLines)
		if err != nil {
			return nil, false, fmt.Errorf("inserting bump step: %w", err)
		}
		yamlContent = updated
		gp.AddMessage(fmt.Sprintf("Added %s bump step pipeline[%d] for modroot(s) %s with %d dependencies and %d replaces",
			langAnalysis.Language, insertPos, strings.Join(group.Modroots, ", "), len(group.Deps), len(group.Replaces)))
		insertPos++
	}
	return yamlContent, true, nil
}

// rewriteStep applies one changed stepEdit in place (see
// reconcileLanguageBumpSteps): removal when nothing is left, else the first
// group's deps/replaces/modroot on the step itself - a go/bump step, or a
// step carrying a stale go-version, through goStepRewrite - and one clone
// per further group.
func (g *Applier) rewriteStep(ctx context.Context, gp *Processor, yamlContent []byte, edit stepEdit, hasBlankLines bool) ([]byte, error) {
	loader := config.NewLoader()
	step := edit.step
	if len(edit.groups) == 0 {
		updated, err := loader.RemovePipelineStep(yamlContent, step.Index)
		if err != nil {
			return nil, fmt.Errorf("removing %s pipeline[%d]: %w", step.Action, step.Index, err)
		}
		gp.AddMessage(fmt.Sprintf("Removed %s pipeline[%d]: no dependencies or replaces left to declare", step.Action, step.Index))
		return updated, nil
	}

	first := edit.groups[0]
	var updated []byte
	var err error
	if step.Action == "go/bump" || step.GoVersion != "" {
		updated, err = g.goStepRewrite(ctx, gp, loader, yamlContent, edit)
	} else {
		updated, err = updateStepInPlace(loader, yamlContent, step, first, "")
	}
	if err != nil {
		return nil, err
	}
	gp.AddMessage(fmt.Sprintf("Updated %s pipeline[%d] in place with %d dependencies and %d replaces", step.Action, step.Index, len(first.Deps), len(first.Replaces)))

	// Further groups: clones of the rewritten step, in group order.
	for gi := len(edit.groups) - 1; gi >= 1; gi-- {
		group := edit.groups[gi]
		if updated, err = loader.ClonePipelineStepAfter(updated, step.Index, hasBlankLines); err != nil {
			return nil, fmt.Errorf("splitting pipeline[%d]: %w", step.Index, err)
		}
		clone := step.Index + 1
		if updated, err = loader.UpdateBumpStep(updated, clone, group.Deps, group.Replaces, ""); err != nil {
			return nil, fmt.Errorf("updating split of pipeline[%d]: %w", step.Index, err)
		}
		if updated, err = loader.SetBumpModroots(updated, clone, group.Modroots); err != nil {
			return nil, fmt.Errorf("updating modroot of split of pipeline[%d]: %w", step.Index, err)
		}
		gp.AddMessage(fmt.Sprintf("Split pipeline[%d]: modroot(s) %s now diverge, written to a copy of the step with %d dependencies and %d replaces",
			step.Index, strings.Join(group.Modroots, ", "), len(group.Deps), len(group.Replaces)))
	}
	return updated, nil
}

// updateStepInPlace writes group's deps/replaces (and goVersion, when
// non-empty) into the step, and its modroot list when that changed.
func updateStepInPlace(loader *config.Loader, yamlContent []byte, step config.BumpStep, group modrootGroup, goVersion string) ([]byte, error) {
	updated, err := loader.UpdateBumpStep(yamlContent, step.Index, group.Deps, group.Replaces, goVersion)
	if err != nil {
		return nil, fmt.Errorf("updating %s pipeline[%d]: %w", step.Action, step.Index, err)
	}
	if !sameRootSet(group.Modroots, step.Modroots) {
		if updated, err = loader.SetBumpModroots(updated, step.Index, group.Modroots); err != nil {
			return nil, fmt.Errorf("updating modroot of %s pipeline[%d]: %w", step.Action, step.Index, err)
		}
	}
	return updated, nil
}

// modrootGroup is a set of modroots that share identical desired dependency
// and replace sets.
type modrootGroup struct {
	Modroots []string
	Deps     []string
	Replaces []string
}

// coalesceModroots groups modroots that end up with identical desired
// dependency AND replace sets (compared as sets) into a single step, in
// first-seen order. A group's lists keep its first modroot's order (the
// order the simulation applied them in). Roots with neither desired deps nor
// replaces are omitted entirely.
func coalesceModroots(byModroot []ModrootAnalysis) []modrootGroup {
	var order []string
	byKey := make(map[string]*modrootGroup)

	for _, m := range byModroot {
		if len(m.DesiredDeps) == 0 && len(m.DesiredReplaces) == 0 {
			continue
		}
		key := groupKey(m.DesiredDeps) + "\x00" + groupKey(m.DesiredReplaces)
		group, ok := byKey[key]
		if !ok {
			group = &modrootGroup{Deps: slices.Clone(m.DesiredDeps), Replaces: slices.Clone(m.DesiredReplaces)}
			byKey[key] = group
			order = append(order, key)
		}
		group.Modroots = append(group.Modroots, m.Modroot)
	}

	groups := make([]modrootGroup, 0, len(order))
	for _, key := range order {
		groups = append(groups, *byKey[key])
	}
	return groups
}

// groupKey returns an order-independent key for a set of rendered dep entries.
func groupKey(deps []string) string {
	return strings.Join(sortedCopy(deps), "\n")
}

func sortedCopy(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

// sameRootSet reports whether two modroot lists contain the same set of roots (order-independent).
func sameRootSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	return slices.Equal(sortedCopy(a), sortedCopy(b))
}
