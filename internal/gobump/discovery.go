package gobump

import (
	"context"
	"sort"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/simulate"
)

// buildStepSignals maps a melange build-pipeline "uses:" name to the
// language it signals, for languages whose pipeline supports declaring an
// explicit with.modroot (verified against melange's own pipeline
// definitions). There is no equivalent Java build pipeline in melange's
// vendor tree (only maven/configure-mirror and maven/pombump, neither of
// which builds), so Java has no structured-signal source here.
var buildStepSignals = map[string]string{
	"go/build":    "go",
	"cargo/build": "rust",
}

// annotationPrefix is the package.annotations key prefix for a language's
// explicit bump opt-in, e.g. "choam/bump-rust: cmd/foo,.". This is the
// signal for packages whose pipeline has no structured build step to infer
// a modroot from (e.g. one that just shells out via a raw `runs:` block).
// The value is deliberately just a comma-separated modroot list - build
// package patterns are NOT expressible here (wedging a second per-modroot
// list into one annotation value has no clean grammar); annotation-declared
// modroots simply get the ./... reachability fallback.
const annotationPrefix = "choam/bump-"

// analysisUnit is one modroot to analyze plus the build package patterns
// (relative to the modroot, in go/build's space-separated with.packages
// grammar) observed across every build step sharing that modroot. Empty
// Packages means no build step declared any - artifact reachability then
// over-approximates with ./... (safe: never narrower than the artifact).
type analysisUnit struct {
	Modroot  string
	Packages []string
	// Tags are the build tags of the go/build steps sharing the modroot
	// (toolchaintags, default netgo,osusergo, plus tags), unioned.
	Tags []string
	// Engine is the apply semantics of the bump step the build will run for
	// the modroot once choam writes it: omnibump for a `uses: bump` step, for
	// a root no step covers yet (new steps are `uses: bump`) and for a
	// `uses: go/bump` step choam will migrate when it rewrites it (see
	// planMigration); gobump only for a go/bump step that cannot migrate.
	// Migrating marks the last case's migratable go/bump steps. NoTidy
	// mirrors the covering step's `tidy: false`.
	Engine    simulate.Engine
	Migrating bool
	NoTidy    bool
	// GoMinor is the lowest Go minor the go/build steps building the
	// modroot pin via go-package (e.g. "1.25"), else the Go minor a
	// migration will pin, else a versioned go package in the environment;
	// "" when none is pinned.
	GoMinor string
}

// defaultToolchainTags mirrors melange's go/build toolchaintags default.
const defaultToolchainTags = "netgo,osusergo"

// discoverAnalysisUnits determines, for every registered language, the set
// of modroots to analyze - the union of three additive sources, checked
// every run: (1) modroots already declared on existing bump/go-bump steps,
// (2) go/build and cargo/build steps' with.modroot across the top-level
// pipeline and every subpackage's pipeline (also capturing their
// with.packages build patterns), and (3) package.annotations explicit
// opt-ins. Returns language -> units sorted by modroot; a language absent
// from the result had no modroots from any source. migrations are the
// go/bump steps' migration plans by pipeline index (see planMigration).
func discoverAnalysisUnits(ctx context.Context, cfg *melange.Configuration, bumpSteps []config.BumpStep, migrations map[int]migrationPlan) map[string][]analysisUnit {
	// language -> modroot -> sets of build package patterns and tags
	type unitSets struct {
		patterns, tags map[string]struct{}
		step           *config.BumpStep // first bump step covering the root
		goMinor        string
	}
	units := make(map[string]map[string]*unitSets)

	add := func(language string, modroots, packages, tags []string) []*unitSets {
		byRoot, ok := units[language]
		if !ok {
			byRoot = make(map[string]*unitSets)
			units[language] = byRoot
		}
		added := make([]*unitSets, 0, len(modroots))
		for _, root := range modroots {
			sets, ok := byRoot[root]
			if !ok {
				sets = &unitSets{patterns: make(map[string]struct{}), tags: make(map[string]struct{})}
				byRoot[root] = sets
			}
			added = append(added, sets)
			for _, pattern := range packages {
				sets.patterns[pattern] = struct{}{}
			}
			for _, tag := range tags {
				sets.tags[tag] = struct{}{}
			}
		}
		return added
	}

	for i := range bumpSteps {
		step := &bumpSteps[i]
		language := step.Language
		if language == "" {
			language = "go" // legacy go/bump and language-less bump steps default to go
		}
		for _, sets := range add(language, step.Modroots, nil, nil) {
			if sets.step == nil {
				sets.step = step
			}
		}
	}

	if cfg != nil {
		for language, buildUnits := range unitsFromBuildSteps(ctx, cfg) {
			for _, unit := range buildUnits {
				for _, sets := range add(language, []string{unit.Modroot}, unit.Packages, unit.Tags) {
					if unit.GoMinor != "" && (sets.goMinor == "" || goversion.Compare(unit.GoMinor, sets.goMinor) < 0) {
						sets.goMinor = unit.GoMinor
					}
				}
			}
		}
		for language, modroots := range modrootsFromAnnotations(cfg) {
			add(language, modroots, nil, nil)
		}
	}

	envMinor := ""
	if cfg != nil {
		for _, pkg := range cfg.Environment.Contents.Packages {
			if _, minor, ok := parseGoPackagePin(pkg); ok && minor != "" {
				envMinor = minor
				break
			}
		}
	}

	result := make(map[string][]analysisUnit, len(units))
	for language, byRoot := range units {
		if len(byRoot) == 0 {
			continue
		}
		langUnits := make([]analysisUnit, 0, len(byRoot))
		for root, sets := range byRoot {
			unit := analysisUnit{Modroot: root, Engine: simulate.EngineOmnibump, GoMinor: sets.goMinor}
			if sets.step != nil {
				unit.NoTidy = sets.step.NoTidy
				if sets.step.Action == "go/bump" {
					if plan := migrations[sets.step.Index]; plan.ok {
						unit.Migrating = true
						if unit.GoMinor == "" {
							unit.GoMinor = plan.goMinor
						}
					} else {
						unit.Engine = simulate.EngineGobump
					}
				}
			}
			if unit.GoMinor == "" && language == "go" {
				unit.GoMinor = envMinor
			}
			for pattern := range sets.patterns {
				unit.Packages = append(unit.Packages, pattern)
			}
			sort.Strings(unit.Packages)
			for tag := range sets.tags {
				unit.Tags = append(unit.Tags, tag)
			}
			sort.Strings(unit.Tags)
			langUnits = append(langUnits, unit)
		}
		sort.Slice(langUnits, func(i, j int) bool { return langUnits[i].Modroot < langUnits[j].Modroot })
		result[language] = langUnits
	}
	return result
}

// unitRoots projects a language's analysis units onto their modroots,
// preserving order.
func unitRoots(units []analysisUnit) []string {
	roots := make([]string, len(units))
	for i, unit := range units {
		roots[i] = unit.Modroot
	}
	return roots
}

// unitsFromBuildSteps walks the top-level pipeline and every subpackage's
// pipeline, collecting with.modroot (default "." to match the pipeline's
// own default when the field is absent) and with.packages from any step
// whose uses: matches a known build-step signal. with.packages values may
// contain melange template expressions, so they're resolved through the
// same renderer git-checkout fields get; a value that fails to render is
// kept raw (a broken pattern later makes reachability fail OPEN - no
// filtering - which is the safe direction).
func unitsFromBuildSteps(ctx context.Context, cfg *melange.Configuration) map[string][]analysisUnit {
	result := make(map[string][]analysisUnit)

	renderer, err := config.NewRenderer(cfg)
	if err != nil {
		logging.From(ctx).Debug("could not build template renderer for build-step discovery", "error", err)
		renderer = nil
	}
	render := func(value string) string {
		if renderer == nil || !strings.Contains(value, "${{") {
			return value
		}
		rendered, err := renderer.RenderString(value)
		if err != nil {
			logging.From(ctx).Debug("could not render build-step field", "value", value, "error", err)
			return value
		}
		return rendered
	}

	collect := func(steps []melange.Pipeline) {
		for _, step := range steps {
			language, ok := buildStepSignals[step.Uses]
			if !ok {
				continue
			}
			modroot := render(step.With["modroot"])
			if modroot == "" {
				modroot = "."
			}
			unit := analysisUnit{
				Modroot:  modroot,
				Packages: strings.Fields(render(step.With["packages"])),
			}
			if step.Uses == "go/build" {
				toolchainTags, set := step.With["toolchaintags"]
				if !set {
					toolchainTags = defaultToolchainTags
				}
				unit.Tags = splitBuildTags(render(toolchainTags) + "," + render(step.With["tags"]))
				if _, minor, ok := parseGoPackagePin(render(step.With["go-package"])); ok {
					unit.GoMinor = minor
				}
			}
			result[language] = append(result[language], unit)
		}
	}

	collect(cfg.Pipeline)
	for _, subpkg := range cfg.Subpackages {
		collect(subpkg.Pipeline)
	}

	return result
}

// splitBuildTags splits go/build's comma-separated tag lists (tolerating
// whitespace), dropping empties.
func splitBuildTags(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

// modrootsFromAnnotations reads package.annotations["choam/bump-<language>"]
// for every registered language, splitting the value on "," (whitespace
// trimmed). A present-but-empty value defaults to ["."], matching the same
// convention build steps and the bump pipeline itself use.
func modrootsFromAnnotations(cfg *melange.Configuration) map[string][]string {
	result := make(map[string][]string)

	if cfg.Package.Annotations == nil {
		return result
	}

	for _, language := range ecosystem.Names() {
		value, ok := cfg.Package.Annotations[annotationPrefix+language]
		if !ok {
			continue
		}

		value = strings.TrimSpace(value)
		if value == "" {
			result[language] = []string{"."}
			continue
		}

		var roots []string
		for root := range strings.SplitSeq(value, ",") {
			root = strings.TrimSpace(root)
			if root != "" {
				roots = append(roots, root)
			}
		}
		if len(roots) > 0 {
			result[language] = roots
		}
	}

	return result
}
