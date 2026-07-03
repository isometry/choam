package gobump

import (
	"log/slog"
	"sort"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/ecosystem"
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
}

// discoverAnalysisUnits determines, for every registered language, the set
// of modroots to analyze - the union of three additive sources, checked
// every run: (1) modroots already declared on existing bump/go-bump steps,
// (2) go/build and cargo/build steps' with.modroot across the top-level
// pipeline and every subpackage's pipeline (also capturing their
// with.packages build patterns), and (3) package.annotations explicit
// opt-ins. Returns language -> units sorted by modroot; a language absent
// from the result had no modroots from any source.
func discoverAnalysisUnits(cfg *melange.Configuration, bumpSteps []config.BumpStep) map[string][]analysisUnit {
	// language -> modroot -> set of build package patterns
	units := make(map[string]map[string]map[string]struct{})

	add := func(language string, modroots, packages []string) {
		byRoot, ok := units[language]
		if !ok {
			byRoot = make(map[string]map[string]struct{})
			units[language] = byRoot
		}
		for _, root := range modroots {
			patterns, ok := byRoot[root]
			if !ok {
				patterns = make(map[string]struct{})
				byRoot[root] = patterns
			}
			for _, pattern := range packages {
				patterns[pattern] = struct{}{}
			}
		}
	}

	for _, step := range bumpSteps {
		language := step.Language
		if language == "" {
			language = "go" // legacy go/bump and language-less bump steps default to go
		}
		add(language, step.Modroots, nil)
	}

	if cfg != nil {
		for language, buildUnits := range unitsFromBuildSteps(cfg) {
			for _, unit := range buildUnits {
				add(language, []string{unit.Modroot}, unit.Packages)
			}
		}
		for language, modroots := range modrootsFromAnnotations(cfg) {
			add(language, modroots, nil)
		}
	}

	result := make(map[string][]analysisUnit, len(units))
	for language, byRoot := range units {
		if len(byRoot) == 0 {
			continue
		}
		langUnits := make([]analysisUnit, 0, len(byRoot))
		for root, patterns := range byRoot {
			unit := analysisUnit{Modroot: root}
			for pattern := range patterns {
				unit.Packages = append(unit.Packages, pattern)
			}
			sort.Strings(unit.Packages)
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
func unitsFromBuildSteps(cfg *melange.Configuration) map[string][]analysisUnit {
	result := make(map[string][]analysisUnit)

	renderer, err := config.NewRenderer(cfg)
	if err != nil {
		slog.Debug("could not build template renderer for build-step discovery", "error", err)
		renderer = nil
	}
	render := func(value string) string {
		if renderer == nil || !strings.Contains(value, "${{") {
			return value
		}
		rendered, err := renderer.RenderString(value)
		if err != nil {
			slog.Debug("could not render build-step field", "value", value, "error", err)
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
			result[language] = append(result[language], analysisUnit{
				Modroot:  modroot,
				Packages: strings.Fields(render(step.With["packages"])),
			})
		}
	}

	collect(cfg.Pipeline)
	for _, subpkg := range cfg.Subpackages {
		collect(subpkg.Pipeline)
	}

	return result
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
		for _, root := range strings.Split(value, ",") {
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
