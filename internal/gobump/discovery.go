package gobump

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"path"
	"slices"
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
	// Arches are the GOARCHes the package is built for and Env the build
	// environment of the steps building the modroot (merged; for a root no
	// build step covers, the package-level environment's) - Go only, see
	// simulate.BuildTarget. envs are the per-step environments before the
	// merge (discovery-internal).
	Arches []string
	Env    simulate.BuildEnv
	envs   []simulate.BuildEnv
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
func discoverAnalysisUnits(ctx context.Context, cfg *melange.Configuration, bumpSteps []config.BumpStep, migrations map[int]migrationPlan) (map[string][]analysisUnit, []string) {
	// language -> modroot -> sets of build package patterns and tags
	type unitSets struct {
		patterns, tags map[string]struct{}
		step           *config.BumpStep // first bump step covering the root
		goMinor        string
		envs           []simulate.BuildEnv
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

	notes := make(map[string]struct{})
	var arches []string
	if cfg != nil {
		scan := scanBuildSteps(ctx, cfg)
		notes = scan.notes
		arches = goTargetArches(ctx, cfg)
		for language, buildUnits := range scan.units {
			for _, unit := range buildUnits {
				for _, sets := range add(language, []string{unit.Modroot}, unit.Packages, unit.Tags) {
					if unit.GoMinor != "" && (sets.goMinor == "" || goversion.Compare(unit.GoMinor, sets.goMinor) < 0) {
						sets.goMinor = unit.GoMinor
					}
					sets.envs = append(sets.envs, unit.envs...)
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
			if language == "go" {
				if unit.GoMinor == "" {
					unit.GoMinor = envMinor
				}
				unit.Arches = arches
				if len(sets.envs) > 0 {
					unit.Env = mergeBuildEnvs(root, sets.envs, notes)
				} else if cfg != nil {
					// No build step: the package builds it some other way
					// (runs:), under the package-level environment.
					var tags []string
					unit.Env, tags = buildEnv("environment", cfg.Environment.Environment, nil, newLenientRenderer(ctx, cfg), notes)
					for _, tag := range tags {
						sets.tags[tag] = struct{}{}
					}
				}
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
		slices.SortStableFunc(langUnits, func(a, b analysisUnit) int { return strings.Compare(a.Modroot, b.Modroot) })
		result[language] = langUnits
	}
	return result, slices.Sorted(maps.Keys(notes))
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

// buildStepScan is what scanBuildSteps finds: the analysis units, by
// language (a go unit's Env still unmerged: see analysisUnit.Env); notes on
// what the simulation cannot mirror (distinct); and the versioned go/install
// steps (pkg@version), whose artifacts no bump step affects.
type buildStepScan struct {
	units             map[string][]analysisUnit
	notes             map[string]struct{}
	versionedInstalls []string
}

// scanBuildSteps walks the top-level pipeline and every subpackage's
// pipeline, collecting with.modroot (default "." to match the pipeline's
// own default when the field is absent) and with.packages from any step
// whose uses: matches a known build-step signal, plus go/install steps (see
// goInstallUnit). with.packages values may contain melange template
// expressions, so they're resolved through the same renderer git-checkout
// fields get; a value that fails to render is kept raw (a broken pattern
// later makes reachability fail OPEN - no filtering - which is the safe
// direction). Go units also carry the package's target arches (see
// goTargetArches) and their step's build environment (see buildEnv).
func scanBuildSteps(ctx context.Context, cfg *melange.Configuration) buildStepScan {
	result := buildStepScan{units: make(map[string][]analysisUnit), notes: make(map[string]struct{})}
	if cfg == nil {
		return result
	}
	render := newLenientRenderer(ctx, cfg)
	arches := goTargetArches(ctx, cfg)

	collect := func(steps []melange.Pipeline) {
		for i := range steps {
			step := &steps[i]
			var unit analysisUnit
			language := "go"
			switch step.Uses {
			case "go/install":
				var ok bool
				if unit, ok = goInstallUnit(step, render, &result); !ok {
					continue
				}
			default:
				var ok bool
				if language, ok = buildStepSignals[step.Uses]; !ok {
					continue
				}
				unit = analysisUnit{
					Modroot:  cmp.Or(render.value(step.With["modroot"]), "."),
					Packages: strings.Fields(render.value(step.With["packages"])),
				}
				if step.Uses != "go/build" {
					break
				}
				unit.Tags, unit.GoMinor = goStepTags(step, render)
			}
			if language == "go" {
				experiments := step.With["experiments"]
				unit.Arches = arches
				unit.Env, _ = buildEnv(step.Uses+" (modroot "+unit.Modroot+")",
					mergedEnv(cfg.Environment.Environment, step.Environment), &experiments, render, result.notes)
				unit.envs = []simulate.BuildEnv{unit.Env}
			}
			result.units[language] = append(result.units[language], unit)
		}
	}

	collect(cfg.Pipeline)
	for _, subpkg := range cfg.Subpackages {
		collect(subpkg.Pipeline)
	}
	slices.Sort(result.versionedInstalls)
	return result
}

// goStepTags are a go/build or go/install step's build tags (toolchaintags,
// default netgo,osusergo, plus tags) and the Go minor its go-package pins.
func goStepTags(step *melange.Pipeline, render lenientRenderer) (tags []string, goMinor string) {
	toolchainTags, set := step.With["toolchaintags"]
	if !set {
		toolchainTags = defaultToolchainTags
	}
	tags = splitBuildTags(render.value(toolchainTags) + "," + render.value(step.With["tags"]))
	if _, minor, ok := parseGoPackagePin(render.value(step.With["go-package"])); ok {
		goMinor = minor
	}
	return tags, goMinor
}

// goInstallUnit turns a go/install step into an analysis unit. melange's
// go/install runs `go install <package>[@<version>]` in the step's
// working-directory (it has no modroot input): with a version, the go
// command builds that module version on its own, ignoring the checkout's
// go.mod, so no bump step can affect the artifact - noted, no unit. Without
// one it builds the checkout's package, like go/build with
// packages: <package>.
func goInstallUnit(step *melange.Pipeline, render lenientRenderer, scan *buildStepScan) (analysisUnit, bool) {
	pkg := strings.TrimSpace(render.value(step.With["package"]))
	if pkg == "" {
		return analysisUnit{}, false // required input missing: melange rejects the step
	}
	if version := strings.TrimSpace(render.value(step.With["version"])); version != "" {
		coord := pkg + "@" + version
		scan.versionedInstalls = append(scan.versionedInstalls, coord)
		scan.notes["go/install "+coord+" is not affected by bumps (go install pkg@version ignores the checkout's go.mod)"] = struct{}{}
		return analysisUnit{}, false
	}
	modroot, ok := workDirModroot(render.value(step.WorkDir))
	if !ok {
		scan.notes[fmt.Sprintf("go/install %s: working-directory %q is outside the build workspace - not analyzed", pkg, step.WorkDir)] = struct{}{}
		return analysisUnit{}, false
	}
	unit := analysisUnit{Modroot: modroot, Packages: []string{pkg}}
	unit.Tags, unit.GoMinor = goStepTags(step, render)
	return unit, true
}

// melangeWorkspace is the build workspace melange runs pipelines in; a
// relative working-directory is relative to it.
const melangeWorkspace = "/home/build"

// workDirModroot maps a step's working-directory to a modroot: "" is the
// workspace itself ("."), a relative path is kept (cleaned), an absolute one
// must lie inside the workspace (ok false otherwise).
func workDirModroot(workDir string) (string, bool) {
	if workDir == "" {
		return ".", true
	}
	if !path.IsAbs(workDir) {
		return path.Clean(workDir), true
	}
	rel, ok := strings.CutPrefix(path.Clean(workDir), melangeWorkspace)
	if !ok || (rel != "" && !strings.HasPrefix(rel, "/")) {
		return "", false
	}
	return cmp.Or(strings.TrimPrefix(rel, "/"), "."), true
}

// melangeGoArches maps melange's architecture names (apko's, both spellings)
// to GOARCH.
var melangeGoArches = map[string]string{
	"x86_64": "amd64", "amd64": "amd64",
	"aarch64": "arm64", "arm64": "arm64",
	"armv7": "arm", "armhf": "arm", "arm/v7": "arm", "arm/v6": "arm",
	"386": "386", "x86": "386", "i386": "386",
	"ppc64le": "ppc64le", "s390x": "s390x", "riscv64": "riscv64",
	"loongarch64": "loong64", "loong64": "loong64",
}

// goTargetArches maps package.target-architecture to the GOARCHes the
// package is built for, normalized (see simulate.TargetArches): empty or
// "all" means melange's default (amd64 and arm64); unknown names are
// ignored, and a list of only unknown names also falls back to the default.
func goTargetArches(ctx context.Context, cfg *melange.Configuration) []string {
	var arches []string
	for _, name := range cfg.Package.TargetArchitecture {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "all" {
			return simulate.TargetArches(nil)
		}
		if arch, ok := melangeGoArches[name]; ok {
			arches = append(arches, arch)
		} else {
			logging.From(ctx).Debug("ignoring unknown target-architecture", "arch", name)
		}
	}
	return simulate.TargetArches(arches)
}

// mergedEnv is the environment a step runs with: the package-level
// environment.environment overlaid with the step's own environment.
func mergedEnv(pkg, step map[string]string) map[string]string {
	env := maps.Clone(pkg)
	if env == nil {
		env = make(map[string]string, len(step))
	}
	maps.Copy(env, step)
	return env
}

// buildEnv derives, from the environment env a build runs with (described
// by where, for notes), the settings that change which files are built:
//   - CGO_ENABLED: "0"/"1" as set; a value that is unset, does not render or
//     is neither is "" - melange's default applies (enabled: see
//     simulate.BuildEnv), noted when set but not understood.
//   - GOEXPERIMENT: for a go/build or go/install step (experiments non-nil)
//     its experiments input, which the pipeline assigns explicitly,
//     overriding the environment's (noted); otherwise the environment's.
//   - GOFLAGS: -tags is returned as extra tags for a build without such a
//     step; go/build and go/install pass -tags on the command line, which
//     overrides GOFLAGS' (noted). Every other GOFLAGS flag is not mirrored -
//     it would fight the simulation's own -mod=mod - and noted.
func buildEnv(where string, env map[string]string, experiments *string, render lenientRenderer, notes map[string]struct{}) (simulate.BuildEnv, []string) {
	var out simulate.BuildEnv
	if raw, set := env["CGO_ENABLED"]; set {
		value, ok := render.full(raw)
		switch value = strings.TrimSpace(value); {
		case ok && (value == "0" || value == "1"):
			out.CGO = value
		default:
			notes[fmt.Sprintf("%s: CGO_ENABLED %q not understood - linkage evaluated with cgo enabled (melange's default)", where, raw)] = struct{}{}
		}
	}
	experiment := env["GOEXPERIMENT"]
	if experiments != nil {
		if experiment != "" && experiment != *experiments {
			notes[fmt.Sprintf("%s: environment GOEXPERIMENT=%s is overridden by the pipeline's experiments input", where, experiment)] = struct{}{}
		}
		experiment = *experiments
	}
	if value, ok := render.full(experiment); ok {
		out.GOExperiment = strings.TrimSpace(value)
	} else {
		notes[fmt.Sprintf("%s: GOEXPERIMENT %q does not render - linkage not evaluated with it", where, experiment)] = struct{}{}
	}
	var tags, ignored []string
	if raw := env["GOFLAGS"]; raw != "" {
		value, ok := render.full(raw)
		if !ok {
			notes[fmt.Sprintf("%s: GOFLAGS %q does not render - not mirrored", where, raw)] = struct{}{}
			value = ""
		}
		for _, flag := range strings.Fields(value) {
			name, arg, _ := strings.Cut(strings.TrimLeft(flag, "-"), "=")
			switch {
			case name == "tags" && experiments == nil:
				tags = append(tags, splitBuildTags(arg)...)
			case name == "tags":
				notes[fmt.Sprintf("%s: GOFLAGS %s is overridden by the pipeline's own -tags - not applied", where, flag)] = struct{}{}
			default:
				ignored = append(ignored, flag)
			}
		}
	}
	if len(ignored) > 0 {
		notes[fmt.Sprintf("%s: linkage not evaluated with GOFLAGS %s (not mirrored)", where, strings.Join(ignored, " "))] = struct{}{}
	}
	return out, tags
}

// mergeBuildEnvs combines the build environments of the steps sharing a
// modroot: CGO when they agree (else "" - the default, enabled - noted), the
// union of their experiments.
func mergeBuildEnvs(modroot string, envs []simulate.BuildEnv, notes map[string]struct{}) simulate.BuildEnv {
	out := simulate.BuildEnv{CGO: envs[0].CGO}
	if slices.ContainsFunc(envs, func(e simulate.BuildEnv) bool { return e.CGO != out.CGO }) {
		out.CGO = ""
		notes[fmt.Sprintf("modroot %s: build steps disagree on CGO_ENABLED - linkage evaluated with cgo enabled", modroot)] = struct{}{}
	}
	experiments := make(map[string]struct{})
	for _, env := range envs {
		for _, e := range splitBuildTags(env.GOExperiment) {
			experiments[e] = struct{}{}
		}
	}
	out.GOExperiment = strings.Join(slices.Sorted(maps.Keys(experiments)), ",")
	return out
}

// lenientRenderer renders melange template expressions in step fields,
// tolerating failure (see value and full).
type lenientRenderer struct {
	ctx      context.Context
	renderer *config.Renderer
}

func newLenientRenderer(ctx context.Context, cfg *melange.Configuration) lenientRenderer {
	renderer, err := config.NewRenderer(cfg)
	if err != nil {
		logging.From(ctx).Debug("could not build template renderer for build-step discovery", "error", err)
		renderer = nil
	}
	return lenientRenderer{ctx: ctx, renderer: renderer}
}

// full renders value, reporting whether it rendered completely (no template
// expression left).
func (r lenientRenderer) full(value string) (string, bool) {
	if !strings.Contains(value, "${{") {
		return value, true
	}
	if r.renderer == nil {
		return value, false
	}
	rendered, err := r.renderer.RenderString(value)
	if err != nil {
		logging.From(r.ctx).Debug("could not render build-step field", "value", value, "error", err)
		return value, false
	}
	return rendered, !strings.Contains(rendered, "${{")
}

// value renders value, keeping it raw when it does not render.
func (r lenientRenderer) value(value string) string {
	rendered, _ := r.full(value)
	return rendered
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
