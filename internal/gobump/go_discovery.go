package gobump

import (
	"fmt"
	"strings"

	"context"

	"github.com/isometry/choam/internal/logging"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/simulate"
)

// goDiscovery is the file-wide input to goUnitDetails: the go/bump steps'
// migration plans by pipeline index (see planMigration) and, once loaded
// from the melange configuration, the package's target GOARCHes and the Go
// minor a versioned go package in the build environment pins.
type goDiscovery struct {
	cfg        *melange.Configuration
	migrations map[int]migrationPlan
	arches     []string
	envMinor   string
}

// load reads the package-wide Go build settings from cfg (non-nil).
func (d *goDiscovery) load(ctx context.Context, cfg *melange.Configuration) {
	d.cfg = cfg
	d.arches = goTargetArches(ctx, cfg)
	for _, pkg := range cfg.Environment.Contents.Packages {
		if _, minor, ok := parseGoPackagePin(pkg); ok && minor != "" {
			d.envMinor = minor
			break
		}
	}
}

// goUnitDetails fills the Go-only parts of a go analysis unit (see
// analysisUnit): the Go minor - the lowest the build steps building the
// modroot pin via go-package, else the one a migration will pin, else the
// build environment's - the engine and migration of a covering go/bump step
// (step, the first bump step covering the root, may be nil), the target
// arches and the build environment (built, the build-step units building the
// root, merged; none: the package-level environment's). It returns the
// extra build tags that package-level environment's GOFLAGS -tags add.
func goUnitDetails(ctx context.Context, d goDiscovery, unit *analysisUnit, step *config.BumpStep, built []analysisUnit, notes map[string]struct{}) []string {
	var envs []simulate.BuildEnv
	for _, b := range built {
		if b.GoMinor != "" && (unit.GoMinor == "" || goversion.Compare(b.GoMinor, unit.GoMinor) < 0) {
			unit.GoMinor = b.GoMinor
		}
		envs = append(envs, b.envs...)
	}
	if step != nil && step.Action == "go/bump" {
		if plan := d.migrations[step.Index]; plan.ok {
			unit.Migrating = true
			if unit.GoMinor == "" {
				unit.GoMinor = plan.goMinor
			}
		} else {
			unit.Engine = simulate.EngineGobump
		}
	}
	if unit.GoMinor == "" {
		unit.GoMinor = d.envMinor
	}
	unit.Arches = d.arches
	if len(envs) > 0 {
		unit.Env = mergeBuildEnvs(unit.Modroot, envs, notes)
		return nil
	}
	if d.cfg == nil {
		return nil
	}
	// No build step: the package builds it some other way (runs:), under
	// the package-level environment.
	var tags []string
	unit.Env, tags = buildEnv("environment", d.cfg.Environment.Environment, nil, newLenientRenderer(ctx, d.cfg), notes)
	return tags
}

// defaultToolchainTags mirrors melange's go/build toolchaintags default.
const defaultToolchainTags = "netgo,osusergo"

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
