package gobump

import (
	"context"

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
