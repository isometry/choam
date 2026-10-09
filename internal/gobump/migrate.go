package gobump

import (
	"context"
	"fmt"
	"regexp"

	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/gorelease"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
)

// migrationPlan says whether, and how, a `uses: go/bump` step becomes a
// `uses: bump` step (language: go) when choam rewrites it. Migration keeps the
// step in place with every option and comment; only uses/language change,
// and go-version is dropped once the Go version is expressed another way:
// an existing go-package pin (or a versioned go package in the environment)
// already does, otherwise addPin is written to every go/build|go/install
// step (pinTargets) so the build keeps the Go minor go-version selected.
type migrationPlan struct {
	ok     bool
	reason string // why ok is false ("" for a step that is not go/bump)

	// goVersion is the step's go-version to drop ("" when it has none);
	// pinnedBy names what already expresses the Go version (for messages).
	goVersion string
	pinnedBy  string

	// addPin ("go-1.26") is written as with.go-package to pinTargets (with
	// block paths); goMinor is its minor, the Go the build will then use.
	addPin     string
	goMinor    string
	pinTargets []config.GoToolchainStep
}

// wolfiGoPackage matches a Wolfi go toolchain package pinned to a Go 1 minor.
var wolfiGoPackage = regexp.MustCompile(`^go-1\.[0-9]+$`)

// planMigration decides migrationPlan for step against the package YAML.
// index (nil-safe) validates a go-version-derived pin names a real Go
// release; an unavailable index fails open (the regex check still applies).
func planMigration(ctx context.Context, yamlContent []byte, step config.BumpStep, index *gorelease.Index) migrationPlan {
	if step.Action != "go/bump" {
		return migrationPlan{}
	}
	if step.Work {
		return migrationPlan{reason: "work: true has no uses: bump equivalent (omnibump detects go.work itself)"}
	}
	if step.GoVersion == "" {
		return migrationPlan{ok: true}
	}
	plan := migrationPlan{goVersion: step.GoVersion}

	loader := config.NewLoader()
	toolchainSteps, err := loader.FindGoToolchainSteps(yamlContent)
	if err != nil {
		return migrationPlan{reason: fmt.Sprintf("could not read go/build|go/install steps: %v", err)}
	}
	for _, ts := range toolchainSteps {
		if ts.HasPin && ts.Value != "" {
			plan.ok, plan.pinnedBy = true, fmt.Sprintf("go-package pin %s (%s)", ts.Value, describePinLocation(ts.GoPackagePin))
			return plan
		}
	}
	envPackages, err := loader.EnvironmentPackages(yamlContent)
	if err != nil {
		return migrationPlan{reason: fmt.Sprintf("could not read environment packages: %v", err)}
	}
	for _, pkg := range envPackages {
		if _, minor, ok := parseGoPackagePin(pkg); ok && minor != "" {
			plan.ok, plan.pinnedBy = true, "environment package "+pkg
			return plan
		}
	}

	minor := goversion.Minor(step.GoVersion)
	pin := "go-" + minor
	base, pinMinor, ok := parseGoPackagePin(pin)
	if minor == "" || !ok || base != "go" || pinMinor != minor || !wolfiGoPackage.MatchString(pin) {
		return migrationPlan{goVersion: step.GoVersion,
			reason: fmt.Sprintf("go-version %q does not map to a go-<major>.<minor> toolchain package and no go-package pin expresses the Go version", step.GoVersion)}
	}
	valid, offlineErr := validateGoVersionFloor(ctx, index, minor)
	if offlineErr != nil {
		logging.From(ctx).Debug("could not validate go-package pin against known Go releases - proceeding", "pin", pin, "error", offlineErr)
	}
	if !valid {
		return migrationPlan{goVersion: step.GoVersion,
			reason: fmt.Sprintf("go-version %q names Go %s, which is not a known Go release", step.GoVersion, minor)}
	}
	if len(toolchainSteps) == 0 {
		return migrationPlan{goVersion: step.GoVersion,
			reason: fmt.Sprintf("go-version %q cannot be expressed as a go-package pin: no go/build or go/install step", step.GoVersion)}
	}
	plan.ok, plan.addPin, plan.goMinor, plan.pinTargets = true, pin, minor, toolchainSteps
	return plan
}

// planMigrations plans every go/bump step, keyed by pipeline index.
func planMigrations(ctx context.Context, yamlContent []byte, steps []config.BumpStep, index *gorelease.Index) map[int]migrationPlan {
	plans := make(map[int]migrationPlan)
	for _, step := range steps {
		if step.Action == "go/bump" {
			plans[step.Index] = planMigration(ctx, yamlContent, step, index)
		}
	}
	return plans
}

// migrateStep rewrites the go/bump step at step.Index into a `uses: bump`
// step in place: go-package pins first (plan.addPin, on targets that still
// lack one), then go-version (with the comment lines describing it) is
// removed, uses is rewritten, and language: go is appended when the step
// names no language. Every other byte of the file is preserved.
func migrateStep(gp *GoBumpProcessor, yamlContent []byte, step config.BumpStep, plan migrationPlan) ([]byte, error) {
	loader := config.NewLoader()
	if plan.addPin != "" {
		current, err := loader.FindGoToolchainSteps(yamlContent)
		if err != nil {
			return nil, fmt.Errorf("finding go/build|go/install steps: %w", err)
		}
		pinned := make(map[string]bool, len(current))
		for _, ts := range current {
			pinned[ts.WithPath] = ts.HasPin
		}
		for _, target := range plan.pinTargets {
			if pinned[target.WithPath] {
				continue // pinned meanwhile (an earlier migration in this run)
			}
			updated, err := loader.SpliceIntoWith(yamlContent, target.WithPath, []string{"go-package: " + plan.addPin})
			if err != nil {
				return nil, fmt.Errorf("adding go-package pin to %s: %w", target.WithPath, err)
			}
			yamlContent = updated
			gp.AddMessage(fmt.Sprintf("added go-package: %s to %s (%s) to keep the Go version go/bump's go-version %s selected",
				plan.addPin, target.Uses, describePinLocation(target.GoPackagePin), plan.goVersion))
		}
	}
	if plan.goVersion != "" {
		updated, err := loader.RemovePipelineWithFieldLines(yamlContent, step.Index, "go-version")
		if err != nil {
			return nil, fmt.Errorf("removing go-version: %w", err)
		}
		yamlContent = updated
		expressed := plan.pinnedBy
		if expressed == "" {
			expressed = "go-package pin " + plan.addPin
		}
		gp.AddMessage(fmt.Sprintf("dropped go-version %s from pipeline[%d] (uses: bump has no such input; Go version expressed by %s)",
			plan.goVersion, step.Index, expressed))
	}
	updated, err := loader.SetPipelineUses(yamlContent, step.Index, "bump")
	if err != nil {
		return nil, fmt.Errorf("rewriting uses: %w", err)
	}
	yamlContent = updated
	if step.Language == "" {
		if yamlContent, err = loader.SpliceIntoWith(yamlContent, fmt.Sprintf("$.pipeline[%d].with", step.Index), []string{"language: go"}); err != nil {
			return nil, fmt.Errorf("adding language: %w", err)
		}
	}
	gp.AddMessage(fmt.Sprintf("migrated pipeline[%d] uses: go/bump -> uses: bump (language: go), options and position kept", step.Index))
	return yamlContent, nil
}
