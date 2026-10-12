package gobump

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
)

// GoToolchainPin describes one go/build|go/install step's toolchain selection.
type GoToolchainPin struct {
	Package string // rendered with.go-package value; "" when the step has no go-package
	Minor   string // "1.24" when Package carries a trailing -1.X suffix; "" = unpinned
}

// goToolchainSteps are the pipeline "uses:" values that select a Go
// toolchain package via with.go-package (verified against melange's own
// go/build and go/install pipeline definitions).
var goToolchainSteps = map[string]struct{}{
	"go/build":   {},
	"go/install": {},
}

// goPackagePinSuffix matches the trailing "-<major>.<minor>" that Wolfi go
// toolchain package names use to pin a specific minor release (e.g.
// "go-1.24", "go-fips-1.24"). Only minor granularity exists in Wolfi's go
// packaging, so this deliberately doesn't match a patch component.
var goPackagePinSuffix = regexp.MustCompile(`^(.+)-([0-9]+\.[0-9]+)$`)

// parseGoPackagePin splits a Wolfi go toolchain package name into base and
// minor-version suffix: "go-1.24" -> ("go", "1.24", true), "go-fips-1.24" ->
// ("go-fips", "1.24", true), "go"/"go-fips" -> (value, "", true). A go
// toolchain package name is exactly "go" or anything "go-"-prefixed;
// anything else (e.g. "golang", "rust") is not a toolchain pin and returns
// ok=false.
func parseGoPackagePin(value string) (base, minor string, ok bool) {
	if value != "go" && !strings.HasPrefix(value, "go-") {
		return "", "", false
	}
	if m := goPackagePinSuffix.FindStringSubmatch(value); m != nil {
		return m[1], m[2], true
	}
	return value, "", true
}

// goToolchainPins walks the top-level pipeline and all subpackage pipelines
// for steps with uses: go/build or go/install, returning one pin per step
// (including steps without a go-package, as unpinned entries). with.go-package
// values may carry melange template expressions, so they're resolved through
// the same renderer other build-step fields get (see scanBuildSteps); a
// value that fails to render is kept raw. A rendered value that isn't a go
// toolchain package name (parseGoPackagePin ok=false) is also treated as
// unpinned, but its Package string is preserved so callers can warn about it.
func goToolchainPins(ctx context.Context, cfg *melange.Configuration) []GoToolchainPin {
	var pins []GoToolchainPin

	render := newLenientRenderer(ctx, cfg).value

	config.ForEachPipelineStep(cfg, func(step *melange.Pipeline) {
		if _, ok := goToolchainSteps[step.Uses]; !ok {
			return
		}

		raw := step.With["go-package"]
		if raw == "" {
			pins = append(pins, GoToolchainPin{})
			return
		}

		pkg := render(raw)
		_, minor, ok := parseGoPackagePin(pkg)
		if !ok {
			pins = append(pins, GoToolchainPin{Package: pkg})
			return
		}
		pins = append(pins, GoToolchainPin{Package: pkg, Minor: minor})
	})

	return pins
}

// goPinFloors is the per-modroot Go language version each go-package pin must
// satisfy, keyed by the modroot the requirement was proven for. Each modroot's
// floor is the max of its own pristine baseline and its (proven or
// best-effort) required raise. A modroot absent from the map (or mapped to "")
// demands nothing, so a go/build pin keyed to it is left alone - the fix for
// the FIPS/variant hazard where a raise in one modroot used to rewrite a
// deliberately held-back pin building a different, lower-requirement modroot.
// go/install pins carry no modroot and instead use the file-wide max (see
// reconcileGoPackagePins).
func goPinFloors(analysis *VulnerabilityAnalysis) map[string]string {
	floors := make(map[string]string)
	for li := range analysis.ByLanguage {
		lang := &analysis.ByLanguage[li]
		if lang.Language != "go" {
			continue
		}
		for mi := range lang.ByModroot {
			m := &lang.ByModroot[mi]
			floors[m.Modroot] = goversion.Max(floors[m.Modroot], pristineGoBaseline(m), m.RequiredGoVersion)
		}
	}
	return floors
}

// reconcileGoPackagePins raises too-old go-package pins on go/build|go/install
// steps (top-level and subpackage pipelines) to satisfy each pin's OWN floor,
// comment-preservingly, only ever raising a pin's minor - never lowering one.
//
// Floors are per-modroot (floors, keyed by modroot): a go/build pin is checked
// against floors[pin.Modroot] (its templated modroot rendered first), so a
// raise proven for one modroot never rewrites a pin building a different,
// lower-requirement modroot - the FIPS/variant hazard fix. A modroot with no
// floor (absent, or "") leaves its pin alone. go/install steps carry no
// modroot, so they fall back to the file-wide max floor (a documented
// trade-off: a go/install pin can still be raised by a requirement proven for
// an unrelated modroot).
//
// Variant toolchains (base != "go", e.g. go-fips) are never auto-rewritten:
// they have separate release/validation cadences and compliance implications,
// so a needed raise is surfaced as a warning for the maintainer to apply
// manually. Only base == "go" auto-raises.
//
// Values it cannot safely rewrite are warned about instead: templated pins
// (the melange variable must be updated manually) and values that aren't a
// recognizable go toolchain package name. Unversioned pins ("go", "go-fips")
// already float to the latest toolchain and are left alone. Empty floors
// (nothing demands anything) make this a no-op.
//
// ctx is consulted for release-existence validation (see validateFloor below)
// and carries this file's logger (internal/logging).
//
// Scope note: this only runs when the apply phase runs at all
// (GoPackagePinStage.ShouldRun shares the applier's bump-actions gate), so a
// package whose pins are stale but whose deps need no bump is not rewritten -
// an accepted v1 limitation.
func (s *GoPackagePinStage) reconcileGoPackagePins(ctx context.Context, gp *GoBumpProcessor, floors map[string]string) error {
	if len(floors) == 0 {
		return nil
	}

	// go/install pins have no modroot association, so they use the file-wide
	// max floor (current behaviour, documented trade-off).
	var maxFloor string
	for _, f := range floors {
		maxFloor = goversion.Max(maxFloor, f)
	}

	loader := config.NewLoader()
	yamlContent := gp.GetCurrentYAML()
	pins, err := loader.FindGoPackagePins(yamlContent)
	if err != nil {
		return fmt.Errorf("finding go-package pins: %w", err)
	}
	if len(pins) == 0 {
		return nil
	}

	render := newLenientRenderer(ctx, gp.Config)

	// validateFloor is defense in depth against an untrusted floor reaching
	// the write below: floors come from goPinFloors, which takes the max of
	// pristineGoBaseline (the modroot's own, pre-existing config - never
	// filtered) and RequiredGoVersion (validated in fallbackGoVersions only
	// on that path; simulation-proven values are untouched by design). A
	// typo'd or otherwise bogus floor must never be written into a pin.
	// Memoized per minor since the same floor commonly recurs across pins.
	validateFloor := newFloorValidator(ctx, s.Analyzer.releaseIndex())

	changed := false
	for _, pin := range pins {
		where := describePinLocation(pin)
		floor := pinFloor(ctx, render, pin, floors, maxFloor)

		if strings.Contains(pin.Value, "${{") {
			checkTemplatedPin(gp, render, pin, where, floor)
			continue
		}

		d := decidePin(pin.Value, floor)
		switch d.verdict {
		case pinNoRequirement:
			continue
		case pinUnrecognized:
			gp.AddMessage(fmt.Sprintf("unrecognized go-package %q (%s); required Go %s - not rewritten", pin.Value, where, floor))
			continue
		case pinUnversioned:
			// Unversioned toolchain package ("go", "go-fips"): tracks the
			// latest release already, nothing to raise.
			logging.From(ctx).Debug("go-package pin is unversioned - leaving untouched", "value", pin.Value, "where", where)
			continue
		case pinSufficient:
			// No requirement, or already sufficient: effective minor is its own.
			recordPinOutcome(gp, d.minor, d.minor)
			continue
		case pinVariant:
			// Variant toolchain (go-fips, ...): separate release/validation
			// cadences and compliance implications mean we must not silently
			// rewrite it - surface it for manual attention. The pin keeps its
			// current minor, so its effective outcome is the identity.
			recordPinOutcome(gp, d.minor, d.minor)
			gp.AddMessage(fmt.Sprintf("go-package pin %s (%s) needs Go %s but is a variant toolchain with separate release/validation cadences and compliance implications; raise it manually",
				pin.Value, where, floor))
			continue
		}

		// pinRaise: validate the floor, then rewrite the pin.
		valid, offlineErr := validateFloor(d.floorMinor)
		if offlineErr != nil {
			gp.AddMessage(fmt.Sprintf("go-package pin %s (%s): could not validate required Go %s against known releases (index unavailable) - proceeding without validation: %v",
				pin.Value, where, floor, offlineErr))
		}
		if !valid {
			recordPinOutcome(gp, d.minor, d.minor)
			gp.AddMessage(fmt.Sprintf("go-package pin %s (%s) required Go %s, which is not a known Go release — leaving pin unchanged (check the dependency's go.mod)",
				pin.Value, where, floor))
			continue
		}

		recordPinOutcome(gp, d.minor, d.floorMinor)

		newValue := d.base + "-" + d.floorMinor
		updated, err := loader.UpdateField(yamlContent, pin.Path, newValue)
		if err != nil {
			return fmt.Errorf("updating go-package pin %s: %w", pin.Path, err)
		}
		yamlContent = updated
		changed = true
		gp.AddMessage(fmt.Sprintf("raised go-package pin %s -> %s (%s; dependencies require Go %s)", pin.Value, newValue, where, floor))
	}

	if changed {
		gp.SetCurrentYAML(yamlContent)
		gp.MarkActualChangesApplied()
	}
	return nil
}

// pinFloor is the Go version the given pin must satisfy: floors[modroot]
// for go/build (its templated modroot rendered), maxFloor for go/install.
// "" means this pin's target proved no requirement - leave it alone.
func pinFloor(ctx context.Context, render lenientRenderer, pin config.GoPackagePin, floors map[string]string, maxFloor string) string {
	if pin.Uses == "go/install" {
		return maxFloor
	}
	modroot := render.value(pin.Modroot)
	floor, ok := floors[modroot]
	if !ok {
		logging.From(ctx).Debug("go-package pin modroot not in analysis - no floor, leaving untouched",
			"modroot", modroot, "value", pin.Value)
	}
	return floor
}

// checkTemplatedPin judges a templated pin's rendered value against its
// floor, warning when it falls short - but never edits the template: the
// variable behind it is the user's to update.
func checkTemplatedPin(gp *GoBumpProcessor, render lenientRenderer, pin config.GoPackagePin, where, floor string) {
	floorMinor := goversion.Minor(floor)
	if floorMinor == "" {
		// This pin's target demands nothing; nothing to check.
		return
	}
	if render.renderer == nil {
		// Degraded path (no gp.Config, or the renderer failed to
		// build): the templated value can't be evaluated at all, so
		// raw-value parsing would silently misjudge or skip it.
		// Warn instead of going quiet.
		gp.AddMessage(fmt.Sprintf("go-package %q (%s) is templated and could not be evaluated; verify manually against required Go %s",
			pin.Value, where, floor))
		return
	}
	_, minor, ok := parseGoPackagePin(render.value(pin.Value))
	if ok && minor != "" && goversion.Compare(minor, floorMinor) < 0 {
		gp.AddMessage(fmt.Sprintf("go-package %q (%s) is templated and resolves to Go %s, below required Go %s; update the variable manually",
			pin.Value, where, minor, floor))
	}
}

// pinVerdict is decidePin's classification of one non-templated pin.
type pinVerdict int

const (
	pinNoRequirement pinVerdict = iota // unrecognized value, but its target demands nothing
	pinUnrecognized                    // not a recognizable go toolchain package name
	pinUnversioned                     // "go", "go-fips": already floats to the latest release
	pinSufficient                      // no requirement, or the pin already satisfies it
	pinVariant                         // needs a raise, but is a variant toolchain (base != "go")
	pinRaise                           // needs a raise to floorMinor
)

// pinDecision is decidePin's result: the verdict plus the parsed pin
// (base, minor) and the floor's minor.
type pinDecision struct {
	verdict     pinVerdict
	base, minor string
	floorMinor  string
}

// decidePin classifies a non-templated go-package pin value against its
// floor (pure: no I/O, no messages).
func decidePin(value, floor string) pinDecision {
	d := pinDecision{floorMinor: goversion.Minor(floor)}
	base, minor, ok := parseGoPackagePin(value)
	if !ok {
		if d.floorMinor == "" {
			d.verdict = pinNoRequirement
		} else {
			d.verdict = pinUnrecognized
		}
		return d
	}
	d.base, d.minor = base, minor
	switch {
	case minor == "":
		d.verdict = pinUnversioned
	case d.floorMinor == "" || goversion.Compare(minor, d.floorMinor) >= 0:
		d.verdict = pinSufficient
	case base != "go":
		d.verdict = pinVariant
	default:
		d.verdict = pinRaise
	}
	return d
}

// describePinLocation renders a human-readable location for a pin's messages,
// naming its pipeline (top-level or subpackage) and its modroot.
func describePinLocation(pin config.GoPackagePin) string {
	where := "pipeline"
	if pin.Subpackage != "" {
		where = "subpackage " + pin.Subpackage
	}
	// go/install has no modroot; only name one when it's meaningful.
	if pin.Uses == "go/install" {
		return where
	}
	return fmt.Sprintf("%s, modroot %s", where, pin.Modroot)
}

// recordPinOutcome notes one versioned go-package pin's effective minor after
// reconciliation (identity when the pin was already sufficient, or when a
// variant toolchain was warned-not-rewritten) on the processor, for the
// stdlib staleness check's rebuild-side constraints.
//
// Per-modroot floors and the variant guard mean pins sharing an ORIGINAL minor
// can now diverge (one raised, another held back). We record the MINIMUM
// effective per original minor so the stdlib rebuild side assumes the oldest
// toolchain that will actually be used - over-detecting staleness, the safe
// direction (a rebuild the older pin still triggers is never missed).
func recordPinOutcome(gp *GoBumpProcessor, original, effective string) {
	if gp.RaisedPinMinors == nil {
		gp.RaisedPinMinors = make(map[string]string)
	}
	if existing, ok := gp.RaisedPinMinors[original]; ok && goversion.Compare(existing, effective) <= 0 {
		return // keep the smaller (older) effective already recorded
	}
	gp.RaisedPinMinors[original] = effective
}

// rebuildConstraintsFor maps each pristine-config pin constraint to the
// constraint the NEXT build will actually use, applying same-run go-package
// pin raises (GoBumpProcessor.RaisedPinMinors). Unpinned ("") and untouched
// constraints map to themselves and are omitted; nil is returned when no
// raise changes anything. Note the deliberate coarseness: constraints are
// distinct minors, so a raised raw pin also stands in for a templated pin
// that renders to the same minor (templated pins record nothing but share
// the constraint) - acceptable, the raise message already tells the user to
// update the variable manually.
func rebuildConstraintsFor(constraints []string, raised map[string]string) map[string]string {
	var out map[string]string
	for _, constraint := range constraints {
		if constraint == "" {
			continue
		}
		if effective, ok := raised[constraint]; ok && effective != constraint {
			if out == nil {
				out = make(map[string]string)
			}
			out[constraint] = effective
		}
	}
	return out
}

// distinctMinorConstraints reduces pins to the sorted distinct set of minor
// constraints; "" (unpinned) sorts first. Empty input -> [""].
func distinctMinorConstraints(pins []GoToolchainPin) []string {
	seen := make(map[string]struct{})
	unpinned := len(pins) == 0
	for _, pin := range pins {
		if pin.Minor == "" {
			unpinned = true
			continue
		}
		seen[pin.Minor] = struct{}{}
	}

	minors := slices.SortedFunc(maps.Keys(seen), func(a, b string) int {
		return cmp.Or(goversion.Compare(a, b), strings.Compare(a, b))
	})

	if unpinned {
		return append([]string{""}, minors...)
	}
	return minors
}
