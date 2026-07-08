package gobump

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/goversion"
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
// the same renderer other build-step fields get (see unitsFromBuildSteps); a
// value that fails to render is kept raw. A rendered value that isn't a go
// toolchain package name (parseGoPackagePin ok=false) is also treated as
// unpinned, but its Package string is preserved so callers can warn about it.
func goToolchainPins(cfg *melange.Configuration) []GoToolchainPin {
	var pins []GoToolchainPin

	renderer, err := config.NewRenderer(cfg)
	if err != nil {
		slog.Debug("could not build template renderer for go-toolchain-pin discovery", "error", err)
		renderer = nil
	}
	render := func(value string) string {
		if renderer == nil || !strings.Contains(value, "${{") {
			return value
		}
		rendered, err := renderer.RenderString(value)
		if err != nil {
			slog.Debug("could not render go-package field", "value", value, "error", err)
			return value
		}
		return rendered
	}

	collect := func(steps []melange.Pipeline) {
		for _, step := range steps {
			if _, ok := goToolchainSteps[step.Uses]; !ok {
				continue
			}

			raw := step.With["go-package"]
			if raw == "" {
				pins = append(pins, GoToolchainPin{})
				continue
			}

			pkg := render(raw)
			_, minor, ok := parseGoPackagePin(pkg)
			if !ok {
				pins = append(pins, GoToolchainPin{Package: pkg})
				continue
			}
			pins = append(pins, GoToolchainPin{Package: pkg, Minor: minor})
		}
	}

	collect(cfg.Pipeline)
	for _, subpkg := range cfg.Subpackages {
		collect(subpkg.Pipeline)
	}

	return pins
}

// goPinFloor is the Go language version every go-package pin in the file
// must satisfy: the file-wide max, across go modroots, of each root's own
// pristine baseline and its (proven or best-effort) required raise. "" when
// nothing demands anything (no go modroots, or no baseline information).
func goPinFloor(analysis *VulnerabilityAnalysis) string {
	var floor string
	for li := range analysis.ByLanguage {
		lang := &analysis.ByLanguage[li]
		if lang.Language != "go" {
			continue
		}
		for mi := range lang.ByModroot {
			m := &lang.ByModroot[mi]
			floor = goversion.Max(floor, pristineGoBaseline(m), m.RequiredGoVersion)
		}
	}
	return floor
}

// reconcileGoPackagePins raises too-old go-package pins on go/build|go/install
// steps (top-level and subpackage pipelines) to satisfy pinFloor (a bare Go
// version), comment-preservingly, only ever raising a pin's minor - never
// lowering one. Values it cannot safely rewrite are warned about instead:
// templated pins (the melange variable must be updated manually) and values
// that aren't a recognizable go toolchain package name. Unversioned pins
// ("go", "go-fips") already float to the latest toolchain and are left alone.
// pinFloor "" is a no-op.
//
// Scope note: this only runs when the applier runs at all
// (GoBumpApplier.ShouldRun gates on bump actions), so a package whose pins
// are stale but whose deps need no bump is not rewritten - an accepted v1
// limitation.
func (g *GoBumpApplier) reconcileGoPackagePins(gp *GoBumpProcessor, pinFloor string) error {
	if pinFloor == "" {
		return nil
	}
	floorMinor := goversion.Minor(pinFloor)
	if floorMinor == "" {
		return nil
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

	var renderer *config.Renderer
	if gp.Config != nil {
		renderer, err = config.NewRenderer(gp.Config)
		if err != nil {
			slog.Debug("could not build template renderer for go-package pin reconciliation", "error", err)
			renderer = nil
		}
	}

	changed := false
	for _, pin := range pins {
		where := "pipeline"
		if pin.Subpackage != "" {
			where = "subpackage " + pin.Subpackage
		}

		if strings.Contains(pin.Value, "${{") {
			if renderer == nil {
				// Degraded path (no gp.Config, or the renderer failed to
				// build): the templated value can't be evaluated at all, so
				// raw-value parsing below would silently misjudge or skip it.
				// Warn instead of going quiet.
				gp.AddMessage(fmt.Sprintf("go-package %q (%s) is templated and could not be evaluated; verify manually against required Go %s",
					pin.Value, where, pinFloor))
				continue
			}
			// Templated pin: judge the rendered value, but never edit the
			// template - the variable behind it is the user's to update.
			rendered := pin.Value
			if r, err := renderer.RenderString(pin.Value); err == nil {
				rendered = r
			} else {
				slog.Debug("could not render go-package pin", "value", pin.Value, "error", err)
			}
			_, minor, ok := parseGoPackagePin(rendered)
			if ok && minor != "" && goversion.Compare(minor, floorMinor) < 0 {
				gp.AddMessage(fmt.Sprintf("go-package %q (%s) is templated and resolves to Go %s, below required Go %s; update the variable manually",
					pin.Value, where, minor, pinFloor))
			}
			continue
		}

		base, minor, ok := parseGoPackagePin(pin.Value)
		if !ok {
			gp.AddMessage(fmt.Sprintf("unrecognized go-package %q (%s); required Go %s - not rewritten", pin.Value, where, pinFloor))
			continue
		}
		if minor == "" {
			// Unversioned toolchain package ("go", "go-fips"): tracks the
			// latest release already, nothing to raise.
			slog.Debug("go-package pin is unversioned - leaving untouched", "value", pin.Value, "where", where)
			continue
		}
		if goversion.Compare(minor, floorMinor) >= 0 {
			continue
		}

		newValue := base + "-" + floorMinor
		updated, err := loader.UpdateField(yamlContent, pin.Path, newValue)
		if err != nil {
			return fmt.Errorf("updating go-package pin %s: %w", pin.Path, err)
		}
		yamlContent = updated
		changed = true
		gp.AddMessage(fmt.Sprintf("raised go-package pin %s -> %s (%s; dependencies require Go %s)", pin.Value, newValue, where, pinFloor))
	}

	if changed {
		gp.SetCurrentYAML(yamlContent)
		gp.MarkActualChangesApplied()
	}
	return nil
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

	minors := make([]string, 0, len(seen))
	for minor := range seen {
		minors = append(minors, minor)
	}
	sort.Slice(minors, func(i, j int) bool { return goversion.Compare(minors[i], minors[j]) < 0 })

	if unpinned {
		return append([]string{""}, minors...)
	}
	return minors
}
