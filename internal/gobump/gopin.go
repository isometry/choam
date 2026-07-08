package gobump

import (
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
