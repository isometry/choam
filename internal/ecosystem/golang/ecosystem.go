// Package golang implements the Go ecosystem.Ecosystem: go.mod/go.sum
// parsing, v2+ module path normalization, replace-directive resolution, and
// bump decisioning. This logic is deliberately CHOAM's own rather than
// omnibump's - omnibump's AnalyzeRemote only reads go.mod, which would
// silently drop the go.sum-derived indirect-dependency scanning CHOAM needs
// for pre-1.17 modules (whose go.mod lists direct requirements only; from
// go 1.17, graph pruning makes go.mod's require block complete and go.sum
// merging is skipped - see needsGoSumMerge).
package golang

import (
	"context"
	"fmt"
	"strings"

	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/utils"
	"golang.org/x/mod/modfile"
)

// Ecosystem implements ecosystem.Ecosystem for Go modules.
type Ecosystem struct {
	parser   *parser
	analyzer *analyzer
}

// New creates the Go ecosystem implementation.
func New() *Ecosystem {
	return &Ecosystem{
		parser:   newParser(),
		analyzer: newAnalyzer(),
	}
}

func init() {
	ecosystem.Register("go", func() ecosystem.Ecosystem { return New() })
}

func (e *Ecosystem) Name() string { return "go" }

// ManifestFiles returns go.mod and go.sum. go.sum is optional at fetch time
// (some projects predate its existence) - Analyze tolerates its absence.
func (e *Ecosystem) ManifestFiles() []string { return []string{"go.mod", "go.sum"} }

func (e *Ecosystem) Analyze(_ context.Context, files map[string][]byte) (*ecosystem.ModuleDeps, error) {
	goModContent, ok := files["go.mod"]
	if !ok {
		return nil, fmt.Errorf("go.mod not found")
	}

	info, err := e.parser.parseGoModWithSum(goModContent, files["go.sum"])
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod/go.sum: %w", err)
	}

	deps := make([]ecosystem.Dep, 0, len(info.AllRequirements))
	for module, version := range info.AllRequirements {
		_, direct := info.Requirements[module]
		deps = append(deps, ecosystem.Dep{
			Coord:    module,
			Name:     module,
			Version:  version,
			Indirect: !direct,
		})
	}

	return &ecosystem.ModuleDeps{Deps: deps, Raw: info}, nil
}

// ScanPackages builds the OSV query list from a modroot's full requirement
// set (direct + indirect), skipping the standard library and resolving
// replace directives: a locally-replaced module is skipped entirely (no
// meaningful version to query), and a module replaced with another module is
// queried under its replacement's name/version.
func (e *Ecosystem) ScanPackages(deps *ecosystem.ModuleDeps) []scan.Package {
	info, ok := deps.Raw.(*GoModInfo)
	if !ok || info == nil {
		return nil
	}

	pkgs := make([]scan.Package, 0, len(info.AllRequirements))
	for module, version := range info.AllRequirements {
		if strings.HasPrefix(module, "std") {
			continue
		}

		moduleToScan := module
		versionToScan := version

		if replace, ok := info.Replacements[module+"@"+version]; ok {
			if utils.IsLocalPath(replace.New.Path) {
				continue
			}
			moduleToScan = replace.New.Path
			versionToScan = replace.New.Version
		} else if replace, ok := info.Replacements[module]; ok {
			if utils.IsLocalPath(replace.New.Path) {
				continue
			}
			moduleToScan = replace.New.Path
			versionToScan = replace.New.Version
			if versionToScan == "" {
				versionToScan = version
			}
		}

		pkgs = append(pkgs, scan.Package{Name: moduleToScan, Version: versionToScan, Ecosystem: "Go"})
	}

	return pkgs
}

// ModFileOf returns the parsed pristine go.mod behind a ModuleDeps produced
// by this ecosystem's Analyze, or nil for anything else. Exposed because
// GoModInfo travels as ModuleDeps.Raw (opaque any); the simulation stage
// needs the pristine modfile to reproduce melange gobump's build-time
// co-update check against the exact same input.
func ModFileOf(deps *ecosystem.ModuleDeps) *modfile.File {
	if deps == nil {
		return nil
	}
	info, ok := deps.Raw.(*GoModInfo)
	if !ok || info == nil {
		return nil
	}
	return info.ModFile
}

// EffectiveVersions returns every required module's (direct and indirect)
// effective version - the go.mod requirement with replace directives applied
// (a local-path replacement maps to the "never bump this" sentinel, see
// getEffectiveVersion). Used as the baseline for bump simulation: an entry
// that doesn't move a module beyond this baseline is a no-op.
func (e *Ecosystem) EffectiveVersions(deps *ecosystem.ModuleDeps) map[string]string {
	if deps == nil {
		return nil
	}
	info, ok := deps.Raw.(*GoModInfo)
	if !ok || info == nil {
		return nil
	}
	versions := make(map[string]string, len(info.AllRequirements))
	for module, version := range info.AllRequirements {
		versions[module] = e.analyzer.getEffectiveVersion(module, version, info.Replacements)
	}
	return versions
}

// BumpCoords maps each OSV bump to the go.mod-normalized module path used in
// rendered dep entries: OSV names v2+ modules without the /vN path suffix
// (e.g. "github.com/cli/go-gh" for the module "github.com/cli/go-gh/v2"), and
// normalizeModulePath resolves that against this modroot's requirements. The
// normalized path is used even when the module isn't found in go.mod at all -
// FilterBumps drops such entries anyway, so an unmatched key is harmless.
func (e *Ecosystem) BumpCoords(bumps []scan.SecurityBump, deps *ecosystem.ModuleDeps) map[string]scan.SecurityBump {
	info, ok := deps.Raw.(*GoModInfo)
	if !ok || info == nil {
		return nil
	}

	coords := make(map[string]scan.SecurityBump, len(bumps))
	for _, bump := range bumps {
		coord, _ := e.analyzer.normalizeModulePath(bump.Name, bump.FixedVersion, info)
		coords[coord] = bump
	}
	return coords
}

// FilterBumps merges the existing declared deps with fresh OSV bumps and
// runs Go's bump decisioning over the combined set: dedup-by-highest-semver,
// v2+ module path normalization, replace-directive-aware version comparison,
// and removal of no-ops/downgrades/missing modules. Graph coherence (pulling
// in release-group siblings and transitive requirement gaps) is deliberately
// NOT handled here - the bump simulation owns it with the real toolchain
// (go get / go mod tidy / MVS; see internal/simulate).
func (e *Ecosystem) FilterBumps(_ context.Context, existing []string, bumps []scan.SecurityBump, deps *ecosystem.ModuleDeps) []string {
	info, ok := deps.Raw.(*GoModInfo)
	if !ok || info == nil {
		return nil
	}

	candidate := make([]string, 0, len(existing)+len(bumps))
	candidate = append(candidate, existing...)
	for _, bump := range bumps {
		candidate = append(candidate, fmt.Sprintf("%s@%s", bump.Name, bump.FixedVersion))
	}

	_, filtered := e.analyzer.analyzeBumps(candidate, info)
	return filtered
}
