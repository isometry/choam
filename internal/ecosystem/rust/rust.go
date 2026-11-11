// Package rust implements the Rust/Cargo ecosystem.Ecosystem, backed by
// omnibump's RustAnalyzer.
package rust

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/chainguard-dev/omnibump/pkg/languages/rust"
	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/scan"
	"golang.org/x/mod/semver"
)

var errCargoLockNotFound = errors.New("manifest file Cargo.lock not found")

// Ecosystem implements ecosystem.Ecosystem for Rust/Cargo projects.
// omnibump's RustAnalyzer has no checkout-free AnalyzeRemote, so Analyze
// materializes the fetched Cargo.lock into a real temp directory (via
// ecosystem.WriteTempFiles) and calls the local Analyze against it.
type Ecosystem struct {
	analyzer *rust.RustAnalyzer
}

// New creates the Rust ecosystem implementation.
func New() *Ecosystem {
	return &Ecosystem{analyzer: &rust.RustAnalyzer{}}
}

func init() {
	ecosystem.Register("rust", func() ecosystem.Ecosystem { return New() })
}

func (e *Ecosystem) Name() string { return "rust" }

// ManifestFiles returns Cargo.lock only: omnibump's RustAnalyzer.Analyze
// reads Cargo.lock exclusively and never consults Cargo.toml.
func (e *Ecosystem) ManifestFiles() (required, optional []string) {
	return []string{"Cargo.lock"}, nil
}

func (e *Ecosystem) Analyze(ctx context.Context, files map[string][]byte) (*ecosystem.ModuleDeps, error) {
	lockContent, ok := files["Cargo.lock"]
	if !ok {
		return nil, errCargoLockNotFound
	}

	dir, cleanup, err := ecosystem.WriteTempFiles(ctx, map[string][]byte{"Cargo.lock": lockContent})
	if err != nil {
		return nil, err
	}
	defer cleanup()

	result, err := e.analyzer.Analyze(ctx, dir)
	if err != nil {
		return nil, err
	}

	deps := make([]ecosystem.Dep, 0, len(result.Dependencies))
	for _, key := range slices.Sorted(maps.Keys(result.Dependencies)) {
		info := result.Dependencies[key]
		deps = append(deps, ecosystem.Dep{
			Coord:   info.Name + "@" + info.Version,
			Name:    info.Name,
			Version: info.Version,
		})
	}

	return &ecosystem.ModuleDeps{Deps: deps, Raw: result}, nil
}

func (e *Ecosystem) ScanPackages(_ context.Context, deps *ecosystem.ModuleDeps) []scan.Package {
	seen := make(map[string]struct{}, len(deps.Deps))
	pkgs := make([]scan.Package, 0, len(deps.Deps))
	for _, dep := range deps.Deps {
		key := dep.Name + "@" + dep.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, scan.Package{Name: dep.Name, Version: dep.Version, Ecosystem: "crates.io"})
	}
	return pkgs
}

// BumpCoords maps each OSV bump to its rendered-grammar coordinate (see
// ecosystem.SplitDep): the crate name for a crate locked at one version,
// "crate@locked" for one locked at several, matching the pinned entries
// FilterBumps renders for it.
func (e *Ecosystem) BumpCoords(_ context.Context, bumps []scan.SecurityBump, deps *ecosystem.ModuleDeps) map[string]scan.SecurityBump {
	locked := lockedVersions(deps)
	coords := make(map[string]scan.SecurityBump, len(bumps))
	for _, bump := range bumps {
		coord := bump.Name
		if len(locked[bump.Name]) > 1 {
			coord += "@" + bump.CurrentVersion
		}
		coords[coord] = bump
	}
	return coords
}

// FilterBumps merges existing entries and candidate bumps per crate and
// Cargo semver line, keeping the highest version in each line (an existing
// entry is never lowered). A pinned entry "crate@from=to" belongs to the line
// of from, a bump to the line of its CurrentVersion. An entry is dropped when
// no locked version shares its line, or when the highest locked version in
// that line is already at or above it, so a stale pin never downgrades. A fix
// that is not a Cargo-compatible upgrade of its locked version (a different
// major, or for 0.x a different minor: 0.12 -> 0.14 is a breaking change
// under Cargo's caret rules, which Cargo.toml requirements - not fetched here
// - would refuse) is held back, never written. A crate locked at one version
// renders as "crate@version"; one locked at several renders one
// "crate@<locked>=version" per line, since omnibump keys plain entries by
// crate name and a second would overwrite the first. Omnibump's own per-line
// constraint resolution is not replicated.
//
// ponytail: two locked versions in the same semver line (Cargo normally
// merges them) share one entry, pinned from the highest; split by exact
// locked version if that ever shows up in a real Cargo.lock.
func (e *Ecosystem) FilterBumps(_ context.Context, existing []string, bumps []scan.SecurityBump, deps *ecosystem.ModuleDeps) ([]string, []ecosystem.HeldBump) {
	locked := lockedVersions(deps)

	type crateLine struct{ name, line string }
	candidates := make(map[crateLine]string, len(existing)+len(bumps))
	raise := func(name, from, version string) {
		key := crateLine{name, cargoLine(from)}
		if current, ok := candidates[key]; !ok || compareCrateVersions(version, current) > 0 {
			candidates[key] = version
		}
	}
	for _, dep := range existing {
		coord, version, ok := ecosystem.SplitDep(dep)
		if !ok {
			continue
		}
		name, from, pinned := strings.Cut(coord, "@")
		if !pinned {
			from = version
		}
		raise(name, from, version)
	}
	var held []ecosystem.HeldBump
	for _, bump := range bumps {
		if len(locked[bump.Name]) == 0 {
			continue // crate not present in this modroot's Cargo.lock
		}
		if !cargoCompatible(bump.CurrentVersion, bump.FixedVersion) {
			held = append(held, ecosystem.HeldBump{Bump: bump, Reason: fmt.Sprintf(
				"fix %s is a semver-incompatible upgrade from locked %s", bump.FixedVersion, bump.CurrentVersion)})
			continue
		}
		raise(bump.Name, bump.CurrentVersion, bump.FixedVersion)
	}

	var result []string
	for key, version := range candidates {
		versions := locked[key.name]
		var highest string
		for _, v := range versions {
			if cargoLine(v) == key.line && (highest == "" || compareCrateVersions(v, highest) > 0) {
				highest = v
			}
		}
		if highest == "" || compareCrateVersions(version, highest) <= 0 {
			continue // no locked version in this line, or already at/above it
		}
		if len(versions) == 1 {
			result = append(result, key.name+"@"+version)
		} else {
			result = append(result, key.name+"@"+highest+"="+version)
		}
	}

	sort.Strings(result)
	return result, held
}

// lockedVersions maps each crate to its distinct locked versions.
func lockedVersions(deps *ecosystem.ModuleDeps) map[string][]string {
	locked := make(map[string][]string, len(deps.Deps))
	for _, dep := range deps.Deps {
		if !slices.Contains(locked[dep.Name], dep.Version) {
			locked[dep.Name] = append(locked[dep.Name], dep.Version)
		}
	}
	return locked
}

// compareCrateVersions compares two bare crate versions as semver.
func compareCrateVersions(a, b string) int {
	return semver.Compare(scan.EnsureVPrefix(a), scan.EnsureVPrefix(b))
}

// cargoCompatible reports whether to is a Cargo caret-compatible upgrade of
// from.
func cargoCompatible(from, to string) bool {
	return cargoLine(from) == cargoLine(to)
}

// cargoLine returns the Cargo caret-compatibility line of a version: the
// major for 1.x+, the minor for 0.x, the patch for 0.0.x ("" if invalid).
func cargoLine(version string) string {
	v := scan.EnsureVPrefix(version)
	switch {
	case !semver.IsValid(v):
		return ""
	case semver.Major(v) != "v0":
		return semver.Major(v)
	case semver.MajorMinor(v) != "v0.0":
		return semver.MajorMinor(v)
	default:
		return strings.TrimSuffix(semver.Canonical(v), semver.Prerelease(v))
	}
}
