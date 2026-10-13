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

// BumpCoords maps each OSV bump to its rendered-grammar coordinate. For Rust
// the two coincide: OSV names crates exactly as Cargo.lock does, and the
// rendered grammar is "crate@version", so the coordinate is the crate name.
func (e *Ecosystem) BumpCoords(_ context.Context, bumps []scan.SecurityBump, _ *ecosystem.ModuleDeps) map[string]scan.SecurityBump {
	coords := make(map[string]scan.SecurityBump, len(bumps))
	for _, bump := range bumps {
		coords[bump.Name] = bump
	}
	return coords
}

// FilterBumps keeps a candidate bump only when the crate is present in this
// modroot's Cargo.lock and the candidate version is newer than the highest
// locked version. An existing entry above an advisory's fix is kept (never
// lowered). A fix is held back, never written, when the crate is locked at
// several versions (one entry cannot say which to move) or when it is not a
// Cargo-compatible upgrade of the locked version (a different major, or for
// 0.x a different minor: 0.12 -> 0.14 is a breaking change under Cargo's
// caret rules, which Cargo.toml requirements - not fetched here - would
// refuse). Omnibump's own per-line constraint resolution is not replicated.
func (e *Ecosystem) FilterBumps(_ context.Context, existing []string, bumps []scan.SecurityBump, deps *ecosystem.ModuleDeps) ([]string, []ecosystem.HeldBump) {
	locked := make(map[string][]string, len(deps.Deps))
	for _, dep := range deps.Deps {
		if !slices.Contains(locked[dep.Name], dep.Version) {
			locked[dep.Name] = append(locked[dep.Name], dep.Version)
		}
	}

	candidateVersions := make(map[string]string, len(existing)+len(bumps))
	for _, dep := range existing {
		name, version, ok := strings.Cut(dep, "@")
		if !ok {
			continue
		}
		candidateVersions[name] = version
	}
	var held []ecosystem.HeldBump
	for _, bump := range bumps {
		versions := locked[bump.Name]
		switch {
		case len(versions) == 0:
			continue // crate not present in this modroot's Cargo.lock
		case len(versions) > 1:
			slices.SortFunc(versions, compareCrateVersions)
			held = append(held, ecosystem.HeldBump{Bump: bump, Reason: fmt.Sprintf(
				"crate locked at multiple versions (%s): one bump entry cannot target a single one", strings.Join(versions, ", "))})
			continue
		case !cargoCompatible(versions[0], bump.FixedVersion):
			held = append(held, ecosystem.HeldBump{Bump: bump, Reason: fmt.Sprintf(
				"fix %s is a semver-incompatible upgrade from locked %s", bump.FixedVersion, versions[0])})
			continue
		}
		if current, ok := candidateVersions[bump.Name]; ok && compareCrateVersions(current, bump.FixedVersion) >= 0 {
			continue // an existing pin at or above the fix is kept
		}
		candidateVersions[bump.Name] = bump.FixedVersion
	}

	var result []string
	for name, version := range candidateVersions {
		versions := locked[name]
		if len(versions) == 0 {
			continue // crate not present in this modroot's Cargo.lock
		}
		if compareCrateVersions(version, slices.MaxFunc(versions, compareCrateVersions)) <= 0 {
			continue // not newer than what's already locked
		}
		result = append(result, name+"@"+version)
	}

	sort.Strings(result)
	return result, held
}

// compareCrateVersions compares two bare crate versions as semver.
func compareCrateVersions(a, b string) int {
	return semver.Compare(scan.EnsureVPrefix(a), scan.EnsureVPrefix(b))
}

// cargoCompatible reports whether to is a Cargo caret-compatible upgrade of
// from: the same major for 1.x+, the same minor for 0.x, the same patch for
// 0.0.x.
func cargoCompatible(from, to string) bool {
	f, t := scan.EnsureVPrefix(from), scan.EnsureVPrefix(to)
	switch {
	case semver.Major(f) != "v0":
		return semver.Major(f) == semver.Major(t)
	case semver.MajorMinor(f) != "v0.0":
		return semver.MajorMinor(f) == semver.MajorMinor(t)
	default:
		release := func(v string) string { return strings.TrimSuffix(semver.Canonical(v), semver.Prerelease(v)) }
		return release(f) == release(t)
	}
}
