// Package rust implements the Rust/Cargo ecosystem.Ecosystem, backed by
// omnibump's RustAnalyzer.
package rust

import (
	"context"
	"errors"
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
func (e *Ecosystem) ManifestFiles() []string { return []string{"Cargo.lock"} }

func (e *Ecosystem) Analyze(ctx context.Context, files map[string][]byte) (*ecosystem.ModuleDeps, error) {
	lockContent, ok := files["Cargo.lock"]
	if !ok {
		return nil, errCargoLockNotFound
	}

	dir, cleanup, err := ecosystem.WriteTempFiles(map[string][]byte{"Cargo.lock": lockContent})
	if err != nil {
		return nil, err
	}
	defer cleanup()

	result, err := e.analyzer.Analyze(ctx, dir)
	if err != nil {
		return nil, err
	}

	deps := make([]ecosystem.Dep, 0, len(result.Dependencies))
	for _, info := range result.Dependencies {
		deps = append(deps, ecosystem.Dep{
			Coord:   info.Name + "@" + info.Version,
			Name:    info.Name,
			Version: info.Version,
		})
	}

	return &ecosystem.ModuleDeps{Deps: deps, Raw: result}, nil
}

func (e *Ecosystem) ScanPackages(deps *ecosystem.ModuleDeps) []scan.Package {
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
func (e *Ecosystem) BumpCoords(bumps []scan.SecurityBump, _ *ecosystem.ModuleDeps) map[string]scan.SecurityBump {
	coords := make(map[string]scan.SecurityBump, len(bumps))
	for _, bump := range bumps {
		coords[bump.Name] = bump
	}
	return coords
}

// FilterBumps keeps a candidate bump only when the crate is present in this
// modroot's Cargo.lock and the candidate version is newer than the highest
// locked version (Cargo.lock may pin a crate at multiple versions across the
// dependency graph). This does not replicate omnibump's own per-line
// semver-constraint resolution (that requires parsing Cargo.toml's caret
// requirements, which CHOAM doesn't fetch) - it's a simpler "is this newer
// than what's locked" check, sufficient to decide whether a bump applies.
func (e *Ecosystem) FilterBumps(_ context.Context, existing []string, bumps []scan.SecurityBump, deps *ecosystem.ModuleDeps) []string {
	maxLocked := make(map[string]string, len(deps.Deps))
	for _, dep := range deps.Deps {
		if current, ok := maxLocked[dep.Name]; !ok || semver.Compare(scan.EnsureVPrefix(dep.Version), scan.EnsureVPrefix(current)) > 0 {
			maxLocked[dep.Name] = dep.Version
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
	for _, bump := range bumps {
		candidateVersions[bump.Name] = bump.FixedVersion
	}

	var result []string
	for name, version := range candidateVersions {
		locked, ok := maxLocked[name]
		if !ok {
			continue // crate not present in this modroot's Cargo.lock
		}
		if semver.Compare(scan.EnsureVPrefix(version), scan.EnsureVPrefix(locked)) <= 0 {
			continue // not newer than what's already locked
		}
		result = append(result, name+"@"+version)
	}

	sort.Strings(result)
	return result
}
