// Package ecosystem encapsulates all language-specific behavior needed to
// detect and apply dependency-vulnerability bumps for a melange package.
// Exactly one Ecosystem is selected per package (see internal/gobump's
// language-detection logic); every ecosystem implementation renders melange
// bump/go-bump pipeline entries in its own grammar, but the pipeline
// reconciliation logic in internal/gobump treats those entries as opaque
// strings and is itself language-agnostic.
package ecosystem

import (
	"context"

	"github.com/isometry/choam/internal/scan"
)

// Ecosystem encapsulates all language-specific behavior for dependency
// vulnerability bumping.
type Ecosystem interface {
	// Name is the melange with.language: token ("go", "rust", "java").
	Name() string

	// ManifestFiles are the modroot-relative filenames to fetch for a modroot.
	ManifestFiles() []string

	// Analyze turns fetched manifest content into a normalized per-modroot
	// dependency view. files is keyed by the basenames from ManifestFiles().
	// Implementations that can't analyze in-memory content (because the
	// underlying tooling requires a real directory) are responsible for
	// materializing files to a temporary directory internally.
	Analyze(ctx context.Context, files map[string][]byte) (*ModuleDeps, error)

	// ScanPackages maps the modroot's dependencies into OSV query inputs.
	ScanPackages(deps *ModuleDeps) []scan.Package

	// FilterBumps merges a modroot's existing declared melange deps with
	// fresh OSV security bumps and returns the desired melange deps for
	// that modroot, rendered in this language's grammar, deduplicated and
	// with no-ops/downgrades/missing entries removed. ctx bounds any
	// network access an implementation may need; current implementations
	// are offline and ignore it.
	FilterBumps(ctx context.Context, existing []string, bumps []scan.SecurityBump, deps *ModuleDeps) []string

	// BumpCoords maps each OSV security bump to the coordinate this
	// ecosystem's rendered dep grammar uses for it - the segment before the
	// LAST "@" of a rendered entry. OSV's own package names don't always
	// match: Maven's are "groupId:artifactId" (colon) while the rendered
	// grammar is "groupId@artifactId@version", and OSV names v2+ Go modules
	// without the /vN path suffix go.mod requires. Callers use the keys to
	// recognize which rendered deps fix a flagged vulnerability, and the
	// values to attribute advisory IDs / prior versions to them.
	BumpCoords(bumps []scan.SecurityBump, deps *ModuleDeps) map[string]scan.SecurityBump
}

// ModuleDeps is a normalized dependency view for one modroot.
type ModuleDeps struct {
	// Deps lists every dependency this ecosystem found for the modroot.
	Deps []Dep

	// Raw carries the ecosystem's own internal representation (e.g. a
	// *golang.GoModInfo), opaque to callers outside that ecosystem's package.
	// FilterBumps type-asserts it back; nothing else should depend on its shape.
	Raw any
}

// Dep is a single dependency in a modroot's normalized view.
type Dep struct {
	// Coord is the ecosystem-natural coordinate: Go "module/path", Rust
	// "crate", Java "groupId:artifactId".
	Coord string
	// Name is the OSV query name for this dependency (often equal to Coord).
	Name       string
	Version    string
	GroupID    string // Java only
	ArtifactID string // Java only
	Indirect   bool
}
