// Package java implements the Maven-based Java ecosystem.Ecosystem, backed
// by omnibump's MavenAnalyzer.
package java

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/chainguard-dev/omnibump/pkg/languages/java/maven"
	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/scan"
)

var (
	errPomNotFound = errors.New("pom.xml not found")
	errNoAnalysis  = errors.New("no analysis produced for pom.xml")
)

// Ecosystem implements ecosystem.Ecosystem for Maven-based Java projects.
// Gradle is not yet supported: melange has no build-pipeline signal to
// auto-detect a first-time Gradle package (unlike go/build for Go or
// maven/pombump for Maven), so it isn't reachable through the
// language-detection path internal/gobump wires up.
//
// Known limitation: omnibump's Maven analyzer resolves properties declared
// in a <parent> POM's chain, but only within the files it's given - and
// CHOAM fetches only the modroot's own pom.xml (no parent chase). A
// dependency whose version is a property defined solely in an unfetched
// parent POM is skipped rather than mis-scanned.
type Ecosystem struct {
	analyzer *maven.MavenAnalyzer
}

// New creates the Java (Maven) ecosystem implementation.
func New() *Ecosystem {
	return &Ecosystem{analyzer: &maven.MavenAnalyzer{}}
}

func init() {
	ecosystem.Register("java", func() ecosystem.Ecosystem { return New() })
}

func (e *Ecosystem) Name() string { return "java" }

func (e *Ecosystem) ManifestFiles() []string { return []string{"pom.xml"} }

func (e *Ecosystem) Analyze(ctx context.Context, files map[string][]byte) (*ecosystem.ModuleDeps, error) {
	pomContent, ok := files["pom.xml"]
	if !ok {
		return nil, errPomNotFound
	}

	remote, err := e.analyzer.AnalyzeRemote(ctx, map[string][]byte{"pom.xml": pomContent})
	if err != nil {
		return nil, err
	}
	if len(remote.FileAnalyses) == 0 {
		return nil, errNoAnalysis
	}
	result := remote.FileAnalyses[0].Analysis

	deps := make([]ecosystem.Dep, 0, len(result.Dependencies))
	for _, info := range result.Dependencies {
		version := info.Version
		if info.UsesProperty {
			resolved, ok := result.Properties[info.PropertyName]
			if !ok {
				// Property not resolvable from this single pom.xml (likely
				// defined in an unfetched parent) - skip rather than scan a
				// literal "${...}" string as a version.
				continue
			}
			version = resolved
		}

		groupID, _ := info.Metadata["groupId"].(string)
		artifactID, _ := info.Metadata["artifactId"].(string)

		deps = append(deps, ecosystem.Dep{
			Coord:      info.Name,
			Name:       info.Name,
			Version:    version,
			GroupID:    groupID,
			ArtifactID: artifactID,
		})
	}

	return &ecosystem.ModuleDeps{Deps: deps, Raw: result}, nil
}

func (e *Ecosystem) ScanPackages(deps *ecosystem.ModuleDeps) []scan.Package {
	pkgs := make([]scan.Package, 0, len(deps.Deps))
	for _, dep := range deps.Deps {
		if dep.Version == "" {
			continue
		}
		pkgs = append(pkgs, scan.Package{Name: dep.Name, Version: dep.Version, Ecosystem: "Maven"})
	}
	return pkgs
}

// BumpCoords maps each OSV bump (named "groupId:artifactId", colon) to the
// "groupId@artifactId" coordinate the rendered Maven grammar uses, resolved
// from this modroot's own pom.xml entries when present (matching FilterBumps'
// rendering exactly). A bump for a coordinate absent from the pom falls back
// to a plain colon->at-sign substitution - FilterBumps drops such entries
// anyway, so the unmatched key is harmless.
func (e *Ecosystem) BumpCoords(bumps []scan.SecurityBump, deps *ecosystem.ModuleDeps) map[string]scan.SecurityBump {
	byName := make(map[string]ecosystem.Dep, len(deps.Deps))
	for _, dep := range deps.Deps {
		byName[dep.Name] = dep
	}

	coords := make(map[string]scan.SecurityBump, len(bumps))
	for _, bump := range bumps {
		coord := strings.Replace(bump.Name, ":", "@", 1)
		if dep, ok := byName[bump.Name]; ok && dep.GroupID != "" && dep.ArtifactID != "" {
			coord = dep.GroupID + "@" + dep.ArtifactID
		}
		coords[coord] = bump
	}
	return coords
}

// FilterBumps keeps a candidate bump only when its groupId:artifactId
// coordinate is present in this modroot's pom.xml and the candidate version
// is newer than what's currently declared, per Maven's (non-semver) version
// ordering. Rendered entries use the "groupId@artifactId@version" grammar
// the melange bump pipeline expects for Maven.
func (e *Ecosystem) FilterBumps(_ context.Context, existing []string, bumps []scan.SecurityBump, deps *ecosystem.ModuleDeps) []string {
	type coordInfo struct {
		groupID, artifactID, version string
	}
	byCoord := make(map[string]coordInfo, len(deps.Deps))
	for _, dep := range deps.Deps {
		byCoord[dep.Name] = coordInfo{groupID: dep.GroupID, artifactID: dep.ArtifactID, version: dep.Version}
	}

	candidateVersions := make(map[string]string, len(existing)+len(bumps))
	for _, dep := range existing {
		parts := strings.Split(dep, "@")
		if len(parts) < 3 {
			continue
		}
		candidateVersions[parts[0]+":"+parts[1]] = parts[2]
	}
	for _, bump := range bumps {
		candidateVersions[bump.Name] = bump.FixedVersion
	}

	var result []string
	for coord, version := range candidateVersions {
		info, present := byCoord[coord]
		if !present {
			continue // coordinate not present in this modroot's pom.xml
		}
		if scan.CompareMavenVersions(version, info.version) <= 0 {
			continue // not newer - no-op or downgrade
		}
		result = append(result, fmt.Sprintf("%s@%s@%s", info.groupID, info.artifactID, version))
	}

	sort.Strings(result)
	return result
}
