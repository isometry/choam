package gobump

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/scan"
)

// goReleaseIndex is the release-lookup seam between the stdlib staleness
// check and gorelease.Index, injectable for tests. Both methods return bare
// versions ("1.24.5") and error when the constrained release set is empty or
// the index cannot be loaded.
type goReleaseIndex interface {
	LatestAsOf(ctx context.Context, t time.Time, minorConstraint string) (string, error)
	LatestAvailable(ctx context.Context, minorConstraint string) (string, error)
}

// stdlibScanner is the OSV seam for the stdlib staleness check;
// *scan.VulnerabilityScanner satisfies it.
type stdlibScanner interface {
	ScanPackages(ctx context.Context, pkgs []scan.Package) (*scan.ScanResult, error)
}

// stdlibInput is the package-derived state evaluateStdlibStaleness works
// from: when the melange file was last committed (the build-time estimate),
// which go-package pin constraints apply, and - when known - which stdlib
// import paths are actually linked into the build artifacts.
type stdlibInput struct {
	CommitTime  time.Time
	Constraints []string            // distinct minor constraints ("" = unpinned)
	Linked      map[string]struct{} // linked stdlib import paths; nil = unknown
	Validated   bool                // whether Linked-based filtering applies
}

// stdlibTargetGOOS mirrors internal/scan's targetGOOS: melange builds linux
// packages, so a vulnerable import GOOS-constrained to other platforms can
// never be linked into an artifact CHOAM manages.
const stdlibTargetGOOS = "linux"

// evaluateStdlibStaleness decides, per go-package pin constraint, whether
// rebuilding with the newest allowed Go release would fix stdlib advisories
// present in the release the package was (estimatedly) last built with. The
// estimate is "latest release as of the melange file's last commit", per
// constraint. Fix availability is a two-scan diff: advisories affecting the
// assumed release whose IDs are absent at the rebuild release (the scanner's
// own fix-version logic decides what each release is affected by - nothing is
// re-derived here). When a validated linked-stdlib set is provided, advisories
// whose vulnerable imports are all outside it are demoted to informational
// (UnlinkedVulnIDs). Returns one StdlibBump per constraint with fixable,
// applicable advisories, plus human-readable messages; any index/scan failure
// returns an error for the caller to degrade on.
func evaluateStdlibStaleness(ctx context.Context, index goReleaseIndex, scanner stdlibScanner, in stdlibInput) ([]StdlibBump, []string, error) {
	var bumps []StdlibBump
	var messages []string

	filter := in.Linked != nil && in.Validated

	for _, constraint := range in.Constraints {
		assumed, err := index.LatestAsOf(ctx, in.CommitTime, constraint)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving Go release as of %s (pin %s): %w",
				in.CommitTime.Format(time.RFC3339), pinWord(constraint), err)
		}
		rebuild, err := index.LatestAvailable(ctx, constraint)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving latest available Go release (pin %s): %w", pinWord(constraint), err)
		}

		// Already on (or somehow past) the newest allowed release: a rebuild
		// changes nothing for this constraint.
		if goversion.Compare(assumed, rebuild) >= 0 {
			continue
		}

		atAssumed, err := scanStdlib(ctx, scanner, assumed)
		if err != nil {
			return nil, nil, err
		}
		if len(atAssumed) == 0 {
			continue
		}
		atRebuild, err := scanStdlib(ctx, scanner, rebuild)
		if err != nil {
			return nil, nil, err
		}

		remaining := make(map[string]struct{}, len(atRebuild))
		for _, vuln := range atRebuild {
			remaining[vuln.ID] = struct{}{}
		}

		seen := make(map[string]struct{}, len(atAssumed))
		var fixableIDs, unlinkedIDs []string
		for _, vuln := range atAssumed {
			if _, still := remaining[vuln.ID]; still {
				continue // not fixed by the rebuild release either
			}
			if _, dup := seen[vuln.ID]; dup {
				continue
			}
			seen[vuln.ID] = struct{}{}
			if filter && !stdlibVulnLinked(vuln, in.Linked) {
				unlinkedIDs = append(unlinkedIDs, vuln.ID)
				continue
			}
			fixableIDs = append(fixableIDs, vuln.ID)
		}
		sort.Strings(fixableIDs)
		sort.Strings(unlinkedIDs)

		switch {
		case len(fixableIDs) > 0:
			bumps = append(bumps, StdlibBump{
				AssumedGoVersion: assumed,
				AssumedFromDate:  in.CommitTime.UTC().Format(time.RFC3339),
				GoPackagePin:     constraint,
				RebuildGoVersion: rebuild,
				VulnIDs:          fixableIDs,
				UnlinkedVulnIDs:  unlinkedIDs,
				Validated:        filter,
			})
			messages = append(messages, fmt.Sprintf("stdlib: assumed go%s (last commit %s, pin %s); rebuilding with go%s fixes %s",
				assumed, in.CommitTime.UTC().Format("2006-01-02"), pinWord(constraint), rebuild, strings.Join(fixableIDs, ", ")))
		case len(unlinkedIDs) > 0:
			messages = append(messages, fmt.Sprintf("info: stdlib advisories a go%s rebuild would fix affect only packages not linked into build artifacts (%s; assumed go%s, pin %s) - no epoch bump proposed",
				rebuild, strings.Join(unlinkedIDs, ", "), assumed, pinWord(constraint)))
		}
	}

	return bumps, messages, nil
}

// scanStdlib OSV-scans the Go standard library at one release version.
func scanStdlib(ctx context.Context, scanner stdlibScanner, version string) ([]scan.Vulnerability, error) {
	result, err := scanner.ScanPackages(ctx, []scan.Package{{Name: "stdlib", Ecosystem: "Go", Version: version}})
	if err != nil {
		return nil, fmt.Errorf("scanning Go stdlib %s: %w", version, err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("scanning Go stdlib %s: %s", version, result.Error)
	}
	return result.Vulnerabilities, nil
}

// stdlibVulnLinked reports whether an advisory's vulnerable import paths
// intersect the artifact-linked stdlib set. Fail open exactly like
// internal/simulate's vulnApplies: no import metadata at all, or a pathless
// entry, counts as linked. Import entries GOOS-constrained away from linux
// are ignored (mirroring scan's applicableToTarget - such code can never be
// in a linux artifact, and Linked itself is a GOOS=linux import graph).
func stdlibVulnLinked(vuln scan.Vulnerability, linked map[string]struct{}) bool {
	if len(vuln.VulnerableImports) == 0 {
		return true
	}
	for _, imp := range vuln.VulnerableImports {
		if len(imp.GOOS) > 0 && !slices.Contains(imp.GOOS, stdlibTargetGOOS) {
			continue
		}
		if imp.Path == "" {
			return true
		}
		if _, ok := linked[imp.Path]; ok {
			return true
		}
	}
	return false
}

// pinWord renders a go-package pin constraint for messages.
func pinWord(constraint string) string {
	if constraint == "" {
		return "unpinned"
	}
	return constraint
}
