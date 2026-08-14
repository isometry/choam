package gobump

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/isometry/choam/internal/gorelease"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/scan"
)

// stdlibToolchainLagMargin models how far the distro (Wolfi) Go toolchain
// package trails an upstream Go release: proxy.golang.org can list a release
// hours after it is tagged, but the toolchain package that actually rebuilds
// the artifact lags by days. Applied to BOTH sides of the staleness diff so a
// release-day proxy entry can't produce a false "fixed" claim (the epoch-bump
// commit would then anchor the next run's assumed version and the gap would
// never be re-flagged).
const stdlibToolchainLagMargin = 3 * 24 * time.Hour

// goReleaseIndex is the release-lookup seam between the stdlib staleness
// check and gorelease.Index, injectable for tests. All methods return bare
// versions ("1.24.5") and error when the constrained release set is empty or
// the index cannot be loaded; LatestAvailableAsOf reports gorelease.ErrNoReleases
// when nothing is published early enough to satisfy the cutoff.
type goReleaseIndex interface {
	LatestAsOf(ctx context.Context, t time.Time, minorConstraint string) (string, error)
	LatestAvailable(ctx context.Context, minorConstraint string) (string, error)
	LatestAvailableAsOf(ctx context.Context, cutoff time.Time, minorConstraint string) (string, error)
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
	Constraints []string // distinct minor constraints ("" = unpinned)
	// RebuildConstraints maps an entry of Constraints to the constraint the
	// NEXT build will actually use (a same-run go-package pin raise, see
	// rebuildConstraintsFor); a missing key - or a nil map - means the
	// constraint is unchanged. The assumed side always uses Constraints (the
	// pristine config is the historical truth).
	RebuildConstraints map[string]string
	Linked             map[string]struct{} // linked stdlib import paths; nil = unknown
	Validated          bool                // whether Linked-based filtering applies
	// Now is the reference time for the rebuild side's publication-age margin
	// (the rebuild target is the newest release published <= Now - margin). A
	// zero value defaults to time.Now(); tests set it explicitly.
	Now time.Time
}

// stdlibTargetGOOS mirrors internal/scan's targetGOOS: melange builds linux
// packages, so a vulnerable import GOOS-constrained to other platforms can
// never be linked into an artifact CHOAM manages.
const stdlibTargetGOOS = "linux"

// evaluateStdlibStaleness decides, per go-package pin constraint, whether
// rebuilding with the newest allowed Go release would fix stdlib advisories
// present in the release the package was (estimatedly) last built with. The
// estimate is "latest release as of the melange file's last commit", per
// constraint (always the pristine config's pin - the historical truth); the
// rebuild target uses the mapped rebuild constraint when this run raised the
// pin (in.RebuildConstraints). Fix availability is a two-scan diff: advisories
// affecting the assumed release whose IDs are absent at the rebuild release
// (the scanner's own fix-version logic decides what each release is affected
// by - nothing is re-derived here). When a validated linked-stdlib set is
// provided, advisories whose vulnerable imports are all outside it are demoted
// to informational (UnlinkedVulnIDs). Advisories a pinned rebuild cannot fix
// but an unconstrained newer Go minor would (checked lazily, one extra scan at
// most) yield an informational raise-the-pin message, never a bump.
//
// A publication-age lag margin (stdlibToolchainLagMargin) is applied to BOTH
// sides so a release the module proxy lists but the distro toolchain hasn't
// shipped yet can't yield a false "fixed" claim: the assumed side subtracts
// the margin from CommitTime (over-detecting a slightly older toolchain is
// safe), and the rebuild target is the newest release published on or before
// in.Now minus the margin. When the margin defers a fresher release an
// informational message names both; a brand-new minor whose only releases fall
// entirely inside the margin is skipped with a message rather than bumped.
//
// Returns one StdlibBump per constraint with fixable, applicable advisories,
// plus human-readable messages; any index/scan failure returns an error for the
// caller to degrade on.
func evaluateStdlibStaleness(ctx context.Context, index goReleaseIndex, scanner stdlibScanner, in stdlibInput) ([]StdlibBump, []string, error) {
	var bumps []StdlibBump
	var messages []string

	filter := in.Linked != nil && in.Validated

	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	rebuildCutoff := now.Add(-stdlibToolchainLagMargin)

	// Lazy, memoized view of the newest Go release overall - only consulted
	// when a pinned constraint's rebuild leaves residual advisories behind.
	var latestVersion string
	resolveLatestVersion := func() (string, error) {
		if latestVersion == "" {
			v, err := index.LatestAvailable(ctx, "")
			if err != nil {
				return "", fmt.Errorf("resolving latest available Go release (pin %s): %w", pinWord(""), err)
			}
			latestVersion = v
		}
		return latestVersion, nil
	}
	var latestVulnIDs map[string]struct{}
	resolveLatestVulnIDs := func(version string) (map[string]struct{}, error) {
		if latestVulnIDs == nil {
			vulns, err := scanStdlib(ctx, scanner, version)
			if err != nil {
				return nil, err
			}
			latestVulnIDs = make(map[string]struct{}, len(vulns))
			for _, vuln := range vulns {
				latestVulnIDs[vuln.ID] = struct{}{}
			}
		}
		return latestVulnIDs, nil
	}

	for _, constraint := range in.Constraints {
		rebuildConstraint := constraint
		if mapped, ok := in.RebuildConstraints[constraint]; ok && mapped != "" {
			rebuildConstraint = mapped
		}

		// Assumed side: subtract the lag margin from the commit time. This
		// over-detects only (a slightly older toolchain than reality), which is
		// the safe direction for exposure detection.
		assumed, err := index.LatestAsOf(ctx, in.CommitTime.Add(-stdlibToolchainLagMargin), constraint)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving Go release as of %s (pin %s): %w",
				in.CommitTime.Format(time.RFC3339), pinWord(constraint), err)
		}

		// Rebuild side: LatestAvailable first so an unknown pin still hard-errors
		// (and to name the fresher release the margin might defer)...
		latestAvailable, err := index.LatestAvailable(ctx, rebuildConstraint)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving latest available Go release (pin %s): %w", pinWord(rebuildConstraint), err)
		}
		// ...then age the actual rebuild target back behind the publication-age
		// margin: the distro toolchain package trails the module proxy.
		rebuild, err := index.LatestAvailableAsOf(ctx, rebuildCutoff, rebuildConstraint)
		if err != nil {
			if errors.Is(err, gorelease.ErrNoReleases) {
				// A brand-new minor whose only release(s) fall entirely inside
				// the margin: nothing publication-aged enough to rebuild against
				// yet. Skip with a message rather than bump or error.
				messages = append(messages, fmt.Sprintf("info: latest go%s release (pin %s) is within the %d-day publication-age margin - deferring the stdlib rebuild target until a release is old enough",
					latestAvailable, pinWord(rebuildConstraint), marginDays()))
				continue
			}
			return nil, nil, fmt.Errorf("resolving latest available Go release within publication-age margin (pin %s): %w", pinWord(rebuildConstraint), err)
		}
		if goversion.Compare(latestAvailable, rebuild) > 0 {
			// The margin defers a fresher release the distro toolchain likely
			// hasn't shipped: rebuild against the aged target and name both.
			messages = append(messages, fmt.Sprintf("info: go%s (pin %s) is within the %d-day publication-age margin - using go%s as the stdlib rebuild target for now",
				latestAvailable, pinWord(rebuildConstraint), marginDays(), rebuild))
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
		var fixableIDs, unlinkedIDs, residualIDs []string
		for _, vuln := range atAssumed {
			if _, dup := seen[vuln.ID]; dup {
				continue
			}
			seen[vuln.ID] = struct{}{}
			if _, still := remaining[vuln.ID]; still {
				// Not fixed by the rebuild release either - a candidate for
				// the raise-the-pin hint below when this constraint is pinned.
				residualIDs = append(residualIDs, vuln.ID)
				continue
			}
			if filter && !stdlibVulnLinked(vuln, in.Linked) {
				unlinkedIDs = append(unlinkedIDs, vuln.ID)
				continue
			}
			fixableIDs = append(fixableIDs, vuln.ID)
		}
		sort.Strings(fixableIDs)
		sort.Strings(unlinkedIDs)

		rebuildPin := ""
		if rebuildConstraint != constraint {
			rebuildPin = rebuildConstraint
		}

		switch {
		case len(fixableIDs) > 0:
			bumps = append(bumps, StdlibBump{
				AssumedGoVersion:    assumed,
				AssumedFromDate:     in.CommitTime.UTC().Format(time.RFC3339),
				GoPackagePin:        constraint,
				RebuildGoPackagePin: rebuildPin,
				RebuildGoVersion:    rebuild,
				VulnIDs:             fixableIDs,
				UnlinkedVulnIDs:     unlinkedIDs,
				Validated:           filter,
			})
			if rebuildPin != "" {
				messages = append(messages, fmt.Sprintf("stdlib: assumed go%s (last commit %s, pin %s); rebuilding with go%s (pin raised to %s) fixes %s",
					assumed, in.CommitTime.UTC().Format("2006-01-02"), pinWord(constraint), rebuild, rebuildConstraint, strings.Join(fixableIDs, ", ")))
			} else {
				messages = append(messages, fmt.Sprintf("stdlib: assumed go%s (last commit %s, pin %s); rebuilding with go%s fixes %s",
					assumed, in.CommitTime.UTC().Format("2006-01-02"), pinWord(constraint), rebuild, strings.Join(fixableIDs, ", ")))
			}
		case len(unlinkedIDs) > 0:
			messages = append(messages, fmt.Sprintf("info: stdlib advisories a go%s rebuild would fix affect only packages not linked into build artifacts (%s; assumed go%s, pin %s) - no epoch bump proposed",
				rebuild, strings.Join(unlinkedIDs, ", "), assumed, pinWord(constraint)))
		}

		// Unfixable-within-pin hint: advisories the pinned rebuild leaves
		// behind that the newest Go overall has fixed only exist above the
		// pin's minor - message only, never a bump (raising the pin is the
		// user's call; this run's own raises are already reflected in
		// rebuildConstraint).
		if rebuildConstraint == "" || len(residualIDs) == 0 {
			continue
		}
		latest, err := resolveLatestVersion()
		if err != nil {
			return nil, nil, err
		}
		if latest == rebuild {
			continue // the pin already allows the newest Go - nothing above it
		}
		atLatest, err := resolveLatestVulnIDs(latest)
		if err != nil {
			return nil, nil, err
		}
		var unfixableIDs []string
		for _, id := range residualIDs {
			if _, still := atLatest[id]; !still {
				unfixableIDs = append(unfixableIDs, id)
			}
		}
		if len(unfixableIDs) == 0 {
			continue
		}
		sort.Strings(unfixableIDs)
		messages = append(messages, fmt.Sprintf("stdlib: %d %s (%s) affecting the go%s-pinned build %s only fixed in newer Go minors - consider raising the go-package pin",
			len(unfixableIDs), pluralize(len(unfixableIDs), "vulnerability", "vulnerabilities"), strings.Join(unfixableIDs, ", "),
			rebuildConstraint, pluralize(len(unfixableIDs), "is", "are")))
	}

	return bumps, messages, nil
}

// marginDays renders stdlibToolchainLagMargin in whole days for messages.
func marginDays() int {
	return int(stdlibToolchainLagMargin / (24 * time.Hour))
}

// pluralize picks the singular or plural word for a count.
func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
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
