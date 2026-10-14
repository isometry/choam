package gobump

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/isometry/choam/internal/git"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/simulate"
)

// StdlibStage checks whether the package is stale against the Go standard
// library: it estimates the toolchain the package was last built with (latest
// Go release as of the melange file's last commit, per go-package pin
// constraint), diffs OSV stdlib findings against the newest allowed release,
// and records a StdlibBump when a rebuild would fix advisories - which the
// epoch stage then turns into an epoch bump, even with ZERO dependency
// changes (the rebuild itself is the fix). Independently of git, it records
// the rebuild Go version(s) (StdlibRebuildGoVersions): whatever bumps the
// epoch, the rebuild uses them, which is the apk stage's stdlib proof.
//
// The stage is strictly best-effort: every failure degrades to a
// skip-with-message and never fails the bump run. The last-commit Dirty gate
// doubles as the idempotency guard for the staleness trigger - once this
// run's epoch bump is written, the file is dirty and subsequent runs skip the
// trigger until the change is committed (in-run dependency edits live only in
// CurrentYAML, so they never trip it).
type StdlibStage struct {
	processor.BaseStage
	Analyzer *Analyzer
	Options  Options

	// Test seams, mirroring SimulationStage's style: overridable functions
	// and narrow interfaces defaulting to the real implementations.
	lastCommit func(ctx context.Context, filePath string) (*git.FileCommitInfo, error)
	index      goReleaseIndex
	scanner    simulate.Scanner

	// linkStd computes the artifact-linked stdlib import set from a fresh
	// source checkout - the fallback used only when the simulation didn't
	// already provide gp.LinkedStdPackages AND an unfiltered evaluation
	// found fixable advisories worth validating.
	linkStd func(ctx context.Context, gp *Processor) (map[string]struct{}, error)
}

func NewStdlibStage(analyzer *Analyzer, opts Options) *StdlibStage {
	stage := &StdlibStage{
		BaseStage: processor.BaseStage{
			StageName:        "stdlib_check",
			StageDescription: "Check for Go stdlib vulnerabilities fixable by a toolchain rebuild",
		},
		Analyzer:   analyzer,
		Options:    opts,
		lastCommit: git.LastCommitInfo,
	}
	if analyzer != nil {
		stage.index = analyzer.goReleases
		stage.scanner = analyzer.vulnerabilityScanner
	}
	stage.linkStd = stage.checkoutLinkedStd
	return stage
}

// ShouldRun gates on the option flag and on the package actually building Go
// code (go/build or go/install steps - see scanBuildSteps): only such
// packages embed the stdlib in their artifacts. Deliberately independent of
// vulnerability findings or bump actions - the pipeline runner evaluates
// each stage's ShouldRun on its own, so this stage runs even when every
// earlier stage was skipped (a package with no dependency changes can still
// need a stdlib rebuild).
func (s *StdlibStage) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	gp, err := asBump(p)
	if err != nil {
		return false, err
	}
	if !s.Options.StdlibCheck || gp.Config == nil {
		return false, nil
	}
	scan := scanBuildSteps(ctx, gp.Config)
	return len(scan.units["go"]) > 0 || len(scan.versionedInstalls) > 0, nil
}

// Apply runs the staleness check. EVERY failure path degrades to a
// skip-with-message and returns nil - this stage must never fail the run.
func (s *StdlibStage) Apply(ctx context.Context, p processor.Processor) error {
	gp, err := asBump(p)
	if err != nil {
		return err
	}

	if s.index == nil || s.scanner == nil {
		s.skipWarn(ctx, gp, "stdlib: release index/scanner unavailable - skipping stdlib staleness check")
		return nil
	}

	// Constraints come from the pristine config (the historical truth the
	// assumed side needs); the rebuild side additionally reflects go-package
	// pins this same run raised (the applier runs before this stage).
	constraints := distinctMinorConstraints(goToolchainPins(ctx, gp.Config))
	in := stdlibInput{
		Constraints:        constraints,
		RebuildConstraints: rebuildConstraintsFor(constraints, gp.RaisedPinMinors),
		Linked:             gp.LinkedStdPackages,
		Validated:          gp.LinkedStdPackages != nil,
		Now:                time.Now(),
	}

	// The rebuild toolchain first, independent of git: any epoch bump this
	// run makes rebuilds with it, so it is the stdlib proof the apk stage
	// needs even when the staleness trigger below is skipped.
	versions, unknown, err := resolveRebuildVersions(ctx, s.index, in)
	if err != nil {
		return cancelledOr(ctx, func() { s.skipWarn(ctx, gp, fmt.Sprintf("stdlib: staleness check unavailable (%v) - skipping", err)) })
	}
	if !unknown {
		gp.StdlibRebuildGoVersions = versions
	}

	info, err := s.commitInfo(ctx, gp, rebuildToolchainWord(versions, unknown))
	if info == nil {
		return err
	}
	in.CommitTime = info.Time

	bumps, messages, err := evaluateStdlibStaleness(ctx, s.index, s.scanner, in)
	if err != nil {
		return cancelledOr(ctx, func() { s.skipWarn(ctx, gp, fmt.Sprintf("stdlib: staleness check unavailable (%v) - skipping", err)) })
	}

	// Fallback checkout: only worth a clone when the preliminary unfiltered
	// evaluation actually found fixable advisories to validate against the
	// artifact's linked stdlib set.
	if len(bumps) > 0 && in.Linked == nil && s.Options.Validate {
		if bumps, messages, err = s.filterByLinkedStd(ctx, gp, in, bumps, messages); err != nil {
			return err
		}
	}

	gp.StdlibChecked = true
	gp.StdlibBumps = append(gp.StdlibBumps, bumps...)
	for _, msg := range messages {
		gp.AddMessage(msg)
	}
	if len(bumps) == 0 && len(messages) == 0 {
		logging.From(ctx).Debug("stdlib staleness check found nothing to fix")
	}
	return nil
}

// commitInfo looks up the melange file's last commit for the staleness
// estimate. A nil info means skip the staleness trigger: the reason is already
// reported (a message naming the rebuild toolchain, or a skip warning), and
// the error is non-nil only for a cancellation, which must propagate. A
// shallow history is warned about but proceeds.
func (s *StdlibStage) commitInfo(ctx context.Context, gp *Processor, toolchain string) (*git.FileCommitInfo, error) {
	info, err := s.lastCommit(ctx, gp.GetFilePath())
	switch {
	case errors.Is(err, git.ErrNotInRepository):
		gp.AddMessage("stdlib: melange file is not in a git repository - stdlib staleness trigger skipped (rebuild toolchain: " + toolchain + ")")
		return nil, nil
	case errors.Is(err, git.ErrUntracked):
		gp.AddMessage("stdlib: melange file has no commit history - stdlib staleness trigger skipped (rebuild toolchain: " + toolchain + ")")
		return nil, nil
	case err != nil:
		return nil, cancelledOr(ctx, func() {
			s.skipWarn(ctx, gp, fmt.Sprintf("stdlib: could not determine the melange file's last commit (%v) - stdlib staleness trigger skipped (rebuild toolchain: %s)", err, toolchain))
		})
	}
	if info.Dirty {
		// The idempotency guard: an epoch bump this tool wrote on a previous
		// run (or any other pending edit) makes the file dirty; re-running
		// must not stack further stale-only bumps until it is committed.
		gp.AddMessage("stdlib: melange file has uncommitted changes - stdlib staleness trigger skipped, a bump may already be pending (rebuild toolchain: " + toolchain + ")")
		return nil, nil
	}
	if info.Shallow {
		logging.From(ctx).Warn("melange repository history is shallow - stdlib staleness estimate may assume a newer toolchain than reality",
			"commit_time", info.Time)
		gp.AddMessage("stdlib: repository history is shallow - the assumed build toolchain may be newer than reality")
	}
	return info, nil
}

// filterByLinkedStd re-evaluates the staleness findings against the linked
// stdlib set from a fallback checkout (see checkoutLinkedStd). Any failure
// fails OPEN: the unfiltered (Validated=false) bumps and messages are
// returned unchanged. A cancellation is the one failure that must NOT fail
// open - it means stop, not "proceed unfiltered" - and is the only error
// returned.
func (s *StdlibStage) filterByLinkedStd(ctx context.Context, gp *Processor, in stdlibInput, bumps []StdlibBump, messages []string) ([]StdlibBump, []string, error) {
	linked, err := s.linkStd(ctx, gp)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, nil, cerr
		}
		logging.From(ctx).Warn("could not determine linked stdlib packages - stdlib findings remain unfiltered", "error", err)
		gp.AddMessage(fmt.Sprintf("stdlib: could not determine linked stdlib packages (%v) - findings not filtered by artifact reachability", err))
		return bumps, messages, nil
	}
	if linked == nil {
		return bumps, messages, nil
	}
	in.Linked, in.Validated = linked, true
	filteredBumps, filteredMessages, err := evaluateStdlibStaleness(ctx, s.index, s.scanner, in)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, nil, cerr
		}
		logging.From(ctx).Warn("linked-import stdlib re-evaluation failed - stdlib findings remain unfiltered", "error", err)
		gp.AddMessage(fmt.Sprintf("stdlib: linked-import re-evaluation failed (%v) - findings not filtered by artifact reachability", err))
		return bumps, messages, nil
	}
	return filteredBumps, filteredMessages, nil
}

// checkoutLinkedStd clones the package's source (reusing the vulnerability
// analysis' git-checkout coordinates) and computes the union of linked
// stdlib import paths across the package's go build units, exactly as the
// simulation would have (simulate.Toolchain.LinkedStd: GOOS=linux, the
// union over the package's target arches, each step's build environment). A
// versioned go/install step's artifact is built from another module
// version, whose stdlib slice is unknown: an error (fail open).
func (s *StdlibStage) checkoutLinkedStd(ctx context.Context, gp *Processor) (map[string]struct{}, error) {
	analysis := gp.VulnerabilityAnalysis
	if analysis == nil || analysis.RepoURL == "" || analysis.Tag == "" {
		return nil, fmt.Errorf("no source coordinates available (repository/tag unknown)")
	}
	scan := scanBuildSteps(ctx, gp.Config)
	if len(scan.versionedInstalls) > 0 {
		return nil, fmt.Errorf("go/install %s builds outside the checkout", strings.Join(scan.versionedInstalls, ", "))
	}

	simOpts := simulate.Options{Budget: s.Options.SimulationTimeout}.WithDefaults()
	toolchain, err := simulate.NewToolchain(ctx, simOpts.CommandTimeout)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, simOpts.Budget)
	defer cancel()

	cloneDir, cleanup, err := simulate.Checkout(ctx, git.New(), analysis.RepoURL, analysis.Tag, analysis.ExpectedCommit, s.Options.TempDir, "stdlib")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	union := make(map[string]struct{})
	for _, unit := range scan.units["go"] {
		std, err := toolchain.LinkedStd(ctx, simulate.ModrootDir(cloneDir, unit.Modroot), simulate.BuildTarget{Patterns: unit.Packages, Tags: unit.Tags, Arches: unit.Arches, Env: unit.Env})
		if err != nil {
			return nil, fmt.Errorf("computing linked stdlib packages for modroot %s: %w", unit.Modroot, err)
		}
		for pkg := range std {
			union[pkg] = struct{}{}
		}
	}
	if len(union) == 0 {
		// Every Go artifact links at least the runtime; an empty union means
		// the walk saw nothing - treat as unknown rather than "nothing linked".
		return nil, fmt.Errorf("no linked stdlib packages found (empty import graph)")
	}
	return union, nil
}

// rebuildToolchainWord renders the resolved rebuild Go version(s) for
// messages.
func rebuildToolchainWord(versions []string, unknown bool) string {
	if unknown || len(versions) == 0 {
		return "unresolved"
	}
	return "go" + strings.Join(versions, ", go")
}

// skipWarn records a degrade-to-skip both in the log and the per-package
// messages (this stage never fails the run).
func (s *StdlibStage) skipWarn(ctx context.Context, gp *Processor, msg string) {
	logging.From(ctx).Warn(msg)
	gp.AddMessage(msg)
}
