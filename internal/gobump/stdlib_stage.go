package gobump

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/isometry/choam/internal/git"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/simulate"
)

// StdlibStage checks whether the package is stale against the Go standard
// library: it estimates the toolchain the package was last built with (latest
// Go release as of the melange file's last commit, per go-package pin
// constraint), diffs OSV stdlib findings against the newest allowed release,
// and records a StdlibBump when a rebuild would fix advisories - which the
// epoch stage then turns into an epoch bump, even with ZERO dependency
// changes (the rebuild itself is the fix).
//
// The stage is strictly best-effort: every failure degrades to a
// skip-with-message and never fails the bump run. The last-commit Dirty gate
// doubles as the idempotency guard - once this run's epoch bump is written,
// the file is dirty and subsequent runs skip until the change is committed
// (in-run dependency edits live only in CurrentYAML, so they never trip it).
type StdlibStage struct {
	processor.BaseStage
	Analyzer *Analyzer
	Options  ProcessorOptions

	// Test seams, mirroring SimulationStage's style: overridable functions
	// and narrow interfaces defaulting to the real implementations.
	lastCommit func(filePath string) (*git.FileCommitInfo, error)
	index      goReleaseIndex
	scanner    stdlibScanner

	// linkStd computes the artifact-linked stdlib import set from a fresh
	// source checkout - the fallback used only when the simulation didn't
	// already provide gp.LinkedStdPackages AND an unfiltered evaluation
	// found fixable advisories worth validating.
	linkStd func(ctx context.Context, gp *GoBumpProcessor) (map[string]struct{}, error)
}

func NewStdlibStage(analyzer *Analyzer, opts ProcessorOptions) *StdlibStage {
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
// code (go/build or go/install steps - see unitsFromBuildSteps): only such
// packages embed the stdlib in their artifacts. Deliberately independent of
// vulnerability findings or bump actions - the pipeline runner evaluates
// each stage's ShouldRun on its own, so this stage runs even when every
// earlier stage was skipped (a package with no dependency changes can still
// need a stdlib rebuild).
func (s *StdlibStage) ShouldRun(_ context.Context, p processor.Processor) (bool, error) {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return false, fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}
	if !s.Options.StdlibCheck || gp.Config == nil {
		return false, nil
	}
	return len(unitsFromBuildSteps(gp.Config)["go"]) > 0, nil
}

// Apply runs the staleness check. EVERY failure path degrades to a
// skip-with-message and returns nil - this stage must never fail the run.
func (s *StdlibStage) Apply(ctx context.Context, p processor.Processor) error {
	gp, ok := p.(*GoBumpProcessor)
	if !ok {
		return fmt.Errorf("expected GoBumpProcessor, got %T", p)
	}

	if s.index == nil || s.scanner == nil {
		s.skipWarn(gp, "stdlib: release index/scanner unavailable - skipping stdlib staleness check")
		return nil
	}

	info, err := s.lastCommit(gp.GetFilePath())
	switch {
	case errors.Is(err, git.ErrNotInRepository):
		gp.AddMessage("stdlib: melange file is not in a git repository - skipping stdlib staleness check")
		return nil
	case errors.Is(err, git.ErrUntracked):
		gp.AddMessage("stdlib: melange file has no commit history - skipping stdlib staleness check")
		return nil
	case err != nil:
		s.skipWarn(gp, fmt.Sprintf("stdlib: could not determine the melange file's last commit (%v) - skipping stdlib staleness check", err))
		return nil
	}
	if info.Dirty {
		// The idempotency guard: an epoch bump this tool wrote on a previous
		// run (or any other pending edit) makes the file dirty; re-running
		// must not stack further bumps until the change is committed.
		gp.AddMessage("stdlib: melange file has uncommitted changes - skipping stdlib staleness check (a bump may already be pending)")
		return nil
	}
	if info.Shallow {
		slog.Warn("melange repository history is shallow - stdlib staleness estimate may assume a newer toolchain than reality",
			"file", gp.GetFilePath(), "commit_time", info.Time)
		gp.AddMessage("stdlib: repository history is shallow - the assumed build toolchain may be newer than reality")
	}

	// Constraints come from the pristine config (the historical truth the
	// assumed side needs); the rebuild side additionally reflects go-package
	// pins this same run raised (the applier runs before this stage).
	constraints := distinctMinorConstraints(goToolchainPins(gp.Config))
	in := stdlibInput{
		CommitTime:         info.Time,
		Constraints:        constraints,
		RebuildConstraints: rebuildConstraintsFor(constraints, gp.RaisedPinMinors),
		Linked:             gp.LinkedStdPackages,
		Validated:          gp.LinkedStdPackages != nil,
	}

	bumps, messages, err := evaluateStdlibStaleness(ctx, s.index, s.scanner, in)
	if err != nil {
		s.skipWarn(gp, fmt.Sprintf("stdlib: staleness check unavailable (%v) - skipping", err))
		return nil
	}

	// Fallback checkout: only worth a clone when the preliminary unfiltered
	// evaluation actually found fixable advisories to validate against the
	// artifact's linked stdlib set. Any failure fails OPEN: the unfiltered
	// (Validated=false) findings stand.
	if len(bumps) > 0 && in.Linked == nil && s.Options.Validate {
		linked, err := s.linkStd(ctx, gp)
		if err != nil {
			slog.Warn("could not determine linked stdlib packages - stdlib findings remain unfiltered", "error", err)
			gp.AddMessage(fmt.Sprintf("stdlib: could not determine linked stdlib packages (%v) - findings not filtered by artifact reachability", err))
		} else if linked != nil {
			in.Linked, in.Validated = linked, true
			filteredBumps, filteredMessages, err := evaluateStdlibStaleness(ctx, s.index, s.scanner, in)
			if err != nil {
				slog.Warn("linked-import stdlib re-evaluation failed - stdlib findings remain unfiltered", "error", err)
				gp.AddMessage(fmt.Sprintf("stdlib: linked-import re-evaluation failed (%v) - findings not filtered by artifact reachability", err))
			} else {
				bumps, messages = filteredBumps, filteredMessages
			}
		}
	}

	gp.StdlibChecked = true
	gp.StdlibBumps = append(gp.StdlibBumps, bumps...)
	for _, msg := range messages {
		gp.AddMessage(msg)
	}
	if len(bumps) == 0 && len(messages) == 0 {
		slog.Debug("stdlib staleness check found nothing to fix", "file", gp.GetFilePath())
	}
	return nil
}

// checkoutLinkedStd clones the package's source (reusing the vulnerability
// analysis' git-checkout coordinates) and computes the union of linked
// stdlib import paths across the package's go build units, exactly as the
// simulation would have (simulate.Toolchain.LinkedStd, GOOS=linux).
func (s *StdlibStage) checkoutLinkedStd(ctx context.Context, gp *GoBumpProcessor) (map[string]struct{}, error) {
	analysis := gp.VulnerabilityAnalysis
	if analysis == nil || analysis.RepoURL == "" || analysis.Tag == "" {
		return nil, fmt.Errorf("no source coordinates available (repository/tag unknown)")
	}

	simOpts := simulate.Options{Budget: s.Options.SimulationTimeout}.WithDefaults()
	toolchain, err := simulate.NewToolchain(simOpts.CommandTimeout)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, simOpts.Budget)
	defer cancel()

	cloneDir, err := os.MkdirTemp(s.Options.TempDir, "choam-stdlib-*")
	if err != nil {
		return nil, fmt.Errorf("creating stdlib checkout directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(cloneDir); err != nil {
			slog.Debug("could not remove stdlib checkout directory", "dir", cloneDir, "error", err)
		}
	}()

	gitClient := git.New()
	slog.Debug("cloning source for stdlib reachability", "repository", analysis.RepoURL, "tag", analysis.Tag, "dir", cloneDir)
	if err := gitClient.CloneAtTag(ctx, analysis.RepoURL, analysis.Tag, cloneDir); err != nil {
		return nil, fmt.Errorf("cloning %s at %s: %w", analysis.RepoURL, analysis.Tag, err)
	}
	if analysis.ExpectedCommit != "" {
		// Warn-only, mirroring the simulator: melange enforces it at build time.
		if head, err := gitClient.HeadCommit(cloneDir); err != nil {
			slog.Warn("could not verify expected commit for stdlib checkout", "error", err)
		} else if head != analysis.ExpectedCommit {
			slog.Warn("stdlib checkout does not match expected-commit; using the tag's actual state",
				"tag", analysis.Tag, "expected", analysis.ExpectedCommit, "actual", head)
		}
	}

	union := make(map[string]struct{})
	for _, unit := range unitsFromBuildSteps(gp.Config)["go"] {
		dir := cloneDir
		if unit.Modroot != "" && unit.Modroot != "." {
			dir = filepath.Join(cloneDir, filepath.FromSlash(unit.Modroot))
		}
		std, err := toolchain.LinkedStd(ctx, dir, unit.Packages)
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

// skipWarn records a degrade-to-skip both in the log and the per-package
// messages (this stage never fails the run).
func (s *StdlibStage) skipWarn(gp *GoBumpProcessor, msg string) {
	slog.Warn(msg, "file", gp.GetFilePath())
	gp.AddMessage(msg)
}
