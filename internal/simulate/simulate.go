package simulate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/isometry/choam/internal/git"
)

// Cloner is the source-checkout seam; *git.Client satisfies it.
type Cloner interface {
	CloneAtTag(ctx context.Context, repoURL, tag, destDir string) error
	HeadCommit(ctx context.Context, dir string) (string, error)
}

// Simulator validates per-modroot bump candidate sets against a real
// checkout of the upstream source (see package doc).
type Simulator struct {
	git     Cloner
	tc      Toolchain
	sc      Scanner
	opts    Options
	tempDir string // parent for the clone; "" means os.MkdirTemp default
}

// NewSimulator wires a Simulator from its dependencies. tempDir may be empty.
func NewSimulator(cloner Cloner, tc Toolchain, sc Scanner, tempDir string, opts Options) *Simulator {
	if cloner == nil {
		cloner = git.New()
	}
	return &Simulator{
		git:     cloner,
		tc:      tc,
		sc:      sc,
		opts:    opts.WithDefaults(),
		tempDir: tempDir,
	}
}

// Simulate clones repoURL at tag once and runs the fixpoint loop for each
// requested modroot against that checkout. A per-modroot failure is recorded
// on its result slot as an error return; a clone failure fails the whole
// simulation. expectedCommit, when non-empty, is verified warn-only (melange
// enforces it at build time).
func (s *Simulator) Simulate(ctx context.Context, repoURL, tag, expectedCommit string, reqs []ModrootRequest) (map[string]*ModrootResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.opts.Budget)
	defer cancel()

	cloneDir, err := os.MkdirTemp(s.tempDir, "choam-simulate-*")
	if err != nil {
		return nil, fmt.Errorf("creating simulation directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(cloneDir); err != nil {
			slog.Debug("could not remove simulation directory", "dir", cloneDir, "error", err)
		}
	}()

	slog.Debug("cloning source for bump simulation", "repository", repoURL, "tag", tag, "dir", cloneDir)
	if err := s.git.CloneAtTag(ctx, repoURL, tag, cloneDir); err != nil {
		return nil, fmt.Errorf("cloning %s at %s: %w", repoURL, tag, err)
	}

	if expectedCommit != "" {
		if head, err := s.git.HeadCommit(ctx, cloneDir); err != nil {
			slog.Warn("could not verify expected commit", "error", err)
		} else if head != expectedCommit {
			slog.Warn("checkout does not match expected-commit; simulating against the tag's actual state",
				"tag", tag, "expected", expectedCommit, "actual", head)
		}
	}

	results := make(map[string]*ModrootResult, len(reqs))
	for _, req := range reqs {
		dir := cloneDir
		if req.Modroot != "" && req.Modroot != "." {
			dir = filepath.Join(cloneDir, filepath.FromSlash(req.Modroot))
		}

		result, err := RunLoop(ctx, s.tc, s.sc, dir, req, s.opts)
		if err != nil {
			return nil, fmt.Errorf("simulating modroot %s: %w", req.Modroot, err)
		}
		slog.Debug("modroot simulation complete",
			"modroot", req.Modroot,
			"iterations", result.Iterations,
			"converged", result.Converged,
			"final_deps", len(result.FinalDeps),
			"residuals", len(result.Residuals),
			"dropped", len(result.Dropped))
		results[req.Modroot] = result
	}

	return results, nil
}
