package simulate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/isometry/choam/internal/git"
	"github.com/isometry/choam/internal/logging"
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

	cloneDir, cleanup, err := Checkout(ctx, s.git, repoURL, tag, expectedCommit, s.tempDir, "simulate")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	results := make(map[string]*ModrootResult, len(reqs))
	for _, req := range reqs {
		result, err := RunLoop(ctx, s.tc, s.sc, ModrootDir(cloneDir, req.Modroot), req, s.opts)
		if err != nil {
			return nil, fmt.Errorf("simulating modroot %s: %w", req.Modroot, err)
		}
		logging.From(ctx).Debug("modroot simulation complete",
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

// Checkout clones repoURL at tag into a fresh directory under tmpDir ("" =
// the os.MkdirTemp default) named for purpose ("choam-<purpose>-*").
// expectedCommit, when non-empty, is verified warn-only (melange enforces it
// at build time). cleanup removes the directory; call it once err is nil.
func Checkout(ctx context.Context, cloner Cloner, repoURL, tag, expectedCommit, tmpDir, purpose string) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp(tmpDir, "choam-"+purpose+"-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating %s checkout directory: %w", purpose, err)
	}
	cleanup = func() {
		if err := os.RemoveAll(dir); err != nil {
			logging.From(ctx).Debug("could not remove checkout directory", "purpose", purpose, "dir", dir, "error", err)
		}
	}

	logging.From(ctx).Debug("cloning source", "purpose", purpose, "repository", repoURL, "tag", tag, "dir", dir)
	if err := cloner.CloneAtTag(ctx, repoURL, tag, dir); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("cloning %s at %s: %w", repoURL, tag, err)
	}

	if expectedCommit != "" {
		if head, err := cloner.HeadCommit(ctx, dir); err != nil {
			logging.From(ctx).Warn("could not verify expected commit", "purpose", purpose, "error", err)
		} else if head != expectedCommit {
			logging.From(ctx).Warn("checkout does not match expected-commit; using the tag's actual state",
				"purpose", purpose, "tag", tag, "expected", expectedCommit, "actual", head)
		}
	}
	return dir, cleanup, nil
}

// ModrootDir is modroot's directory within a checkout at root ("" and "."
// are the root itself).
func ModrootDir(root, modroot string) string {
	if modroot == "" || modroot == "." {
		return root
	}
	return filepath.Join(root, filepath.FromSlash(modroot))
}
