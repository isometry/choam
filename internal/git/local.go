package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// ErrNotInRepository indicates that a file path does not reside inside a
// (discoverable) git repository.
var ErrNotInRepository = errors.New("path is not inside a git repository")

// ErrUntracked indicates that a file exists on disk and inside a git
// repository, but has no commit history for that path.
var ErrUntracked = errors.New("file has no commit history in repository")

// FileCommitInfo describes the last commit that touched a file, plus
// working-tree state relevant to a "how stale is this checkout" heuristic.
type FileCommitInfo struct {
	// Time is the committer time of the last commit that touched the file.
	Time time.Time
	// Hash is the last commit's SHA (hex).
	Hash string
	// Shallow reports whether the containing repository has truncated
	// (shallow) history.
	Shallow bool
	// Dirty reports whether the on-disk content differs from the file's
	// blob at HEAD.
	Dirty bool
}

// LastCommitInfo locates the git repository containing filePath and returns
// information about the last commit that touched it, along with whether the
// on-disk content is dirty relative to HEAD and whether the repository has
// shallow history.
//
// It returns ErrNotInRepository if filePath is not inside a discoverable git
// repository, and ErrUntracked if the file has no commit history.
func LastCommitInfo(ctx context.Context, filePath string) (*FileCommitInfo, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("resolving absolute path for %s: %w", filePath, err)
	}

	// Resolve symlinks so absPath and the repository root (which go-git
	// resolves through any .git-file indirection, and which may therefore
	// come back fully symlink-resolved, e.g. macOS's /tmp -> /private/tmp)
	// share a common prefix for the filepath.Rel call below.
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	} else {
		return nil, fmt.Errorf("resolving symlinks for %s: %w", filePath, err)
	}

	repo, err := gogit.PlainOpenWithOptions(filepath.Dir(absPath), &gogit.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		if errors.Is(err, gogit.ErrRepositoryNotExists) {
			return nil, ErrNotInRepository
		}
		return nil, fmt.Errorf("opening repository for %s: %w", filePath, err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("resolving worktree for %s: %w", filePath, err)
	}
	root := worktree.Filesystem.Root()

	relPath, err := filepath.Rel(root, absPath)
	if err != nil {
		return nil, fmt.Errorf("resolving %s relative to repository root %s: %w", filePath, root, err)
	}
	relPath = filepath.ToSlash(relPath)

	hash, commitTime, err := lastCommitTouching(ctx, repo, root, relPath)
	if err != nil {
		return nil, err
	}

	dirty, err := fileDirty(ctx, repo, root, absPath, relPath)
	if err != nil {
		return nil, err
	}

	shallow, err := isShallow(repo)
	if err != nil {
		return nil, err
	}

	return &FileCommitInfo{
		Time:    commitTime,
		Hash:    hash.String(),
		Shallow: shallow,
		Dirty:   dirty,
	}, nil
}

// lastCommitTouching finds the most recent commit that touched relPath.
// It prefers shelling out to the real git binary (git log's file-history
// walk is far cheaper than go-git's tree-diffing Log on large repositories)
// and falls back to logViaGoGit when the binary is unavailable or fails to
// execute.
func lastCommitTouching(ctx context.Context, repo *gogit.Repository, root, relPath string) (plumbing.Hash, time.Time, error) {
	hash, when, invoked, err := runGitLog(ctx, root, relPath)
	if invoked {
		return hash, when, err
	}
	return logViaGoGit(repo, relPath)
}

// runGitLog shells out to `git -C root log -1 --format=%H|%cI -- relPath`.
// invoked reports whether the git binary was found and executed
// successfully; callers should fall back to logViaGoGit when it is false,
// regardless of the returned error (which will be nil in that case).
func runGitLog(ctx context.Context, root, relPath string) (hash plumbing.Hash, when time.Time, invoked bool, err error) {
	if _, lookErr := exec.LookPath("git"); lookErr != nil {
		return plumbing.ZeroHash, time.Time{}, false, nil
	}

	cmd := exec.CommandContext(ctx, "git", "-C", root, "log", "-1", "--format=%H|%cI", "--", relPath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if runErr := cmd.Run(); runErr != nil {
		// Fall back to go-git rather than surfacing an exec failure.
		return plumbing.ZeroHash, time.Time{}, false, nil
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		return plumbing.ZeroHash, time.Time{}, true, ErrUntracked
	}

	sha, dateStr, found := strings.Cut(out, "|")
	if !found {
		return plumbing.ZeroHash, time.Time{}, true, fmt.Errorf("parsing git log output %q for %s", out, relPath)
	}

	when, parseErr := time.Parse(time.RFC3339, dateStr)
	if parseErr != nil {
		return plumbing.ZeroHash, time.Time{}, true, fmt.Errorf("parsing commit date %q for %s: %w", dateStr, relPath, parseErr)
	}

	return plumbing.NewHash(sha), when, true, nil
}

// logViaGoGit is the go-git fallback for lastCommitTouching, used when the
// git binary is unavailable. It is split out so it can be exercised
// directly by tests without hiding the git binary from PATH.
func logViaGoGit(repo *gogit.Repository, relPath string) (plumbing.Hash, time.Time, error) {
	iter, err := repo.Log(&gogit.LogOptions{FileName: &relPath, Order: gogit.LogOrderCommitterTime})
	if err != nil {
		// An empty repository (no commits yet, so HEAD doesn't resolve) has
		// no history for any path, same as the fast path's "empty output".
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return plumbing.ZeroHash, time.Time{}, ErrUntracked
		}
		return plumbing.ZeroHash, time.Time{}, fmt.Errorf("walking commit log for %s: %w", relPath, err)
	}
	defer iter.Close()

	commit, err := iter.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return plumbing.ZeroHash, time.Time{}, ErrUntracked
		}
		return plumbing.ZeroHash, time.Time{}, fmt.Errorf("reading commit log for %s: %w", relPath, err)
	}

	return commit.Hash, commit.Committer.When, nil
}

// fileDirty reports whether relPath has uncommitted changes. It prefers
// shelling out to the real git binary via runGitStatus, which honours
// content filters (core.autocrlf, .gitattributes eol rules) the same way
// git itself does when populating the working tree, and falls back to the
// isDirty raw byte-compare when the binary is unavailable or fails to
// execute.
func fileDirty(ctx context.Context, repo *gogit.Repository, root, absPath, relPath string) (bool, error) {
	dirty, invoked, err := runGitStatus(ctx, root, relPath)
	if invoked {
		return dirty, err
	}
	return isDirty(repo, absPath, relPath)
}

// runGitStatus shells out to `git -C root status --porcelain -- relPath`.
// invoked reports whether the git binary was found and executed
// successfully; callers should fall back to isDirty when it is false,
// regardless of the returned error (which will be nil in that case).
// err is currently always nil even when invoked is true; it is kept in the
// signature for symmetry with runGitLog's fast-path/fallback contract.
func runGitStatus(ctx context.Context, root, relPath string) (dirty bool, invoked bool, err error) {
	if _, lookErr := exec.LookPath("git"); lookErr != nil {
		return false, false, nil
	}

	cmd := exec.CommandContext(ctx, "git", "-C", root, "status", "--porcelain", "--", relPath)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if runErr := cmd.Run(); runErr != nil {
		// Fall back to the go-git byte-compare rather than surfacing an exec
		// failure.
		return false, false, nil
	}

	return strings.TrimSpace(stdout.String()) != "", true, nil
}

// isDirty reports whether the on-disk content at absPath differs from the
// relPath blob in the HEAD tree. It deliberately avoids worktree.Status(),
// which walks the entire working tree and is too slow on large repositories.
//
// It also deliberately avoids applying any git content filters (core.autocrlf,
// .gitattributes eol rules): it byte-compares the raw worktree file against
// the raw HEAD blob, so a filtered repository (e.g. CRLF checkouts normalized
// to LF on commit) reads as permanently dirty even when git itself considers
// the file clean. It exists purely as the fileDirty fallback for when the git
// binary isn't invocable; prefer runGitStatus (via fileDirty), which shells
// out to real git and therefore honours those filters correctly.
//
// If relPath is absent from the HEAD tree (the file has commit history, per
// lastCommitTouching, but was since deleted at HEAD), the file is treated as
// dirty.
func isDirty(repo *gogit.Repository, absPath, relPath string) (bool, error) {
	headRef, err := repo.Head()
	if err != nil {
		return false, fmt.Errorf("resolving HEAD: %w", err)
	}

	headCommit, err := repo.CommitObject(headRef.Hash())
	if err != nil {
		return false, fmt.Errorf("resolving HEAD commit %s: %w", headRef.Hash(), err)
	}

	tree, err := headCommit.Tree()
	if err != nil {
		return false, fmt.Errorf("resolving tree for HEAD commit %s: %w", headRef.Hash(), err)
	}

	diskContent, err := os.ReadFile(absPath)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", absPath, err)
	}

	entry, err := tree.File(relPath)
	if err != nil {
		if errors.Is(err, object.ErrFileNotFound) {
			return true, nil
		}
		return false, fmt.Errorf("finding %s in HEAD tree: %w", relPath, err)
	}

	blobContent, err := entry.Contents()
	if err != nil {
		return false, fmt.Errorf("reading blob contents for %s: %w", relPath, err)
	}

	return !bytes.Equal(diskContent, []byte(blobContent)), nil
}

// isShallow reports whether repo's history has been truncated by a shallow
// clone or fetch. PlainOpenWithOptions (with DetectDotGit) resolves the
// .git-file indirection used by submodules (and the primary case this
// package cares about: a plain checkout with a real .git directory) before
// constructing the repository's Storer, so Storer.Shallow() reads the
// "shallow" file from the correctly resolved git directory in those cases.
//
// Known limitation: for a secondary `git worktree add` checkout, "shallow"
// lives in the shared main .git directory, not the per-worktree gitdir
// (.git/worktrees/<name>) that DetectDotGit resolves to, so this can under-
// report shallowness for that specific case. Melange package checkouts are
// plain (non-linked-worktree) clones, so this does not affect the intended
// use of LastCommitInfo.
func isShallow(repo *gogit.Repository) (bool, error) {
	shallow, err := repo.Storer.Shallow()
	if err != nil {
		return false, fmt.Errorf("checking shallow history: %w", err)
	}
	return len(shallow) > 0, nil
}
