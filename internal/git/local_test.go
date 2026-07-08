package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireGit skips the test if the git binary is not available on PATH.
// Fixtures in this file are built by exec'ing the real git binary rather
// than go-git, so GIT_COMMITTER_DATE can be used to pin committer times.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not found in PATH")
	}
}

// runGitWithEnv runs git in dir with additional environment variables,
// always disabling commit signing so fixture commits never trigger the
// developer machine's configured signing key.
func runGitWithEnv(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	fullArgs := append([]string{"-c", "commit.gpgsign=false"}, args...)
	cmd := exec.Command("git", fullArgs...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %s: %s", strings.Join(args, " "), out)
	return strings.TrimSpace(string(out))
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return runGitWithEnv(t, dir, nil, args...)
}

// initLocalRepo initializes an empty repo in dir with local user config, so
// commits succeed without relying on any global git config.
func initLocalRepo(t *testing.T, dir string) {
	t.Helper()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.name", "Test User")
	runGit(t, dir, "config", "user.email", "test@example.com")
}

func commitEnv(when time.Time) []string {
	stamp := when.Format(time.RFC3339)
	return []string{
		"GIT_AUTHOR_NAME=Test User", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test User", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_AUTHOR_DATE=" + stamp, "GIT_COMMITTER_DATE=" + stamp,
	}
}

// newLocalFixtureRepo creates a repo in t.TempDir() with a single committed
// melange.yaml file, returning the repo dir, the pinned committer time, and
// the commit's SHA.
func newLocalFixtureRepo(t *testing.T) (dir string, committedAt time.Time, headSHA string) {
	t.Helper()
	dir = t.TempDir()
	initLocalRepo(t, dir)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "melange.yaml"), []byte("package:\n  name: fixture\n"), 0o644))
	runGit(t, dir, "add", "melange.yaml")

	committedAt = time.Date(2024, 3, 15, 10, 30, 0, 0, time.UTC)
	runGitWithEnv(t, dir, commitEnv(committedAt), "commit", "-q", "-m", "add melange.yaml")

	headSHA = runGit(t, dir, "rev-parse", "HEAD")
	return dir, committedAt, headSHA
}

func TestLastCommitInfo_Committed(t *testing.T) {
	requireGit(t)
	dir, committedAt, headSHA := newLocalFixtureRepo(t)

	info, err := LastCommitInfo(filepath.Join(dir, "melange.yaml"))
	require.NoError(t, err)
	assert.True(t, committedAt.Equal(info.Time), "want %v, got %v", committedAt, info.Time)
	assert.Equal(t, headSHA, info.Hash)
	assert.False(t, info.Dirty)
	assert.False(t, info.Shallow)
}

func TestLastCommitInfo_Dirty(t *testing.T) {
	requireGit(t)
	dir, committedAt, headSHA := newLocalFixtureRepo(t)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "melange.yaml"), []byte("package:\n  name: fixture-modified\n"), 0o644))

	info, err := LastCommitInfo(filepath.Join(dir, "melange.yaml"))
	require.NoError(t, err)
	assert.True(t, committedAt.Equal(info.Time), "commit time should be unaffected by dirty content")
	assert.Equal(t, headSHA, info.Hash)
	assert.True(t, info.Dirty)
}

func TestLastCommitInfo_Untracked(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initLocalRepo(t, dir)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "untracked.yaml"), []byte("package:\n  name: untracked\n"), 0o644))

	_, err := LastCommitInfo(filepath.Join(dir, "untracked.yaml"))
	assert.ErrorIs(t, err, ErrUntracked)
}

func TestLastCommitInfo_NotInRepository(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "file.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte("package:\n"), 0o644))

	_, err := LastCommitInfo(filePath)
	assert.ErrorIs(t, err, ErrNotInRepository)
}

func TestLastCommitInfo_Subdirectory(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initLocalRepo(t, dir)

	subdir := filepath.Join(dir, "packages", "foo")
	require.NoError(t, os.MkdirAll(subdir, 0o755))
	filePath := filepath.Join(subdir, "melange.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte("package:\n  name: foo\n"), 0o644))
	runGit(t, dir, "add", "packages/foo/melange.yaml")

	committedAt := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	runGitWithEnv(t, dir, commitEnv(committedAt), "commit", "-q", "-m", "add foo")
	headSHA := runGit(t, dir, "rev-parse", "HEAD")

	info, err := LastCommitInfo(filePath)
	require.NoError(t, err)
	assert.Equal(t, headSHA, info.Hash)
	assert.True(t, committedAt.Equal(info.Time))
	assert.False(t, info.Dirty)
}

func TestLastCommitInfo_Shallow(t *testing.T) {
	requireGit(t)
	src, _, _ := newLocalFixtureRepo(t)

	parent := t.TempDir()
	dstRepo := filepath.Join(parent, "clone")
	runGit(t, parent, "clone", "-q", "--depth", "1", "file://"+src, dstRepo)

	info, err := LastCommitInfo(filepath.Join(dstRepo, "melange.yaml"))
	require.NoError(t, err)
	assert.True(t, info.Shallow)
	assert.False(t, info.Dirty)
}

// TestLogViaGoGit_Committed exercises the go-git fallback path directly
// (rather than by hiding the git binary from PATH), covering the
// committed-file case.
func TestLogViaGoGit_Committed(t *testing.T) {
	requireGit(t)
	dir, committedAt, headSHA := newLocalFixtureRepo(t)

	repo, err := gogit.PlainOpen(dir)
	require.NoError(t, err)

	hash, when, err := logViaGoGit(repo, "melange.yaml")
	require.NoError(t, err)
	assert.Equal(t, headSHA, hash.String())
	assert.True(t, committedAt.Equal(when))
}

func TestLogViaGoGit_Untracked(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initLocalRepo(t, dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "untracked.yaml"), []byte("package:\n"), 0o644))

	repo, err := gogit.PlainOpen(dir)
	require.NoError(t, err)

	_, _, err = logViaGoGit(repo, "untracked.yaml")
	assert.ErrorIs(t, err, ErrUntracked)
}

// TestLastCommitInfo_Rename documents that the "last commit" for a renamed
// file is the rename commit itself: LastCommitInfo does not follow renames
// (matching plain `git log -- path`, without --follow).
func TestLastCommitInfo_Rename(t *testing.T) {
	requireGit(t)
	dir, _, _ := newLocalFixtureRepo(t)

	runGit(t, dir, "mv", "melange.yaml", "renamed.yaml")

	renamedAt := time.Date(2024, 7, 1, 9, 0, 0, 0, time.UTC)
	runGitWithEnv(t, dir, commitEnv(renamedAt), "commit", "-q", "-m", "rename melange.yaml")
	renameSHA := runGit(t, dir, "rev-parse", "HEAD")

	info, err := LastCommitInfo(filepath.Join(dir, "renamed.yaml"))
	require.NoError(t, err)
	assert.Equal(t, renameSHA, info.Hash)
	assert.True(t, renamedAt.Equal(info.Time))
}
