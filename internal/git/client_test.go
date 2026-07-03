package git

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFixtureRepo creates an on-disk repository with one commit tagged v1.0.0,
// returning its path and the commit SHA.
func newFixtureRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()

	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/fixture\n\ngo 1.21\n"), 0o644))

	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("go.mod")
	require.NoError(t, err)

	sig := &object.Signature{Name: "test", Email: "test@example.com", When: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	commit, err := worktree.Commit("initial", &gogit.CommitOptions{Author: sig, Committer: sig})
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.0", commit, nil)
	require.NoError(t, err)

	return dir, commit.String()
}

func TestCloneAtTag(t *testing.T) {
	fixture, commitSHA := newFixtureRepo(t)
	dest := t.TempDir()

	client := New()
	require.NoError(t, client.CloneAtTag(t.Context(), fixture, "v1.0.0", dest))

	content, err := os.ReadFile(filepath.Join(dest, "go.mod"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "module example.com/fixture")

	head, err := client.HeadCommit(dest)
	require.NoError(t, err)
	assert.Equal(t, commitSHA, head)
}

func TestCloneAtTag_MissingTag(t *testing.T) {
	fixture, _ := newFixtureRepo(t)
	dest := t.TempDir()

	client := New()
	err := client.CloneAtTag(t.Context(), fixture, "v9.9.9", dest)
	assert.Error(t, err)
}
