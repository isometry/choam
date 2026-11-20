package git

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
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

	head, err := client.HeadCommit(t.Context(), dest)
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

func TestGetCommitSHAForTag(t *testing.T) {
	fixture, commitSHA := newFixtureRepo(t)

	repo, err := gogit.PlainOpen(fixture)
	require.NoError(t, err)
	tagger := &object.Signature{Name: "test", Email: "test@example.com", When: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}
	annotated, err := repo.CreateTag("v2.0.0", plumbing.NewHash(commitSHA), &gogit.CreateTagOptions{Tagger: tagger, Message: "v2.0.0"})
	require.NoError(t, err)
	// The tag object is a distinct object from the commit; that is the bug's trigger.
	require.NotEqual(t, commitSHA, annotated.Hash().String())

	client := New()

	t.Run("lightweight", func(t *testing.T) {
		got, err := client.GetCommitSHAForTag(t.Context(), fixture, "v1.0.0")
		require.NoError(t, err)
		assert.Equal(t, commitSHA, got)
	})

	t.Run("annotated resolves to the commit, not the tag object", func(t *testing.T) {
		got, err := client.GetCommitSHAForTag(t.Context(), fixture, "v2.0.0")
		require.NoError(t, err)
		assert.Equal(t, commitSHA, got)
	})

	t.Run("missing", func(t *testing.T) {
		_, err := client.GetCommitSHAForTag(t.Context(), fixture, "v9.9.9")
		assert.Error(t, err)
	})
}

func TestListTags(t *testing.T) {
	fixture, _ := newFixtureRepo(t)

	tags, err := New().ListTags(t.Context(), fixture)
	require.NoError(t, err)
	assert.Equal(t, []string{"v1.0.0"}, tags)
}

func TestListTags_NoTags(t *testing.T) {
	dir := t.TempDir()
	_, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)

	_, err = New().ListTags(t.Context(), dir)
	assert.Error(t, err)
}
