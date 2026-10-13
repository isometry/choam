package simulate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCloner struct {
	cloneErr error
	head     string
	headErr  error
}

func (f *fakeCloner) CloneAtTag(_ context.Context, _, _, destDir string) error {
	if err := os.WriteFile(filepath.Join(destDir, "go.mod"), []byte("module m\n"), 0o600); err != nil {
		return err
	}
	return f.cloneErr
}

func (f *fakeCloner) HeadCommit(context.Context, string) (string, error) { return f.head, f.headErr }

func TestCheckout(t *testing.T) {
	t.Run("clones into a fresh directory; cleanup removes it", func(t *testing.T) {
		tmp := t.TempDir()
		dir, cleanup, err := Checkout(t.Context(), &fakeCloner{head: "abc"}, "https://example.com/r", "v1", "abc", tmp, "stdlib")
		require.NoError(t, err)
		assert.Equal(t, tmp, filepath.Dir(dir))
		assert.Regexp(t, `^choam-stdlib-`, filepath.Base(dir))
		assert.FileExists(t, filepath.Join(dir, "go.mod"))
		cleanup()
		assert.NoDirExists(t, dir)
	})

	t.Run("expected-commit mismatch and lookup failure are warn-only", func(t *testing.T) {
		for _, c := range []*fakeCloner{{head: "other"}, {headErr: errors.New("no HEAD")}} {
			dir, cleanup, err := Checkout(t.Context(), c, "https://example.com/r", "v1", "abc", t.TempDir(), "simulate")
			require.NoError(t, err)
			assert.DirExists(t, dir)
			cleanup()
		}
	})

	t.Run("clone failure removes the directory", func(t *testing.T) {
		tmp := t.TempDir()
		_, cleanup, err := Checkout(t.Context(), &fakeCloner{cloneErr: errors.New("boom")}, "https://example.com/r", "v1", "", tmp, "simulate")
		require.ErrorContains(t, err, "cloning https://example.com/r at v1: boom")
		assert.Nil(t, cleanup)
		entries, err := os.ReadDir(tmp)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

func TestModrootDir(t *testing.T) {
	assert.Equal(t, "/src", ModrootDir("/src", ""))
	assert.Equal(t, "/src", ModrootDir("/src", "."))
	assert.Equal(t, filepath.Join("/src", "a", "b"), ModrootDir("/src", "a/b"))
}
