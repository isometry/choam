package git

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
)

// Client represents a Git client using go-git
type Client struct{}

// New creates a new Git client
func New() *Client {
	return &Client{}
}

// ListTags returns the names of all tags in the remote repository, in no
// particular order; callers pick the newest by comparing parsed versions.
func (c *Client) ListTags(ctx context.Context, repoURL string) ([]string, error) {
	// Create a remote to list references without cloning
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	var tags []string
	for _, ref := range refs {
		if ref.Name().IsTag() {
			tags = append(tags, ref.Name().Short())
		}
	}

	if len(tags) == 0 {
		return nil, fmt.Errorf("no tags found in repository %s", repoURL)
	}

	return tags, nil
}

// GetCommitSHAForTag gets the commit SHA for a specific tag
func (c *Client) GetCommitSHAForTag(ctx context.Context, repoURL, tag string) (string, error) {
	// Create a remote to get references
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// AppendPeeled adds "<tag>^{}" entries pointing at the commit an annotated
	// tag names; without it an annotated tag lists as its tag object, which is
	// not the commit melange's expected-commit is compared with.
	refs, err := rem.ListContext(ctx, &git.ListOptions{PeelingOption: git.AppendPeeled})
	if err != nil {
		return "", fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	// Prefer the peeled commit; a lightweight tag has no peeled entry and its
	// ref already is the commit.
	tagRefName := plumbing.NewTagReferenceName(tag)
	peeledRefName := plumbing.ReferenceName(tagRefName.String() + "^{}")
	var found string
	for _, ref := range refs {
		switch ref.Name() {
		case peeledRefName:
			return ref.Hash().String(), nil
		case tagRefName:
			found = ref.Hash().String()
		}
	}
	if found != "" {
		return found, nil
	}

	return "", fmt.Errorf("tag %s not found in repository %s", tag, repoURL)
}

// CloneAtTag clones the repository at the given tag into destDir. It first
// attempts a shallow single-branch clone (cheap); some servers reject shallow
// tag fetches, in which case it falls back to a full clone of the tag ref.
func (c *Client) CloneAtTag(ctx context.Context, repoURL, tag, destDir string) error {
	opts := &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: plumbing.NewTagReferenceName(tag),
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
	}

	if _, err := git.PlainCloneContext(ctx, destDir, false, opts); err != nil {
		// Retry without shallow depth: leave destDir clean for the retry.
		if cleanErr := removeDirContents(destDir); cleanErr != nil {
			return fmt.Errorf("cloning %s at tag %s: %w (cleanup failed: %v)", repoURL, tag, err, cleanErr)
		}
		opts.Depth = 0
		if _, retryErr := git.PlainCloneContext(ctx, destDir, false, opts); retryErr != nil {
			return fmt.Errorf("cloning %s at tag %s: %w", repoURL, tag, retryErr)
		}
	}

	return nil
}

// HeadCommit returns the commit SHA the checkout at dir points to. ctx is
// accepted for interface consistency with the client's other methods; the
// underlying go-git read is local-disk-only and doesn't support cancellation.
func (c *Client) HeadCommit(_ context.Context, dir string) (string, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return "", fmt.Errorf("opening repository at %s: %w", dir, err)
	}
	head, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("resolving HEAD at %s: %w", dir, err)
	}
	return head.Hash().String(), nil
}

// removeDirContents empties dir without removing dir itself, so a caller
// holding a temp dir can reuse it.
func removeDirContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
