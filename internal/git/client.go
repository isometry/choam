package git

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/isometry/choam/internal/types"
)

// Pre-compiled regex for version number extraction
var versionNumRegex = regexp.MustCompile(`(\d+)`)

// Client represents a Git client using go-git
type Client struct{}

// New creates a new Git client
func New() *Client {
	return &Client{}
}

// GetLatestTag returns the latest tag from a Git repository
func (c *Client) GetLatestTag(ctx context.Context, repoURL string) (string, error) {
	tags, err := c.GetTags(ctx, repoURL)
	if err != nil {
		return "", fmt.Errorf("getting tags: %w", err)
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found in repository %s", repoURL)
	}

	// Return the first (most recent) tag
	return tags[0], nil
}

// GetTagsWithFilter returns filtered tags from a Git repository with early termination
func (c *Client) GetTagsWithFilter(ctx context.Context, repoURL, filterPrefix, filterContains string) ([]string, error) {
	// Create a remote to list references without cloning
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// List all references
	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	var tags []string
	for _, ref := range refs {
		// Only process tag references
		if !ref.Name().IsTag() {
			continue
		}

		// Extract tag name
		tagName := ref.Name().Short()

		// Apply filters
		if filterPrefix != "" && !strings.HasPrefix(tagName, filterPrefix) {
			continue
		}
		if filterContains != "" && !strings.Contains(tagName, filterContains) {
			continue
		}

		tags = append(tags, tagName)
	}

	// Sort tags in descending order (newest first)
	// Use version-aware sorting instead of lexical
	sort.Slice(tags, func(i, j int) bool {
		return compareVersionStrings(tags[i], tags[j]) > 0
	})

	return tags, nil
}

// GetFirstValidTag finds the first tag that passes all filtering criteria
func (c *Client) GetFirstValidTag(ctx context.Context, repoURL string, filter types.VersionFilterFunc) (string, error) {
	// Create a remote to list references without cloning
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// List all references
	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	// Collect tags and sort them by version (newest first)
	var tags []string
	for _, ref := range refs {
		if ref.Name().IsTag() {
			tags = append(tags, ref.Name().Short())
		}
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found in repository %s", repoURL)
	}

	// Sort tags in descending order (newest first)
	sort.Slice(tags, func(i, j int) bool {
		return compareVersionStrings(tags[i], tags[j]) > 0
	})

	// Find first valid version
	for _, tag := range tags {
		if filter(tag) {
			return tag, nil
		}
	}

	return "", fmt.Errorf("no valid version found in repository %s", repoURL)
}

// GetTags returns all tags from a Git repository
func (c *Client) GetTags(ctx context.Context, repoURL string) ([]string, error) {
	// Create a remote to list references without cloning
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// List all references
	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	var tags []string
	for _, ref := range refs {
		// Only process tag references
		if ref.Name().IsTag() {
			tagName := ref.Name().Short()
			tags = append(tags, tagName)
		}
	}

	// Sort tags in descending order (newest first)
	// Use version-aware sorting instead of lexical
	sort.Slice(tags, func(i, j int) bool {
		return compareVersionStrings(tags[i], tags[j]) > 0
	})

	return tags, nil
}

// FilterTags filters tags based on a pattern
func (c *Client) FilterTags(tags []string, pattern string) []string {
	if pattern == "" {
		return tags
	}

	var filtered []string
	for _, tag := range tags {
		if strings.Contains(tag, pattern) {
			filtered = append(filtered, tag)
		}
	}

	return filtered
}

// FilterTagsWithPrefix filters tags that start with a specific prefix
func (c *Client) FilterTagsWithPrefix(tags []string, prefix string) []string {
	if prefix == "" {
		return tags
	}

	var filtered []string
	for _, tag := range tags {
		if strings.HasPrefix(tag, prefix) {
			filtered = append(filtered, tag)
		}
	}

	return filtered
}

// GetLatestTagWithFilter returns the latest tag that matches the filter
func (c *Client) GetLatestTagWithFilter(ctx context.Context, repoURL, filter string) (string, error) {
	tags, err := c.GetTags(ctx, repoURL)
	if err != nil {
		return "", fmt.Errorf("getting tags: %w", err)
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found in repository %s", repoURL)
	}

	// Apply filter if specified
	if filter != "" {
		tags = c.FilterTags(tags, filter)
		if len(tags) == 0 {
			return "", fmt.Errorf("no tags matching filter '%s' found in repository %s", filter, repoURL)
		}
	}

	// Return the first (most recent) tag
	return tags[0], nil
}

// GetCommitSHAForTag gets the commit SHA for a specific tag
func (c *Client) GetCommitSHAForTag(ctx context.Context, repoURL, tag string) (string, error) {
	// Create a remote to get references
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// List all references
	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	// Find the specific tag
	tagRefName := plumbing.NewTagReferenceName(tag)
	for _, ref := range refs {
		if ref.Name() == tagRefName {
			return ref.Hash().String(), nil
		}
	}

	return "", fmt.Errorf("tag %s not found in repository %s", tag, repoURL)
}

// GetCommitInfo gets information about a commit
func (c *Client) GetCommitInfo(ctx context.Context, repoURL, commitSHA string) (*CommitInfo, error) {
	// For getting commit info, we need more than just ls-remote
	// This would require cloning or using a more advanced approach
	// For now, we'll return basic info

	// Verify the commit exists by checking if we can find it in refs
	exists, err := c.VerifyCommitExists(ctx, repoURL, commitSHA)
	if err != nil {
		return nil, fmt.Errorf("verifying commit: %w", err)
	}

	if !exists {
		return nil, fmt.Errorf("commit %s not found in repository %s", commitSHA, repoURL)
	}

	return &CommitInfo{
		SHA:        commitSHA,
		Repository: repoURL,
	}, nil
}

// VerifyCommitExists verifies that a commit SHA exists in the repository
func (c *Client) VerifyCommitExists(ctx context.Context, repoURL, commitSHA string) (bool, error) {
	// Create a remote to list references
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// List all references
	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	// Check if the commit SHA matches any reference
	for _, ref := range refs {
		if ref.Hash().String() == commitSHA {
			return true, nil
		}
	}

	return false, nil
}

// GetTagInfo gets detailed information about a tag
func (c *Client) GetTagInfo(ctx context.Context, repoURL, tagName string) (*TagInfo, error) {
	// Create a remote to get references
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// List all references
	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	// Find the specific tag
	tagRefName := plumbing.NewTagReferenceName(tagName)
	for _, ref := range refs {
		if ref.Name() == tagRefName {
			return &TagInfo{
				Name: tagName,
				SHA:  ref.Hash().String(),
			}, nil
		}
	}

	return nil, fmt.Errorf("tag %s not found in repository %s", tagName, repoURL)
}

// ListBranches lists all branches in the repository
func (c *Client) ListBranches(ctx context.Context, repoURL string) ([]string, error) {
	// Create a remote to list references
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// List all references
	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	var branches []string
	for _, ref := range refs {
		// Only process branch references
		if ref.Name().IsBranch() {
			branchName := ref.Name().Short()
			branches = append(branches, branchName)
		}
	}

	return branches, nil
}

// GetDefaultBranch gets the default branch of the repository
func (c *Client) GetDefaultBranch(ctx context.Context, repoURL string) (string, error) {
	// Create a remote to get references
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})

	// List all references
	refs, err := rem.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("listing references from %s: %w", repoURL, err)
	}

	// Look for HEAD reference to determine default branch
	for _, ref := range refs {
		if ref.Name() == plumbing.HEAD {
			if ref.Type() == plumbing.SymbolicReference {
				// HEAD is a symbolic reference pointing to the default branch
				return ref.Target().Short(), nil
			}
		}
	}

	// Fallback: look for common default branch names
	defaultBranches := []string{"main", "master", "develop"}
	for _, ref := range refs {
		if ref.Name().IsBranch() {
			branchName := ref.Name().Short()
			if slices.Contains(defaultBranches, branchName) {
				return branchName, nil
			}
		}
	}

	return "", fmt.Errorf("could not determine default branch for %s", repoURL)
}

// CloneRepository clones a repository to memory for more advanced operations
func (c *Client) CloneRepository(ctx context.Context, repoURL string) (*git.Repository, error) {
	// Clone to memory storage (doesn't create files on disk)
	repo, err := git.CloneContext(ctx, memory.NewStorage(), nil, &git.CloneOptions{
		URL: repoURL,
	})
	if err != nil {
		return nil, fmt.Errorf("cloning repository %s: %w", repoURL, err)
	}

	return repo, nil
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

// GetCommitFromClone gets detailed commit information by cloning the repository
func (c *Client) GetCommitFromClone(ctx context.Context, repoURL, commitSHA string) (*object.Commit, error) {
	repo, err := c.CloneRepository(ctx, repoURL)
	if err != nil {
		return nil, fmt.Errorf("cloning repository: %w", err)
	}

	hash := plumbing.NewHash(commitSHA)
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("getting commit object: %w", err)
	}

	return commit, nil
}

// compareVersionStrings compares two version strings for sorting
// Returns positive if v1 > v2, negative if v1 < v2, zero if equal
func compareVersionStrings(v1, v2 string) int {
	// Handle identical strings
	if v1 == v2 {
		return 0
	}

	// Extract version numbers using pre-compiled regex
	v1Parts := versionNumRegex.FindAllString(v1, -1)
	v2Parts := versionNumRegex.FindAllString(v2, -1)

	// Compare numeric parts
	maxLen := max(len(v2Parts), len(v1Parts))

	for i := range maxLen {
		var n1, n2 int
		var err error

		if i < len(v1Parts) {
			n1, err = strconv.Atoi(v1Parts[i])
			if err != nil {
				n1 = 0
			}
		}

		if i < len(v2Parts) {
			n2, err = strconv.Atoi(v2Parts[i])
			if err != nil {
				n2 = 0
			}
		}

		if n1 != n2 {
			return n1 - n2
		}
	}

	// If numeric parts are equal, fall back to lexical comparison
	// This handles cases like "1.2.3-alpha" vs "1.2.3-beta"
	return strings.Compare(v1, v2)
}
