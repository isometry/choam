package github

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v81/github"
	"github.com/isometry/choam/internal/types"
	"golang.org/x/oauth2"
)

// Client represents a client for the GitHub API using go-github
type Client struct {
	client *github.Client
}

// New creates a new GitHub client with optional authentication
// If httpClient is nil, a default HTTP client will be used
// If authentication is configured via GITHUB_TOKEN, the client's transport is
// wrapped with oauth2's token-injecting RoundTripper.
func New(httpClient *http.Client) *Client {
	// Check for GitHub token in environment for authentication
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)

		// Preserve the caller's transport (connection pooling, TLS config)
		// and timeout by wrapping them, rather than handing the whole
		// client to oauth2.NewClient - which builds a fresh client with
		// Timeout: 0, silently discarding --http-timeout for every
		// authenticated GitHub call.
		base := http.DefaultTransport
		var timeout time.Duration
		if httpClient != nil {
			timeout = httpClient.Timeout
			if httpClient.Transport != nil {
				base = httpClient.Transport
			}
		}
		httpClient = &http.Client{
			Transport: &oauth2.Transport{Source: ts, Base: base},
			Timeout:   timeout,
		}
	}

	return &Client{
		client: github.NewClient(httpClient),
	}
}

// paginateAll is a generic helper for paginating through GitHub API responses
type paginateFunc[T any] func(ctx context.Context, opts *github.ListOptions) ([]T, *github.Response, error)

func paginateAll[T any](ctx context.Context, fn paginateFunc[T]) ([]T, error) {
	var all []T
	opts := &github.ListOptions{
		Page:    1,
		PerPage: 100,
	}

	for {
		items, resp, err := fn(ctx, opts)
		if err != nil {
			return nil, err
		}

		all = append(all, items...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return all, nil
}

// GetReleases fetches releases for a repository
func (c *Client) GetReleases(ctx context.Context, owner, repo string) ([]*github.RepositoryRelease, error) {
	return paginateAll(ctx, func(ctx context.Context, opts *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error) {
		releases, resp, err := c.client.Repositories.ListReleases(ctx, owner, repo, opts)
		if err != nil {
			return nil, nil, fmt.Errorf("listing releases: %w", err)
		}
		return releases, resp, nil
	})
}

// GetLatestRelease fetches the latest release for a repository
func (c *Client) GetLatestRelease(ctx context.Context, owner, repo string) (*github.RepositoryRelease, error) {
	release, _, err := c.client.Repositories.GetLatestRelease(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("getting latest release: %w", err)
	}

	return release, nil
}

// GetTags fetches tags for a repository
func (c *Client) GetTags(ctx context.Context, owner, repo string) ([]*github.RepositoryTag, error) {
	return paginateAll(ctx, func(ctx context.Context, opts *github.ListOptions) ([]*github.RepositoryTag, *github.Response, error) {
		tags, resp, err := c.client.Repositories.ListTags(ctx, owner, repo, opts)
		if err != nil {
			return nil, nil, fmt.Errorf("listing tags: %w", err)
		}
		return tags, resp, nil
	})
}

// FilterTagsWithPrefix filters tags that start with a specific prefix
func (c *Client) FilterTagsWithPrefix(tags []*github.RepositoryTag, prefix string) []*github.RepositoryTag {
	if prefix == "" {
		return tags
	}

	var filtered []*github.RepositoryTag
	for _, tag := range tags {
		if tag.Name != nil && strings.HasPrefix(*tag.Name, prefix) {
			filtered = append(filtered, tag)
		}
	}

	return filtered
}

// ParseRepository parses a repository identifier like "golang/go" into owner and repo
func ParseRepository(identifier string) (*Repository, error) {
	parts := strings.Split(identifier, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository identifier: %s (expected format: owner/repo)", identifier)
	}

	return &Repository{
		Owner: parts[0],
		Name:  parts[1],
	}, nil
}

// GetCommitForTag gets the commit SHA for a specific tag
func (c *Client) GetCommitForTag(ctx context.Context, owner, repo, tag string) (string, error) {
	// Get the tag reference
	ref, _, err := c.client.Git.GetRef(ctx, owner, repo, fmt.Sprintf("tags/%s", tag))
	if err != nil {
		return "", fmt.Errorf("getting tag reference: %w", err)
	}

	if ref.Object == nil || ref.Object.SHA == nil {
		return "", fmt.Errorf("tag reference object or SHA is nil")
	}

	// Check if this is an annotated tag
	if ref.Object.Type != nil && *ref.Object.Type == "tag" {
		// This is an annotated tag - we need to dereference it to get the commit SHA
		tagObj, _, err := c.client.Git.GetTag(ctx, owner, repo, *ref.Object.SHA)
		if err != nil {
			return "", fmt.Errorf("getting tag object: %w", err)
		}

		if tagObj.Object == nil || tagObj.Object.SHA == nil {
			return "", fmt.Errorf("tag object or target SHA is nil")
		}

		return *tagObj.Object.SHA, nil
	}

	// This is a lightweight tag pointing directly to a commit
	return *ref.Object.SHA, nil
}

// GetCommitInfo gets detailed information about a commit
func (c *Client) GetCommitInfo(ctx context.Context, owner, repo, sha string) (*github.Commit, error) {
	commit, _, err := c.client.Git.GetCommit(ctx, owner, repo, sha)
	if err != nil {
		return nil, fmt.Errorf("getting commit: %w", err)
	}

	return commit, nil
}

// GetRepositoryCommit gets a repository commit (different from Git commit)
func (c *Client) GetRepositoryCommit(ctx context.Context, owner, repo, sha string) (*github.RepositoryCommit, error) {
	commit, _, err := c.client.Repositories.GetCommit(ctx, owner, repo, sha, nil)
	if err != nil {
		return nil, fmt.Errorf("getting repository commit: %w", err)
	}

	return commit, nil
}

// VerifyRepository checks if a repository exists and is accessible
func (c *Client) VerifyRepository(ctx context.Context, owner, repo string) error {
	_, _, err := c.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("verifying repository %s/%s: %w", owner, repo, err)
	}

	return nil
}

// ListReleasesByTag gets releases that match a specific tag pattern
func (c *Client) ListReleasesByTag(ctx context.Context, owner, repo, tagPattern string) ([]*github.RepositoryRelease, error) {
	releases, err := c.GetReleases(ctx, owner, repo)
	if err != nil {
		return nil, err
	}

	var filtered []*github.RepositoryRelease
	for _, release := range releases {
		if release.TagName != nil && strings.Contains(*release.TagName, tagPattern) {
			filtered = append(filtered, release)
		}
	}

	return filtered, nil
}

// GetTagsPage fetches a specific page of tags (useful for pagination)
func (c *Client) GetTagsPage(ctx context.Context, owner, repo string, page, perPage int) ([]*github.RepositoryTag, *github.Response, error) {
	opts := &github.ListOptions{
		Page:    page,
		PerPage: perPage,
	}

	tags, resp, err := c.client.Repositories.ListTags(ctx, owner, repo, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("listing tags page %d: %w", page, err)
	}

	return tags, resp, nil
}

// GetReleasesPage fetches a specific page of releases (useful for pagination)
func (c *Client) GetReleasesPage(ctx context.Context, owner, repo string, page, perPage int) ([]*github.RepositoryRelease, *github.Response, error) {
	opts := &github.ListOptions{
		Page:    page,
		PerPage: perPage,
	}

	releases, resp, err := c.client.Repositories.ListReleases(ctx, owner, repo, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("listing releases page %d: %w", page, err)
	}

	return releases, resp, nil
}

// GetFirstValidTag finds the first tag that passes all filtering criteria
func (c *Client) GetFirstValidTag(ctx context.Context, owner, repo string, tagPrefix, tagContains string, filter types.VersionFilterFunc) (string, error) {
	const maxPages = 10 // Limit search to 1000 tags (100 per page)
	opts := &github.ListOptions{
		Page:    1,
		PerPage: 100,
	}

	for page := 1; page <= maxPages; page++ {
		opts.Page = page
		tags, resp, err := c.client.Repositories.ListTags(ctx, owner, repo, opts)
		if err != nil {
			return "", fmt.Errorf("listing tags page %d: %w", page, err)
		}

		// Process each tag on this page
		for _, tag := range tags {
			if tag.Name == nil {
				continue
			}

			// Apply prefix filter at API level if specified for efficiency
			if tagPrefix != "" && !strings.HasPrefix(*tag.Name, tagPrefix) {
				continue
			}

			// Apply substring filter if specified
			if tagContains != "" && !strings.Contains(*tag.Name, tagContains) {
				continue
			}

			// Apply the unified filter function
			if filter(*tag.Name) {
				return *tag.Name, nil // Found first valid version, return immediately
			}
		}

		// If we have no more pages, break
		if resp.NextPage == 0 {
			break
		}
	}

	return "", fmt.Errorf("no valid version found after checking up to %d pages", maxPages)
}

// GetFirstValidRelease finds the first release that passes all filtering criteria
func (c *Client) GetFirstValidRelease(ctx context.Context, owner, repo string, tagPrefix, tagContains string, filter types.VersionFilterFunc) (string, error) {
	const maxPages = 5 // Limit search to 500 releases (100 per page)
	opts := &github.ListOptions{
		Page:    1,
		PerPage: 100,
	}

	for page := 1; page <= maxPages; page++ {
		opts.Page = page
		releases, resp, err := c.client.Repositories.ListReleases(ctx, owner, repo, opts)
		if err != nil {
			return "", fmt.Errorf("listing releases page %d: %w", page, err)
		}

		// Process each release on this page
		for _, release := range releases {
			if release.TagName == nil {
				continue
			}

			// Apply prefix filter at API level if specified for efficiency
			if tagPrefix != "" && !strings.HasPrefix(*release.TagName, tagPrefix) {
				continue
			}

			// Apply substring filter if specified
			if tagContains != "" && !strings.Contains(*release.TagName, tagContains) {
				continue
			}

			// Apply the unified filter function
			if filter(*release.TagName) {
				return *release.TagName, nil // Found first valid version, return immediately
			}
		}

		// If we have no more pages, break
		if resp.NextPage == 0 {
			break
		}
	}

	return "", fmt.Errorf("no valid version found after checking up to %d pages", maxPages)
}
