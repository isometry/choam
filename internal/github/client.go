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

// firstMatch pages through a 100-per-page listing (at most maxPages pages) and
// returns the first item name that passes filter.
func firstMatch[T any](maxPages int, what string, list func(*github.ListOptions) ([]T, *github.Response, error), name func(T) *string, filter types.VersionFilterFunc) (string, error) {
	opts := &github.ListOptions{Page: 1, PerPage: 100}

	for page := 1; page <= maxPages; page++ {
		opts.Page = page
		items, resp, err := list(opts)
		if err != nil {
			return "", fmt.Errorf("listing %s page %d: %w", what, page, err)
		}

		for _, item := range items {
			if n := name(item); n != nil && filter(*n) {
				return *n, nil
			}
		}

		if resp.NextPage == 0 {
			break
		}
	}

	return "", fmt.Errorf("no valid version found after checking up to %d pages", maxPages)
}

// GetFirstValidTag finds the first tag (newest first, up to 1000 tags) that passes filter
func (c *Client) GetFirstValidTag(ctx context.Context, owner, repo string, filter types.VersionFilterFunc) (string, error) {
	return firstMatch(10, "tags", func(opts *github.ListOptions) ([]*github.RepositoryTag, *github.Response, error) {
		return c.client.Repositories.ListTags(ctx, owner, repo, opts)
	}, func(t *github.RepositoryTag) *string { return t.Name }, filter)
}

// GetFirstValidRelease finds the first release (newest first, up to 500 releases) that passes filter
func (c *Client) GetFirstValidRelease(ctx context.Context, owner, repo string, filter types.VersionFilterFunc) (string, error) {
	return firstMatch(5, "releases", func(opts *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error) {
		return c.client.Repositories.ListReleases(ctx, owner, repo, opts)
	}, func(r *github.RepositoryRelease) *string { return r.TagName }, filter)
}
