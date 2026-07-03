package ecosystem

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/chainguard-dev/omnibump/pkg/remote"
	choamgithub "github.com/isometry/choam/internal/github"
)

// githubURLPattern extracts owner/repo from a GitHub repository URL such as
// "https://github.com/owner/repo" or "https://github.com/owner/repo.git".
var githubURLPattern = regexp.MustCompile(`https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)

// Fetcher fetches manifest/lockfile content from GitHub repositories without
// a local checkout, via omnibump's remote fetcher (raw content first,
// falling back to the authenticated Contents API for private repositories).
// It is shared across all ecosystems - the transport is language-agnostic.
type Fetcher struct {
	remote remote.RemoteFetcher
}

// NewFetcher creates a new fetcher with the provided HTTP client.
// The httpClient parameter is required and should be obtained from httpclient.NewHTTPClient()
func NewFetcher(httpClient *http.Client) *Fetcher {
	if httpClient == nil {
		panic("ecosystem.NewFetcher: httpClient cannot be nil")
	}
	return &Fetcher{
		remote: remote.NewGitHubFetcher(choamgithub.NewSearcher(httpClient)),
	}
}

// FetchFile fetches a single file's content from a git repository at the
// given modroot-relative path.
func (f *Fetcher) FetchFile(ctx context.Context, repoURL, tag, path string) ([]byte, error) {
	repo, err := repositoryRefFromURL(repoURL, tag)
	if err != nil {
		return nil, err
	}

	file, err := f.remote.GetFile(ctx, repo, path)
	if err != nil {
		return nil, fmt.Errorf("fetching %s from %s@%s: %w", path, repoURL, tag, err)
	}

	return file.Content, nil
}

// repositoryRefFromURL parses a GitHub repository URL into a remote.RepositoryRef.
func repositoryRefFromURL(repoURL, tag string) (remote.RepositoryRef, error) {
	if !strings.Contains(repoURL, "github.com") {
		return remote.RepositoryRef{}, fmt.Errorf("unsupported repository URL format: %s", repoURL)
	}

	matches := githubURLPattern.FindStringSubmatch(repoURL)
	if len(matches) != 3 {
		return remote.RepositoryRef{}, fmt.Errorf("unsupported repository URL format: %s", repoURL)
	}

	return remote.RepositoryRef{
		Host:  "github.com",
		Owner: matches[1],
		Repo:  matches[2],
		Ref:   tag,
	}, nil
}
