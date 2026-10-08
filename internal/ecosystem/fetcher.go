package ecosystem

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/chainguard-dev/omnibump/pkg/remote"
	choamgithub "github.com/isometry/choam/internal/github"
)

// githubURLPattern extracts owner/repo from a GitHub repository URL such as
// "https://github.com/owner/repo" or "https://github.com/owner/repo.git".
var githubURLPattern = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)

// ErrUnsupportedRepository marks a repository URL manifests cannot be fetched
// from (anything but https://github.com/owner/repo: GitLab, other hosts, the
// ssh form) - the package is skipped, never reported clean.
var ErrUnsupportedRepository = errors.New("unsupported repository URL (only https://github.com/<owner>/<repo> is supported)")

// ErrNotFound reports a confirmed 404 for a manifest file at the ref (see
// github.ErrNotFound); every other fetch failure is a plain error.
var ErrNotFound = choamgithub.ErrNotFound

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
// given ref (a commit or tag) and repository-relative path.
func (f *Fetcher) FetchFile(ctx context.Context, repoURL, ref, path string) ([]byte, error) {
	repo, err := repositoryRefFromURL(repoURL, ref)
	if err != nil {
		return nil, err
	}

	file, err := f.remote.GetFile(ctx, repo, path)
	if err != nil {
		return nil, fmt.Errorf("fetching %s from %s@%s: %w", path, repoURL, ref, err)
	}

	return file.Content, nil
}

// CheckRepository reports whether manifests can be fetched from repoURL
// (ErrUnsupportedRepository otherwise).
func CheckRepository(repoURL string) error {
	_, err := repositoryRefFromURL(repoURL, "")
	return err
}

// repositoryRefFromURL parses a GitHub repository URL into a remote.RepositoryRef.
func repositoryRefFromURL(repoURL, ref string) (remote.RepositoryRef, error) {
	matches := githubURLPattern.FindStringSubmatch(repoURL)
	if len(matches) != 3 {
		return remote.RepositoryRef{}, fmt.Errorf("%w: %s", ErrUnsupportedRepository, repoURL)
	}

	return remote.RepositoryRef{
		Host:  "github.com",
		Owner: matches[1],
		Repo:  matches[2],
		Ref:   ref,
	}, nil
}
