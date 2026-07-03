package github

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/chainguard-dev/omnibump/pkg/remote"
	"github.com/google/go-github/v75/github"
)

// Searcher satisfies omnibump's remote.GitHubSearcher interface.
var _ remote.GitHubSearcher = (*Searcher)(nil)

// Searcher adapts CHOAM's GitHub access to omnibump's remote.GitHubSearcher
// interface (GetFileContent + ListFilePaths), so that omnibump's remote fetcher
// can retrieve go.mod/go.sum files without checking out the repository.
//
// GetFileContent prefers the unauthenticated raw.githubusercontent.com fast path
// (which avoids consuming GitHub API rate limit for public repositories) and
// falls back to the authenticated Contents API for private repositories.
type Searcher struct {
	client  *github.Client
	rawHTTP *http.Client
}

// NewSearcher creates a Searcher. The provided httpClient is used both to build
// the (optionally token-authenticated) go-github client and for raw content
// fetches; if nil, http.DefaultClient is used for raw fetches.
func NewSearcher(httpClient *http.Client) *Searcher {
	rawHTTP := httpClient
	if rawHTTP == nil {
		rawHTTP = http.DefaultClient
	}
	return &Searcher{
		client:  New(httpClient).client,
		rawHTTP: rawHTTP,
	}
}

// GetFileContent fetches the content of a file at a specific ref, trying the raw
// content host first and falling back to the authenticated Contents API.
func (s *Searcher) GetFileContent(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, ref, path)
	content, rawErr := s.fetchRaw(ctx, rawURL)
	if rawErr == nil {
		return content, nil
	}

	// Fall back to the Contents API (handles private repos and raw outages).
	fileContent, _, _, apiErr := s.client.Repositories.GetContents(
		ctx, owner, repo, path,
		&github.RepositoryContentGetOptions{Ref: ref},
	)
	if apiErr != nil {
		return nil, fmt.Errorf("fetching %s/%s/%s@%s: raw (%w), api (%v)", owner, repo, path, ref, rawErr, apiErr)
	}
	if fileContent == nil {
		return nil, fmt.Errorf("fetching %s/%s/%s@%s: path is not a file", owner, repo, path, ref)
	}

	decoded, err := fileContent.GetContent()
	if err != nil {
		return nil, fmt.Errorf("decoding %s/%s/%s@%s: %w", owner, repo, path, ref, err)
	}
	return []byte(decoded), nil
}

// ListFilePaths returns all blob paths in a repository at the given ref using the
// Git Tree API. It is provided to satisfy the remote.GitHubSearcher interface;
// CHOAM fetches known modroots directly and does not rely on it.
func (s *Searcher) ListFilePaths(ctx context.Context, owner, repo, ref string) ([]string, error) {
	sha, _, err := s.client.Repositories.GetCommitSHA1(ctx, owner, repo, ref, "")
	if err != nil {
		return nil, fmt.Errorf("resolving ref %q for %s/%s: %w", ref, owner, repo, err)
	}

	tree, _, err := s.client.Git.GetTree(ctx, owner, repo, sha, true)
	if err != nil {
		return nil, fmt.Errorf("listing tree for %s/%s@%s: %w", owner, repo, ref, err)
	}

	paths := make([]string, 0, len(tree.Entries))
	for _, entry := range tree.Entries {
		if entry.GetType() == "blob" {
			paths = append(paths, entry.GetPath())
		}
	}
	return paths, nil
}

// fetchRaw performs a GET against raw.githubusercontent.com.
func (s *Searcher) fetchRaw(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := s.rawHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d fetching %s", resp.StatusCode, rawURL)
	}

	return io.ReadAll(resp.Body)
}
