package gobump

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// GitHubFileResponse represents the GitHub API response for file content
type GitHubFileResponse struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

// Fetcher handles fetching go.mod and go.sum files from git repositories
type Fetcher struct {
	httpClient *http.Client
}

// NewFetcher creates a new fetcher with the provided HTTP client
func NewFetcher(httpClient *http.Client) *Fetcher {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Fetcher{
		httpClient: httpClient,
	}
}

// FetchGoMod fetches go.mod content from a git repository
// Uses GitHub API for private repos, falls back to raw.githubusercontent.com for public repos
func (f *Fetcher) FetchGoMod(ctx context.Context, repoURL, tag, goModPath string) ([]byte, error) {
	// First try raw URL (works for public repos)
	rawURL, err := f.buildRawURL(repoURL, tag, goModPath)
	if err != nil {
		return nil, fmt.Errorf("building raw URL: %w", err)
	}

	content, err := f.fetchFromRawURL(ctx, rawURL)
	if err == nil {
		return content, nil
	}

	// If raw URL fails with 404, try GitHub API (for private repos)
	if strings.Contains(err.Error(), "HTTP error 404") {
		content, apiErr := f.fetchFromGitHubAPI(ctx, repoURL, tag, goModPath)
		if apiErr == nil {
			return content, nil
		}
		// Return the original error if API also fails
		return nil, fmt.Errorf("failed to fetch from both raw URL (%w) and GitHub API (%v)", err, apiErr)
	}

	return nil, err
}

// FetchGoSum fetches go.sum content from a git repository
// Uses GitHub API for private repos, falls back to raw.githubusercontent.com for public repos
func (f *Fetcher) FetchGoSum(ctx context.Context, repoURL, tag, goSumPath string) ([]byte, error) {
	// First try raw URL (works for public repos)
	rawURL, err := f.buildRawURL(repoURL, tag, goSumPath)
	if err != nil {
		return nil, fmt.Errorf("building raw URL: %w", err)
	}

	content, err := f.fetchFromRawURL(ctx, rawURL)
	if err == nil {
		return content, nil
	}

	// If raw URL fails with 404, try GitHub API (for private repos)
	if strings.Contains(err.Error(), "HTTP error 404") {
		content, apiErr := f.fetchFromGitHubAPI(ctx, repoURL, tag, goSumPath)
		if apiErr == nil {
			return content, nil
		}
		// Return the original error if API also fails
		return nil, fmt.Errorf("failed to fetch from both raw URL (%w) and GitHub API (%v)", err, apiErr)
	}

	return nil, err
}

// fetchFromRawURL fetches content from raw.githubusercontent.com
func (f *Fetcher) fetchFromRawURL(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching go.mod from %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d fetching %s", resp.StatusCode, rawURL)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return content, nil
}

// fetchFromGitHubAPI fetches content using GitHub API (supports private repos with authentication)
func (f *Fetcher) fetchFromGitHubAPI(ctx context.Context, repoURL, tag, goModPath string) ([]byte, error) {
	// Parse GitHub repo info from URL
	githubURLPattern := regexp.MustCompile(`https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)
	matches := githubURLPattern.FindStringSubmatch(repoURL)
	if len(matches) != 3 {
		return nil, fmt.Errorf("invalid GitHub URL format: %s", repoURL)
	}

	owner := matches[1]
	repo := matches[2]
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", owner, repo, goModPath, tag)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GitHub API request: %w", err)
	}

	// Add GitHub token if available
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API HTTP error %d for %s", resp.StatusCode, apiURL)
	}

	var fileResp GitHubFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&fileResp); err != nil {
		return nil, fmt.Errorf("decoding GitHub API response: %w", err)
	}

	// Decode base64 content
	if fileResp.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected encoding: %s (expected base64)", fileResp.Encoding)
	}

	content, err := base64.StdEncoding.DecodeString(fileResp.Content)
	if err != nil {
		return nil, fmt.Errorf("decoding base64 content: %w", err)
	}

	return content, nil
}

// buildRawURL converts a GitHub repository URL to a raw content URL
func (f *Fetcher) buildRawURL(repoURL, tag, filepath string) (string, error) {
	// Handle GitHub URLs - convert to raw.githubusercontent.com format
	if strings.Contains(repoURL, "github.com") {
		githubURLPattern := regexp.MustCompile(`https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)
		matches := githubURLPattern.FindStringSubmatch(repoURL)
		if len(matches) == 3 {
			owner := matches[1]
			repo := matches[2]
			return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, tag, filepath), nil
		}
	}

	return "", fmt.Errorf("unsupported repository URL format: %s", repoURL)
}