package anitya

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

const (
	// DefaultBaseURL is the base URL for the release-monitoring.org API
	DefaultBaseURL = "https://release-monitoring.org/api/v2"
)

// Client represents a client for the release-monitoring.org API
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// New creates a new anitya client with a custom HTTP client
// The httpClient parameter is required and should be obtained from httpclient.NewHTTPClient()
func New(httpClient *http.Client) *Client {
	if httpClient == nil {
		panic("anitya.New: httpClient cannot be nil")
	}
	return &Client{
		baseURL:    DefaultBaseURL,
		httpClient: httpClient,
		token:      os.Getenv("ANITYA_TOKEN"),
	}
}

// IsAuthenticated checks if the client is using authentication
func (c *Client) IsAuthenticated() bool {
	return c.token != ""
}

// GetProject fetches a project by its ID
func (c *Client) GetProject(ctx context.Context, id int) (*Project, error) {
	// Use the v1 API endpoint which works correctly for individual project lookups
	// Use hardcoded URL since the v1 endpoint is different from the v2 base URL
	baseURL := "https://release-monitoring.org"
	if c.baseURL != DefaultBaseURL {
		// If a custom base URL is set (e.g., for testing), use it
		baseURL = c.baseURL
	}
	url := fmt.Sprintf("%s/api/project/%d", baseURL, id)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	// Add authentication if token is available
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var project Project
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &project, nil
}

// GetLatestVersion returns the latest version for a project by ID
func (c *Client) GetLatestVersion(ctx context.Context, id int) (string, error) {
	project, err := c.GetProject(ctx, id)
	if err != nil {
		return "", fmt.Errorf("getting project: %w", err)
	}

	if project.Version == "" {
		return "", fmt.Errorf("no version information available for project %d", id)
	}

	return project.Version, nil
}

// GetStableVersions returns all stable versions for a project by ID
func (c *Client) GetStableVersions(ctx context.Context, id int) ([]string, error) {
	project, err := c.GetProject(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("getting project: %w", err)
	}

	return project.StableVersions, nil
}
