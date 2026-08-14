package updater

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	githubClient "github.com/isometry/choam/internal/github"
)

func TestMatchesTagFilters(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		prefix   string
		contains string
		want     bool
	}{
		{name: "no filters", value: "v2.9.0", want: true},
		{name: "prefix match", value: "v2.8.9", prefix: "v2.8.", want: true},
		{name: "prefix mismatch", value: "v2.9.0", prefix: "v2.8.", want: false},
		{name: "contains match", value: "v2.8.9", contains: "2.8", want: true},
		{name: "contains mismatch", value: "v2.9.0", contains: "2.8.", want: false},
		{name: "both match", value: "v2.8.9-rc1", prefix: "v2.8.", contains: "rc", want: true},
		{name: "prefix match contains mismatch", value: "v2.8.9", prefix: "v2.8.", contains: "rc", want: false},
		{name: "contains match prefix mismatch", value: "v2.9.0-rc1", prefix: "v2.8.", contains: "rc", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesTagFilters(tt.value, tt.prefix, tt.contains); got != tt.want {
				t.Errorf("matchesTagFilters(%q, %q, %q) = %v, want %v", tt.value, tt.prefix, tt.contains, got, tt.want)
			}
		})
	}
}

// rewriteTransport redirects all requests to the test server, regardless of
// the host the go-github client targets.
type rewriteTransport struct {
	host string
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = rt.host
	return http.DefaultTransport.RoundTrip(req)
}

func TestGetLatestValidGitHubVersion_TagFilters(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/fluxcd/flux2/releases", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[{"tag_name":"v2.9.0"},{"tag_name":"v2.8.9"},{"tag_name":"v2.8.8"}]`)
	})
	mux.HandleFunc("/repos/fluxcd/flux2/tags", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[{"name":"v2.9.0"},{"name":"v2.8.9"},{"name":"v2.8.8"}]`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}

	tests := []struct {
		name        string
		monitor     melange.GitHubMonitor
		wantVersion string
		wantSource  string
	}{
		{
			name: "deprecated tag-filter applies as prefix",
			monitor: melange.GitHubMonitor{
				Identifier:  "fluxcd/flux2",
				StripPrefix: "v",
				TagFilter:   "v2.8.",
			},
			wantVersion: "2.8.9",
			wantSource:  "github-releases",
		},
		{
			name: "tag-filter-prefix applies",
			monitor: melange.GitHubMonitor{
				Identifier:      "fluxcd/flux2",
				StripPrefix:     "v",
				TagFilterPrefix: "v2.8.",
			},
			wantVersion: "2.8.9",
			wantSource:  "github-releases",
		},
		{
			name: "tag-filter-prefix wins over deprecated tag-filter",
			monitor: melange.GitHubMonitor{
				Identifier:      "fluxcd/flux2",
				StripPrefix:     "v",
				TagFilter:       "v2.8.",
				TagFilterPrefix: "v2.9.",
			},
			wantVersion: "2.9.0",
			wantSource:  "github-releases",
		},
		{
			name: "no filters selects latest",
			monitor: melange.GitHubMonitor{
				Identifier:  "fluxcd/flux2",
				StripPrefix: "v",
			},
			wantVersion: "2.9.0",
			wantSource:  "github-releases",
		},
		{
			name: "tag-filter-contains applies",
			monitor: melange.GitHubMonitor{
				Identifier:        "fluxcd/flux2",
				StripPrefix:       "v",
				TagFilterContains: "2.8.",
			},
			wantVersion: "2.8.9",
			wantSource:  "github-releases",
		},
		{
			name: "deprecated tag-filter applies to tags path",
			monitor: melange.GitHubMonitor{
				Identifier:  "fluxcd/flux2",
				StripPrefix: "v",
				TagFilter:   "v2.8.",
				UseTags:     true,
			},
			wantVersion: "2.8.9",
			wantSource:  "github-tags",
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orchestrator := NewOrchestrator()
			orchestrator.githubClient = githubClient.New(&http.Client{
				Transport: rewriteTransport{host: serverURL.Host},
			})

			cfg := &melange.Configuration{}
			cfg.Package.Name = "flux-2.8"
			cfg.Package.Version = "2.8.8"
			cfg.Update.Enabled = true
			cfg.Update.GitHubMonitor = &tt.monitor

			vc := NewVersionChecker(orchestrator)
			gotVersion, gotSource, err := vc.getLatestValidGitHubVersion(context.Background(), cfg, cfg.Update.GitHubMonitor, orchestrator, logger)
			if err != nil {
				t.Fatalf("getLatestValidGitHubVersion() error = %v", err)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("getLatestValidGitHubVersion() version = %s, want %s", gotVersion, tt.wantVersion)
			}
			if gotSource != tt.wantSource {
				t.Errorf("getLatestValidGitHubVersion() source = %s, want %s", gotSource, tt.wantSource)
			}
		})
	}
}
