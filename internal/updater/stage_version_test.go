package updater

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	githubClient "github.com/isometry/choam/internal/github"
	"github.com/isometry/choam/internal/httpclient"
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
				TagFilter:   "v2.8.", //nolint:staticcheck // exercises the deprecated tag-filter compat path
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
				TagFilter:       "v2.8.", //nolint:staticcheck // exercises the deprecated tag-filter compat path
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
				TagFilter:   "v2.8.", //nolint:staticcheck // exercises the deprecated tag-filter compat path
				UseTags:     true,
			},
			wantVersion: "2.8.9",
			wantSource:  "github-tags",
		},
		{
			name: "tag-filter-contains applies to tags path",
			monitor: melange.GitHubMonitor{
				Identifier:        "fluxcd/flux2",
				StripPrefix:       "v",
				TagFilterContains: "2.8.",
				UseTags:           true,
			},
			wantVersion: "2.8.9",
			wantSource:  "github-tags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orchestrator := NewOrchestratorWithTimeout(httpclient.DefaultTimeout)
			orchestrator.githubClient = githubClient.New(&http.Client{
				Transport: rewriteTransport{host: serverURL.Host},
			})

			cfg := &melange.Configuration{}
			cfg.Package.Name = "flux-2.8"
			cfg.Package.Version = "2.8.8"
			cfg.Update.Enabled = true
			cfg.Update.GitHubMonitor = &tt.monitor

			vc := NewVersionChecker(orchestrator)
			gotVersion, gotSource, err := vc.getLatestValidGitHubVersion(t.Context(), cfg, cfg.Update.GitHubMonitor, orchestrator)
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

// gitTagSelector wires newestValidTag the way getLatestValidGitVersion does.
func gitTagSelector(t *testing.T, monitor *melange.GitMonitor, preRelease bool) func(tags []string) (string, bool) {
	t.Helper()
	ctx := t.Context()
	cfg := &melange.Configuration{}
	cfg.Update.EnablePreReleaseTags = preRelease
	cfg.Update.GitMonitor = monitor
	vf := NewVersionFilter()
	vc := &VersionChecker{}
	inner := vc.createVersionFilter(ctx, cfg, vf)
	accept := func(tag string) bool {
		return matchesTagFilters(tag, monitor.TagFilterPrefix, monitor.TagFilterContains) && inner(tag)
	}
	process := func(tag string) string {
		p, _, _ := vf.ProcessVersion(ctx, tag, &cfg.Update)
		return p
	}
	return func(tags []string) (string, bool) {
		return newestValidTag(tags, accept, process, NewVersionComparator().Compare)
	}
}

func TestNewestValidTag(t *testing.T) {
	tests := []struct {
		name       string
		monitor    melange.GitMonitor
		preRelease bool
		tags       []string
		want       string
		wantOK     bool
	}{
		{
			name: "final release beats its rc with pre-releases enabled", preRelease: true,
			monitor: melange.GitMonitor{StripPrefix: "v"},
			tags:    []string{"v1.36.5", "v1.36.6-rc.1", "v1.36.6"},
			want:    "1.36.6", wantOK: true,
		},
		{
			name: "rc newer than last final is chosen when enabled", preRelease: true,
			monitor: melange.GitMonitor{StripPrefix: "v"},
			tags:    []string{"v1.36.5", "v1.36.6-rc.1"},
			want:    "1.36.6-rc.1", wantOK: true,
		},
		{
			name:    "pre-releases disabled rejects the rc",
			monitor: melange.GitMonitor{StripPrefix: "v"},
			tags:    []string{"v1.36.5", "v1.36.6-rc.1"},
			want:    "1.36.5", wantOK: true,
		},
		{
			name:    "multi-part numeric: 1.10.0 beats 1.9.0",
			monitor: melange.GitMonitor{StripPrefix: "v"},
			tags:    []string{"v1.9.0", "v1.10.0", "v1.2.0"},
			want:    "1.10.0", wantOK: true,
		},
		{
			name:    "strip-prefix: release-1.10 beats release-1.9",
			monitor: melange.GitMonitor{StripPrefix: "release-"},
			tags:    []string{"release-1.9", "release-1.10", "release-1.8"},
			want:    "1.10", wantOK: true,
		},
		{
			name:    "tag filter prefix restricts candidates",
			monitor: melange.GitMonitor{StripPrefix: "v", TagFilterPrefix: "v1.8."},
			tags:    []string{"v1.9.0", "v1.8.2", "v1.8.10"},
			want:    "1.8.10", wantOK: true,
		},
		{
			name:    "no valid tag",
			monitor: melange.GitMonitor{StripPrefix: "v"},
			tags:    []string{"nightly", "foo", "v1.0.0-rc.1"},
			wantOK:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel := gitTagSelector(t, &tt.monitor, tt.preRelease)
			// Every rotation of the input must agree: the result is
			// independent of the order the remote lists tags in.
			for i := range tt.tags {
				rot := append(append([]string{}, tt.tags[i:]...), tt.tags[:i]...)
				got, ok := sel(rot)
				if ok != tt.wantOK || got != tt.want {
					t.Errorf("order %v: got (%q, %v), want (%q, %v)", rot, got, ok, tt.want, tt.wantOK)
				}
			}
		})
	}
}

func TestNewestValidTag_TieBreakAndCompareError(t *testing.T) {
	identity := func(s string) string { return s }
	always := func(string) bool { return true }

	// Versions that compare equal but differ textually: the greater raw tag
	// wins whatever the listing order.
	equal := func(string, string) (int, error) { return 0, nil }
	for _, tags := range [][]string{{"1.0", "1.0.0"}, {"1.0.0", "1.0"}} {
		if got, ok := newestValidTag(tags, always, identity, equal); !ok || got != "1.0.0" {
			t.Errorf("order %v: got (%q, %v), want (1.0.0, true)", tags, got, ok)
		}
	}

	// A comparison error never displaces an already chosen candidate.
	boom := func(string, string) (int, error) { return 0, fmt.Errorf("boom") }
	if got, ok := newestValidTag([]string{"1.0.0", "2.0.0"}, always, identity, boom); !ok || got != "1.0.0" {
		t.Errorf("compare error: got (%q, %v), want (1.0.0, true)", got, ok)
	}
}
