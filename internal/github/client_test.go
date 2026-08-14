package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-github/v81/github"
)

func TestParseRepository(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		wantOwner  string
		wantName   string
		wantErr    bool
	}{
		{
			name:       "valid repository",
			identifier: "golang/go",
			wantOwner:  "golang",
			wantName:   "go",
			wantErr:    false,
		},
		{
			name:       "invalid format - no slash",
			identifier: "golang",
			wantOwner:  "",
			wantName:   "",
			wantErr:    true,
		},
		{
			name:       "invalid format - too many parts",
			identifier: "golang/go/extra",
			wantOwner:  "",
			wantName:   "",
			wantErr:    true,
		},
		{
			name:       "empty identifier",
			identifier: "",
			wantOwner:  "",
			wantName:   "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, err := ParseRepository(tt.identifier)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRepository() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if repo == nil {
					t.Error("ParseRepository() returned nil repository")
					return
				}
				if repo.Owner != tt.wantOwner {
					t.Errorf("ParseRepository() owner = %s, want %s", repo.Owner, tt.wantOwner)
				}
				if repo.Name != tt.wantName {
					t.Errorf("ParseRepository() name = %s, want %s", repo.Name, tt.wantName)
				}
			}
		})
	}
}

// newTestClient returns a Client backed by a test server serving the given mux.
// Handlers must be registered under the enterprise API prefix "/api/v3/".
func newTestClient(t *testing.T, mux *http.ServeMux) *Client {
	t.Helper()

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, err := github.NewClient(nil).WithEnterpriseURLs(server.URL, server.URL)
	if err != nil {
		t.Fatalf("creating test GitHub client: %v", err)
	}

	return &Client{client: gh}
}

func TestClient_GetFirstValidRelease(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/fluxcd/flux2/releases", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[{"tag_name":"v2.9.0"},{"tag_name":"v2.8.9"},{"tag_name":"v2.8.8"}]`)
	})
	client := newTestClient(t, mux)

	acceptAll := func(string) bool { return true }

	tests := []struct {
		name        string
		tagPrefix   string
		tagContains string
		filter      func(string) bool
		want        string
		wantErr     bool
	}{
		{name: "no filters returns first", filter: acceptAll, want: "v2.9.0"},
		{name: "prefix filter", tagPrefix: "v2.8.", filter: acceptAll, want: "v2.8.9"},
		{name: "contains filter", tagContains: "2.8.", filter: acceptAll, want: "v2.8.9"},
		{name: "prefix and version filter combine", tagPrefix: "v2.8.", filter: func(tag string) bool { return !strings.Contains(tag, "2.8.9") }, want: "v2.8.8"},
		{name: "prefix without match errors", tagPrefix: "v3.", filter: acceptAll, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.GetFirstValidRelease(context.Background(), "fluxcd", "flux2", tt.tagPrefix, tt.tagContains, tt.filter)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetFirstValidRelease() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetFirstValidRelease() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClient_GetFirstValidTag(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/fluxcd/flux2/tags", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[{"name":"v2.9.0"},{"name":"v2.8.9"},{"name":"v2.8.8"}]`)
	})
	client := newTestClient(t, mux)

	acceptAll := func(string) bool { return true }

	tests := []struct {
		name        string
		tagPrefix   string
		tagContains string
		filter      func(string) bool
		want        string
		wantErr     bool
	}{
		{name: "no filters returns first", filter: acceptAll, want: "v2.9.0"},
		{name: "prefix filter", tagPrefix: "v2.8.", filter: acceptAll, want: "v2.8.9"},
		{name: "contains filter", tagContains: "2.8.", filter: acceptAll, want: "v2.8.9"},
		{name: "prefix and version filter combine", tagPrefix: "v2.8.", filter: func(tag string) bool { return !strings.Contains(tag, "2.8.9") }, want: "v2.8.8"},
		{name: "contains without match errors", tagContains: "rc", filter: acceptAll, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.GetFirstValidTag(context.Background(), "fluxcd", "flux2", tt.tagPrefix, tt.tagContains, tt.filter)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GetFirstValidTag() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetFirstValidTag() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClient_FilterTagsWithPrefix(t *testing.T) {
	client := New(&http.Client{})

	tags := []*github.RepositoryTag{
		{Name: new("v1.0.0")},
		{Name: new("v1.1.0")},
		{Name: new("go1.22.0")},
		{Name: new("go1.22.1")},
		{Name: new("release-2.0.0")},
	}

	tests := []struct {
		name     string
		tags     []*github.RepositoryTag
		prefix   string
		expected []string
	}{
		{
			name:     "filter with v prefix",
			tags:     tags,
			prefix:   "v",
			expected: []string{"v1.0.0", "v1.1.0"},
		},
		{
			name:     "filter with go prefix",
			tags:     tags,
			prefix:   "go",
			expected: []string{"go1.22.0", "go1.22.1"},
		},
		{
			name:     "filter with release prefix",
			tags:     tags,
			prefix:   "release",
			expected: []string{"release-2.0.0"},
		},
		{
			name:     "no prefix",
			tags:     tags,
			prefix:   "",
			expected: []string{"v1.0.0", "v1.1.0", "go1.22.0", "go1.22.1", "release-2.0.0"},
		},
		{
			name:     "no matches",
			tags:     tags,
			prefix:   "nonexistent",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.FilterTagsWithPrefix(tt.tags, tt.prefix)

			if len(result) != len(tt.expected) {
				t.Errorf("FilterTagsWithPrefix() returned %d items, want %d", len(result), len(tt.expected))
				return
			}

			for i, tag := range result {
				if tag.Name != nil && *tag.Name != tt.expected[i] {
					t.Errorf("FilterTagsWithPrefix()[%d].Name = %s, want %s", i, *tag.Name, tt.expected[i])
				}
			}
		})
	}
}
