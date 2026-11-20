package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v81/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// TestNew_PreservesConfiguredTimeoutWhenAuthenticated is a regression test:
// New used to hand the caller's *http.Client wholesale to oauth2.NewClient,
// which built a fresh client with Timeout: 0, silently discarding
// --http-timeout for every authenticated GitHub call. New must instead wrap
// the caller's transport (and keep its Timeout) with oauth2's
// token-injecting RoundTripper.
func TestNew_PreservesConfiguredTimeoutWhenAuthenticated(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "test-token")

	customTransport := &http.Transport{}
	configured := &http.Client{Timeout: 7 * time.Second, Transport: customTransport}
	client := New(configured)

	got := client.client.Client()
	require.NotNil(t, got)
	assert.Equal(t, 7*time.Second, got.Timeout,
		"the configured --http-timeout must survive oauth2 wrapping")

	transport, ok := got.Transport.(*oauth2.Transport)
	require.True(t, ok, "transport must be wrapped with oauth2.Transport, got %T", got.Transport)
	assert.Same(t, customTransport, transport.Base,
		"the caller's original transport must be preserved as the oauth2 wrapper's base, not discarded")
}

// TestNew_NoTokenLeavesClientUntouched confirms New is a no-op (beyond
// go-github's own defaulting) when GITHUB_TOKEN is unset.
func TestNew_NoTokenLeavesClientUntouched(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")

	configured := &http.Client{Timeout: 3 * time.Second}
	client := New(configured)

	got := client.client.Client()
	require.NotNil(t, got)
	assert.Equal(t, 3*time.Second, got.Timeout)
}

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

func TestClient_GetFirstValid(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/fluxcd/flux2/releases", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[{"name":"nameless"},{"tag_name":"v2.9.0"},{"tag_name":"v2.8.9"},{"tag_name":"v2.8.8"}]`)
	})
	mux.HandleFunc("/api/v3/repos/fluxcd/flux2/tags", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[{"commit":{}},{"name":"v2.9.0"},{"name":"v2.8.9"},{"name":"v2.8.8"}]`)
	})
	client := newTestClient(t, mux)

	sources := map[string]func(context.Context, string, string, func(string) bool) (string, error){
		"tags": func(ctx context.Context, o, r string, f func(string) bool) (string, error) {
			return client.GetFirstValidTag(ctx, o, r, f)
		},
		"releases": func(ctx context.Context, o, r string, f func(string) bool) (string, error) {
			return client.GetFirstValidRelease(ctx, o, r, f)
		},
	}

	tests := []struct {
		name    string
		filter  func(string) bool
		want    string
		wantErr string
	}{
		{name: "accept all returns first, skipping unnamed", filter: func(string) bool { return true }, want: "v2.9.0"},
		{name: "filter skips rejected", filter: func(tag string) bool { return !strings.Contains(tag, "2.9") }, want: "v2.8.9"},
		{name: "filter skips several", filter: func(tag string) bool { return strings.HasSuffix(tag, ".8") }, want: "v2.8.8"},
		{name: "no match errors", filter: func(string) bool { return false }, wantErr: "no valid version found after checking up to"},
	}

	for kind, get := range sources {
		for _, tt := range tests {
			t.Run(kind+"/"+tt.name, func(t *testing.T) {
				got, err := get(context.Background(), "fluxcd", "flux2", tt.filter)
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			})
		}
	}
}

func TestClient_GetFirstValid_APIError(t *testing.T) {
	client := newTestClient(t, http.NewServeMux()) // unrouted paths 404

	_, err := client.GetFirstValidTag(context.Background(), "fluxcd", "flux2", func(string) bool { return true })
	require.ErrorContains(t, err, "listing tags page 1:")

	_, err = client.GetFirstValidRelease(context.Background(), "fluxcd", "flux2", func(string) bool { return true })
	require.ErrorContains(t, err, "listing releases page 1:")
}
