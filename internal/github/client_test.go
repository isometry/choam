package github

import (
	"net/http"
	"testing"

	"github.com/google/go-github/v75/github"
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
