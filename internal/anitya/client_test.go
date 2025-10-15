package anitya

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/isometry/choam/internal/httpclient"
)

func TestClient_GetProject(t *testing.T) {
	// Mock server that matches the actual v1 API endpoint structure
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract project ID from URL path (e.g., /api/project/123)
		if !strings.HasPrefix(r.URL.Path, "/api/project/") {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		projectID := strings.TrimPrefix(r.URL.Path, "/api/project/")

		switch projectID {
		case "123":
			// Response matches the actual v1 API format (direct project object)
			response := `{
				"id": 123,
				"name": "test-project",
				"backend": "GitHub",
				"ecosystem": "https://github.com",
				"homepage": "https://example.com",
				"created_on": 1672531200.0,
				"updated_on": 1672617600.0,
				"version": "1.2.3",
				"stable_versions": ["1.0.0", "1.1.0", "1.2.3"],
				"versions": ["1.0.0", "1.1.0", "1.2.0-alpha", "1.2.3"]
			}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client with custom base URL for testing
	client := New(httpclient.NewHTTPClient())
	client.baseURL = server.URL // This will override the default URL logic

	tests := []struct {
		name    string
		id      int
		wantErr bool
	}{
		{
			name:    "valid project ID",
			id:      123,
			wantErr: false,
		},
		{
			name:    "invalid project ID",
			id:      999,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			project, err := client.GetProject(ctx, tt.id)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetProject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if project == nil {
					t.Error("GetProject() returned nil project")
					return
				}
				if project.ID != 123 {
					t.Errorf("GetProject() project ID = %d, want 123", project.ID)
				}
				if project.Name != "test-project" {
					t.Errorf("GetProject() project name = %s, want test-project", project.Name)
				}
				if project.Version != "1.2.3" {
					t.Errorf("GetProject() project version = %s, want 1.2.3", project.Version)
				}
			}
		})
	}
}

func TestClient_GetLatestVersion(t *testing.T) {
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/project/") {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		projectID := strings.TrimPrefix(r.URL.Path, "/api/project/")

		switch projectID {
		case "123":
			response := `{
				"id": 123,
				"name": "test-project",
				"version": "1.2.3"
			}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		case "456":
			response := `{
				"id": 456,
				"name": "no-version-project",
				"version": ""
			}`
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(response))
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create client with custom base URL for testing
	client := New(httpclient.NewHTTPClient())
	client.baseURL = server.URL

	tests := []struct {
		name        string
		id          int
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "project with version",
			id:          123,
			wantVersion: "1.2.3",
			wantErr:     false,
		},
		{
			name:        "project without version",
			id:          456,
			wantVersion: "",
			wantErr:     true,
		},
		{
			name:        "non-existent project",
			id:          999,
			wantVersion: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			version, err := client.GetLatestVersion(ctx, tt.id)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetLatestVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && version != tt.wantVersion {
				t.Errorf("GetLatestVersion() version = %s, want %s", version, tt.wantVersion)
			}
		})
	}
}

func TestClient_GetStableVersions(t *testing.T) {
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/project/") {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		response := `{
			"id": 123,
			"name": "test-project",
			"stable_versions": ["1.0.0", "1.1.0", "1.2.3"]
		}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	// Create client with custom base URL for testing
	client := New(httpclient.NewHTTPClient())
	client.baseURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	versions, err := client.GetStableVersions(ctx, 123)
	if err != nil {
		t.Fatalf("GetStableVersions() error = %v", err)
	}

	expectedVersions := []string{"1.0.0", "1.1.0", "1.2.3"}
	if len(versions) != len(expectedVersions) {
		t.Errorf("GetStableVersions() returned %d versions, want %d", len(versions), len(expectedVersions))
		return
	}

	for i, version := range versions {
		if version != expectedVersions[i] {
			t.Errorf("GetStableVersions()[%d] = %s, want %s", i, version, expectedVersions[i])
		}
	}
}

func TestUnixTime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    int64
		wantErr bool
	}{
		{
			name:    "valid unix timestamp",
			input:   []byte("1672531200.0"),
			want:    1672531200,
			wantErr: false,
		},
		{
			name:    "integer timestamp",
			input:   []byte("1672531200"),
			want:    1672531200,
			wantErr: false,
		},
		{
			name:    "invalid input",
			input:   []byte("\"not-a-number\""),
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ut UnixTime
			err := json.Unmarshal(tt.input, &ut)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				got := ut.Time().Unix()
				if got != tt.want {
					t.Errorf("UnmarshalJSON() timestamp = %d, want %d", got, tt.want)
				}
			}
		})
	}
}
