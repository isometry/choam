package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// hostStatus answers each host with a fixed status.
type hostStatus map[string]int

func (h hostStatus) RoundTrip(req *http.Request) (*http.Response, error) {
	status := h[req.URL.Host]
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(`{"message":"x"}`)),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Request:    req,
	}, nil
}

// TestSearcher_NotFoundOnlyWhenConfirmed: ErrNotFound only when both the raw
// host and the Contents API say 404 - a raw 404 for a private repository
// with an API failure (rate limit, 5xx) says nothing about existence.
func TestSearcher_NotFoundOnlyWhenConfirmed(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	tests := []struct {
		name         string
		raw, api     int
		wantNotFound bool
	}{
		{"both 404", 404, 404, true},
		{"raw 404, api rate limited", 404, 403, false},
		{"raw 404, api 5xx", 404, 502, false},
		{"raw 5xx, api 404", 503, 404, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: hostStatus{"raw.githubusercontent.com": tt.raw, "api.github.com": tt.api}}
			_, err := NewSearcher(client).GetFileContent(context.Background(), "o", "r", "go.sum", "v1")
			if err == nil {
				t.Fatal("want error")
			}
			if got := errors.Is(err, ErrNotFound); got != tt.wantNotFound {
				t.Errorf("errors.Is(err, ErrNotFound) = %v, want %v (err: %v)", got, tt.wantNotFound, err)
			}
		})
	}
}
