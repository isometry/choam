package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSVClient_Retry(t *testing.T) {
	tests := []struct {
		name      string
		statuses  []int
		wantErr   string
		wantCalls int
	}{
		{name: "5xx then success", statuses: []int{503, 200}, wantCalls: 2},
		{name: "429 then success", statuses: []int{429, 200}, wantCalls: 2},
		{name: "persistent 5xx exhausts attempts", statuses: []int{500, 500, 500}, wantErr: "max retries exceeded", wantCalls: 3},
		{name: "4xx is not retried", statuses: []int{403}, wantErr: "client error", wantCalls: 1},
		{name: "404 is not found", statuses: []int{404}, wantErr: "not found", wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := tt.statuses[min(calls, len(tt.statuses)-1)]
				calls++
				w.WriteHeader(status)
				if status == 200 {
					_, _ = w.Write([]byte(`{"id":"GO-1"}`))
				}
			}))
			defer srv.Close()

			c := newOSVClient(srv.Client())
			c.baseURL = srv.URL
			c.attempts = 3
			c.backoff = func(int) time.Duration { return 0 }

			vuln, err := c.getVuln(context.Background(), "GO-1")
			assert.Equal(t, tt.wantCalls, calls)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "GO-1", vuln.GetId())
		})
	}
}

// TestOSVClient_BackoffStopsOnCancel: a cancelled ctx ends the retry backoff
// immediately with context.Canceled (the osvdev binding slept it out).
func TestOSVClient_BackoffStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newOSVClient(srv.Client())
	c.baseURL = srv.URL
	c.backoff = func(int) time.Duration { return time.Hour }

	start := time.Now()
	_, err := c.getVuln(ctx, "GO-1")
	require.ErrorIs(t, err, context.Canceled)
	assert.Less(t, time.Since(start), 10*time.Second)
}
