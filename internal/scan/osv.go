package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"osv.dev/bindings/go/api"
)

// osvClient is a minimal api.osv.dev client covering the two endpoints choam
// uses (POST /v1/querybatch, GET /v1/vulns/{id}). It replaces
// osv.dev/bindings/go/osvdev.OSVClient (only its api/osvschema message types
// are still used) because that client cannot be made fail-closed from the
// outside:
//   - it decodes with strict protojson.Unmarshal, so a field added to the OSV
//     schema after the bindings were generated fails every lookup; this client
//     decodes with DiscardUnknown;
//   - its retry backoff is a bare time.Sleep that ignores ctx and it retries
//     context.Canceled, so Ctrl+C waits out the full backoff; here a cancelled
//     ctx ends the retry loop immediately;
//   - it does not distinguish 404 (record genuinely absent) from any other
//     client error; here 404 is errOSVNotFound.
type osvClient struct {
	httpClient *http.Client
	baseURL    string
	userAgent  string

	// attempts bounds tries per request (429, 5xx and transport errors are
	// retried); backoff is the wait before retry n (n >= 1).
	attempts int
	backoff  func(n int) time.Duration
}

const (
	osvDefaultBaseURL = "https://api.osv.dev"

	// osvMaxQueriesPerBatch is api.osv.dev's per-request querybatch limit.
	osvMaxQueriesPerBatch = 1000
)

// errOSVNotFound reports a 404 from the OSV API.
var errOSVNotFound = errors.New("not found")

// osvDecode tolerates fields newer than the generated bindings.
var osvDecode = protojson.UnmarshalOptions{DiscardUnknown: true}

func newOSVClient(httpClient *http.Client) *osvClient {
	return &osvClient{
		httpClient: httpClient,
		baseURL:    osvDefaultBaseURL,
		userAgent:  "choam",
		attempts:   4,
		backoff:    func(n int) time.Duration { return time.Duration(n*n) * time.Second },
	}
}

// queryBatch runs one querybatch round (chunked at the API's limit) and
// returns exactly one result per query, in query order.
func (c *osvClient) queryBatch(ctx context.Context, queries []*api.Query) ([]*api.VulnerabilityList, error) {
	results := make([]*api.VulnerabilityList, 0, len(queries))
	for start := 0; start < len(queries); start += osvMaxQueriesPerBatch {
		chunk := queries[start:min(start+osvMaxQueriesPerBatch, len(queries))]
		body, err := protojson.Marshal(&api.BatchQuery{Queries: chunk})
		if err != nil {
			return nil, fmt.Errorf("encoding OSV batch query: %w", err)
		}
		var resp api.BatchVulnerabilityList
		if err := c.do(ctx, http.MethodPost, "/v1/querybatch", body, &resp); err != nil {
			return nil, err
		}
		if got := len(resp.GetResults()); got != len(chunk) {
			return nil, fmt.Errorf("OSV batch query returned %d results for %d queries", got, len(chunk))
		}
		results = append(results, resp.GetResults()...)
	}
	return results, nil
}

// getVuln fetches one full advisory record; errOSVNotFound when OSV has none.
func (c *osvClient) getVuln(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	var vuln osvschema.Vulnerability
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

func (c *osvClient) do(ctx context.Context, method, path string, body []byte, out proto.Message) error {
	var lastErr error
	for attempt := range c.attempts {
		wait := time.Duration(0)
		if attempt > 0 {
			wait = c.backoff(attempt)
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return err
		}
		status, respBody, err := c.once(ctx, method, path, body)
		switch {
		case err != nil:
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			lastErr = fmt.Errorf("attempt %d: request failed: %w", attempt+1, err)
		case status >= 200 && status < 300:
			if err := osvDecode.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("decoding OSV response from %s: %w", path, err)
			}
			return nil
		case status == http.StatusNotFound:
			return fmt.Errorf("%s %s: %w", method, path, errOSVNotFound)
		case status == http.StatusTooManyRequests || status >= 500:
			lastErr = fmt.Errorf("attempt %d: server error: status=%d body=%s", attempt+1, status, respBody)
		default:
			return fmt.Errorf("client error: status=%d body=%s", status, respBody)
		}
	}
	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *osvClient) once(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBody, nil
}

// sleepCtx waits d, or returns ctx's error as soon as it is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
