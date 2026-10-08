package gobump

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/config"
	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sourceStub answers raw.githubusercontent.com and api.github.com requests
// from a per-file status table (any file not listed: 404 on both), recording
// every requested raw path. OSV is never reached: the served go.mod has no
// requirements.
type sourceStub struct {
	mu     sync.Mutex
	status map[string]int // basename -> status for both hosts
	paths  []string
}

func (s *sourceStub) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	name := filepath.Base(req.URL.Path)
	s.mu.Lock()
	if req.URL.Host == "raw.githubusercontent.com" {
		s.paths = append(s.paths, req.URL.Path)
	}
	status, ok := s.status[name]
	s.mu.Unlock()
	if !ok {
		status = http.StatusNotFound
	}
	body := `{"message":"error"}`
	if status == http.StatusOK && req.URL.Host == "raw.githubusercontent.com" {
		body = "module example.com/app\n\ngo 1.22\n"
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Request:    req,
	}, nil
}

func TestPerformAnalysis_FetchFailuresFailClosed(t *testing.T) {
	tests := []struct {
		name    string
		status  map[string]int
		wantErr string
	}{
		{name: "go.sum confirmed absent is fine", status: map[string]int{"go.mod": 200}},
		{name: "go.mod confirmed absent fails", status: map[string]int{}, wantErr: "file not found"},
		{name: "go.mod 5xx fails", status: map[string]int{"go.mod": 502}, wantErr: "502"},
		{name: "go.mod rate limited fails", status: map[string]int{"go.mod": 403}, wantErr: "403"},
		{name: "go.sum 5xx fails (only a confirmed 404 is optional)", status: map[string]int{"go.mod": 200, "go.sum": 500}, wantErr: "500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &sourceStub{status: tt.status}
			v := &VulnerabilityChecker{Analyzer: NewAnalyzer(&http.Client{Transport: stub})}
			gp := newTestProcessor(t, singleGoBumpYAML)

			_, err := v.performAnalysis(t.Context(), ecogolang.New(), "go", "https://github.com/o/r", "v1.0.0",
				[]analysisUnit{{Modroot: "."}}, []config.BumpStep{}, gp)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}

	t.Run("cancellation fails", func(t *testing.T) {
		stub := &sourceStub{status: map[string]int{"go.mod": 200}}
		v := &VulnerabilityChecker{Analyzer: NewAnalyzer(&http.Client{Transport: stub})}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := v.performAnalysis(ctx, ecogolang.New(), "go", "https://github.com/o/r", "v1.0.0",
			[]analysisUnit{{Modroot: "."}}, []config.BumpStep{}, newTestProcessor(t, singleGoBumpYAML))
		require.ErrorIs(t, err, context.Canceled)
	})
}

// parsedProcessor is newTestProcessor with the melange Config parsed, as
// ProcessFile wires it.
func parsedProcessor(t *testing.T, yamlContent string) *GoBumpProcessor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o644))
	cfg, err := melange.ParseConfiguration(t.Context(), path)
	require.NoError(t, err)
	gp := NewGoBumpProcessor(path, cfg.Package.Name, cfg.Package.Version, int64(cfg.Package.Epoch))
	gp.Config = cfg
	gp.OriginalYAML = []byte(yamlContent)
	gp.SetCurrentYAML([]byte(yamlContent))
	return gp
}

func TestCheckVulnerabilities_UnfetchableSourceIsSkipped(t *testing.T) {
	gitlab := strings.Replace(singleGoBumpYAML, "https://github.com/example/example", "https://gitlab.com/example/example", 1)
	ssh := strings.Replace(singleGoBumpYAML, "https://github.com/example/example", "git@github.com:example/example.git", 1)
	fetchBased := strings.Replace(singleGoBumpYAML, `  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}`, `  - uses: fetch
    with:
      uri: https://example.com/example-${{package.version}}.tar.gz
      expected-sha256: 0000000000000000000000000000000000000000000000000000000000000000`, 1)

	for name, spec := range map[string]string{"gitlab": gitlab, "ssh": ssh, "fetch": fetchBased} {
		t.Run(name, func(t *testing.T) {
			stub := &sourceStub{status: map[string]int{"go.mod": 200}}
			v := &VulnerabilityChecker{Analyzer: NewAnalyzer(&http.Client{Transport: stub})}
			gp := parsedProcessor(t, spec)

			analysis, err := v.checkVulnerabilities(t.Context(), gp)
			require.NoError(t, err)
			assert.Zero(t, analysis.VulnerabilitiesFound)
			require.Len(t, gp.SkipReasons, 1)
			assert.Contains(t, gp.SkipReasons[0], "cannot fetch dependency manifests")
			assert.Empty(t, stub.paths, "nothing is fetched for a skipped source")
			assert.NotEmpty(t, gp.ToResult().SkipReasons)
		})
	}
}

func TestCheckVulnerabilities_FetchesAtExpectedCommit(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	spec := strings.Replace(singleGoBumpYAML, "      tag: v${{package.version}}\n",
		"      tag: v${{package.version}}\n      expected-commit: "+commit+"\n", 1)

	stub := &sourceStub{status: map[string]int{"go.mod": 200}}
	v := &VulnerabilityChecker{Analyzer: NewAnalyzer(&http.Client{Transport: stub})}
	gp := parsedProcessor(t, spec)

	analysis, err := v.checkVulnerabilities(t.Context(), gp)
	require.NoError(t, err)
	assert.Empty(t, gp.SkipReasons)
	assert.Equal(t, commit, analysis.ExpectedCommit)
	require.NotEmpty(t, stub.paths)
	for _, p := range stub.paths {
		assert.Contains(t, p, "/"+commit+"/", "manifests are fetched at the commit melange builds")
	}
}
