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
	ecojava "github.com/isometry/choam/internal/ecosystem/java"
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
	body   string         // raw 200 body; "" serves a requirement-less go.mod
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
		if s.body != "" {
			body = s.body
		}
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
func parsedProcessor(t *testing.T, yamlContent string) *Processor {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o644))
	cfg, err := melange.ParseConfiguration(t.Context(), path)
	require.NoError(t, err)
	gp := NewProcessor(path, cfg.Package.Name, cfg.Package.Version, int64(cfg.Package.Epoch))
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

// TestPerformAnalysis_JavaManifestOverride: a java step's with.manifest is
// fetched checkout-relative in place of <modroot>/pom.xml, and a 404 on it
// still fails (a typo stays visible).
func TestPerformAnalysis_JavaManifestOverride(t *testing.T) {
	const pom = `<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>`
	run := func(t *testing.T, status map[string]int, unit analysisUnit) (*sourceStub, error) {
		t.Helper()
		stub := &sourceStub{status: status, body: pom}
		v := &VulnerabilityChecker{Analyzer: NewAnalyzer(&http.Client{Transport: stub})}
		_, err := v.performAnalysis(t.Context(), ecojava.New(), "java", "https://github.com/o/r", "v1.0.0",
			[]analysisUnit{unit}, []config.BumpStep{}, newTestProcessor(t, singleGoBumpYAML))
		return stub, err
	}

	stub, err := run(t, map[string]int{"pom.xml": 200}, analysisUnit{Modroot: "sub", Manifest: "bom/pom.xml"})
	require.NoError(t, err)
	assert.Equal(t, []string{"/o/r/v1.0.0/bom/pom.xml"}, stub.paths)

	stub, err = run(t, map[string]int{"pom.xml": 200}, analysisUnit{Modroot: "sub"})
	require.NoError(t, err)
	assert.Equal(t, []string{"/o/r/v1.0.0/sub/pom.xml"}, stub.paths)

	_, err = run(t, map[string]int{}, analysisUnit{Modroot: ".", Manifest: "bom/pom.xml"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file not found")
}

func TestDiscoverAnalysisUnits_ManifestFromFirstStep(t *testing.T) {
	steps := []config.BumpStep{
		{Index: 1, Language: "java", Modroots: []string{"."}, Manifest: "bom/pom.xml"},
		{Index: 2, Language: "java", Modroots: []string{"."}, Manifest: "other/pom.xml"},
	}
	units, _ := discoverAnalysisUnits(t.Context(), nil, steps, nil)
	require.Len(t, units["java"], 1)
	assert.Equal(t, "bom/pom.xml", units["java"][0].Manifest)
}

// TestPerformAnalysis_JavaGradleSkipped: a java modroot with no pom.xml but a
// Gradle build file is skipped (not analysed, not an error); with neither, an
// explicit manifest: that 404s, or a failed marker probe, it still fails.
func TestPerformAnalysis_JavaGradleSkipped(t *testing.T) {
	const pom = `<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>`
	tests := []struct {
		name     string
		status   map[string]int
		manifest string
		wantErr  string
		wantSkip bool
		analysed bool
	}{
		{name: "build.gradle", status: map[string]int{"build.gradle": 200}, wantSkip: true},
		{name: "settings.gradle.kts", status: map[string]int{"settings.gradle.kts": 200}, wantSkip: true},
		{name: "neither pom nor gradle", status: map[string]int{}, wantErr: "file not found"},
		{name: "marker probe fails closed", status: map[string]int{"build.gradle": 502}, wantErr: "502"},
		{name: "pom.xml analysed", status: map[string]int{"pom.xml": 200, "build.gradle": 200}, analysed: true},
		{name: "explicit manifest 404 does not probe", status: map[string]int{"build.gradle": 200}, manifest: "bom/pom.xml", wantErr: "file not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &sourceStub{status: tt.status, body: pom}
			v := &VulnerabilityChecker{Analyzer: NewAnalyzer(&http.Client{Transport: stub})}
			gp := newTestProcessor(t, singleGoBumpYAML)
			res, err := v.performAnalysis(t.Context(), ecojava.New(), "java", "https://github.com/o/r", "v1.0.0",
				[]analysisUnit{{Modroot: ".", Manifest: tt.manifest}}, []config.BumpStep{}, gp)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				if tt.manifest != "" {
					assert.Equal(t, []string{"/o/r/v1.0.0/" + tt.manifest}, stub.paths, "no marker probe")
				}
				return
			}
			require.NoError(t, err)
			if tt.analysed {
				assert.Len(t, res.Analysis.ByModroot, 1)
				assert.Empty(t, gp.SkipReasons)
				return
			}
			assert.Empty(t, res.Analysis.ByModroot)
			require.Len(t, gp.SkipReasons, 1)
			assert.Equal(t, "java modroot .: gradle project: java dependency analysis unsupported", gp.SkipReasons[0])
		})
	}
}

// TestCheckVulnerabilities_GradleSpecSkipped: a whole java spec on a Gradle
// upstream analyses cleanly and reports as skipped (status SKIPPED).
func TestCheckVulnerabilities_GradleSpecSkipped(t *testing.T) {
	spec := strings.Replace(singleGoBumpYAML, `  - uses: go/build
    with:
      packages: .

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
`, `  - uses: bump
    with:
      language: java
      deps: |-
        g@a@1.0
`, 1)
	stub := &sourceStub{status: map[string]int{"build.gradle.kts": 200}}
	v := &VulnerabilityChecker{Analyzer: NewAnalyzer(&http.Client{Transport: stub})}
	gp := parsedProcessor(t, spec)

	_, err := v.checkVulnerabilities(t.Context(), gp)
	require.NoError(t, err)
	r := gp.ToResult()
	assert.Equal(t, 0, r.VulnerabilitiesFound)
	require.Len(t, r.SkipReasons, 1)
	assert.Contains(t, r.SkipReasons[0], "gradle")
}
