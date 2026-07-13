package gobump

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGoProxy serves {module}/@v/{version}.mod fixtures; any other path 404s.
func fakeGoProxy(t *testing.T, mods map[string]string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := mods[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

// releaseFixtureServer serves a golang.org/toolchain module @v/list naming
// exactly the given bare release versions (e.g. "1.26.0") as linux/amd64
// entries - all LatestAvailable needs, since it never fetches .info. Any
// other path 404s (via fakeGoProxy). Pointing GOPROXY at this server and
// constructing a gorelease.Index (gorelease.NewIndex, e.g. via NewAnalyzer)
// exercises the same newIndexWithBaseURL seam gorelease's own tests use,
// just through the public, GOPROXY-driven constructor.
func releaseFixtureServer(t *testing.T, releases ...string) *httptest.Server {
	t.Helper()
	var body strings.Builder
	for _, v := range releases {
		body.WriteString("v0.0.1-go" + v + ".linux-amd64\n")
	}
	return fakeGoProxy(t, map[string]string{
		"/golang.org/toolchain/@v/list": body.String(),
	})
}

func TestFallbackCandidates(t *testing.T) {
	m := &ModrootAnalysis{
		DesiredDeps: []string{
			"example.com/a@v1.2.0",
			"example.com/b@v2.0.0",
			"example.com/a@v1.2.0", // duplicate
			"malformed",            // no version - skipped
		},
		DesiredReplaces: []string{
			"example.com/old=example.com/new@v3.0.0",
			"not-gobump-grammar@v1.0.0", // no "=" - skipped
		},
	}

	got := fallbackCandidates(m)
	assert.Equal(t, []moduleVersion{
		{module: "example.com/a", version: "v1.2.0"},
		{module: "example.com/b", version: "v2.0.0"},
		{module: "example.com/new", version: "v3.0.0"},
	}, got)
}

func TestFallbackRequiredGoVersion(t *testing.T) {
	t.Run("max across candidates, per-fetch failures skipped", func(t *testing.T) {
		server := fakeGoProxy(t, map[string]string{
			"/example.com/a/@v/v1.2.0.mod":   "module example.com/a\n\ngo 1.24\n",
			"/example.com/new/@v/v3.0.0.mod": "module example.com/new\n\ngo 1.26\n",
			// example.com/b intentionally missing (404) - skipped, not fatal.
		})

		m := &ModrootAnalysis{
			DesiredDeps:     []string{"example.com/a@v1.2.0", "example.com/b@v2.0.0"},
			DesiredReplaces: []string{"example.com/old=example.com/new@v3.0.0"},
		}
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m, nil)
		require.NoError(t, err)
		assert.Equal(t, "1.26", got)
	})

	t.Run("go.mod without a go directive contributes nothing", func(t *testing.T) {
		server := fakeGoProxy(t, map[string]string{
			"/example.com/a/@v/v1.2.0.mod": "module example.com/a\n",
		})
		m := &ModrootAnalysis{DesiredDeps: []string{"example.com/a@v1.2.0"}}
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m, nil)
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("uppercase module paths are proxy-escaped", func(t *testing.T) {
		server := fakeGoProxy(t, map[string]string{
			"/github.com/!some!org/dep/@v/v1.0.0.mod": "module github.com/SomeOrg/dep\n\ngo 1.25\n",
		})
		m := &ModrootAnalysis{DesiredDeps: []string{"github.com/SomeOrg/dep@v1.0.0"}}
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m, nil)
		require.NoError(t, err)
		assert.Equal(t, "1.25", got)
	})

	t.Run("no candidates - empty without error", func(t *testing.T) {
		server := fakeGoProxy(t, nil)
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, &ModrootAnalysis{}, nil)
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("every fetch failed - error for the caller to warn about", func(t *testing.T) {
		server := fakeGoProxy(t, nil) // 404s everything
		m := &ModrootAnalysis{DesiredDeps: []string{"example.com/a@v1.2.0"}}
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m, nil)
		require.Error(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("private candidate is skipped and never hits the proxy", func(t *testing.T) {
		var hitPaths []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hitPaths = append(hitPaths, r.URL.Path)
			switch r.URL.Path {
			case "/example.com/public/@v/v1.0.0.mod":
				_, _ = w.Write([]byte("module example.com/public\n\ngo 1.25\n"))
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(server.Close)

		m := &ModrootAnalysis{DesiredDeps: []string{
			"example.com/public@v1.0.0",
			"example.com/private/secret@v2.0.0",
		}}
		skip := func(modulePath string) bool {
			return strings.HasPrefix(modulePath, "example.com/private/")
		}

		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m, skip)
		require.NoError(t, err)
		assert.Equal(t, "1.25", got)
		assert.NotContains(t, hitPaths, "/example.com/private/secret/@v/v2.0.0.mod",
			"private candidate must never be sent to the proxy")
	})

	t.Run("all candidates private - warns honestly instead of silently omitting the raise", func(t *testing.T) {
		var hit bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hit = true
			http.NotFound(w, r)
		}))
		t.Cleanup(server.Close)

		m := &ModrootAnalysis{DesiredDeps: []string{
			"example.com/private/a@v1.0.0",
			"example.com/private/b@v2.0.0",
		}}
		skip := func(modulePath string) bool { return true }

		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m, skip)
		require.Error(t, err)
		assert.Equal(t, "", got)
		assert.Contains(t, err.Error(), "2 private modules skipped")
		assert.False(t, hit, "no candidate should reach the proxy when every candidate is private")
	})
}

// fallbackAnalysis builds a single-go-modroot analysis whose pristine go.mod
// carries the given go directive, desiring one dep candidate.
func fallbackAnalysis(t *testing.T, goDirective string) *VulnerabilityAnalysis {
	t.Helper()
	goMod := "module example.com/app\n\ngo " + goDirective + "\n"
	deps, err := ecogolang.New().Analyze(t.Context(), map[string][]byte{"go.mod": []byte(goMod)})
	require.NoError(t, err)

	return &VulnerabilityAnalysis{
		ByLanguage: []LanguageAnalysis{{
			Language: "go",
			ByModroot: []ModrootAnalysis{{
				Modroot:     ".",
				Deps:        deps,
				DesiredDeps: []string{"example.com/a@v1.2.0"},
			}},
		}},
		BumpActions: []BumpAction{{Action: "needs_bump", Language: "go", Modroots: []string{"."}}},
	}
}

func TestGoBumpApplier_FallbackGoVersions(t *testing.T) {
	server := fakeGoProxy(t, map[string]string{
		"/example.com/a/@v/v1.2.0.mod": "module example.com/a\n\ngo 1.26\n",
	})
	newApplier := func() *GoBumpApplier {
		// Pin the proxy env hermetically: an inherited ambient GOPROXY/
		// GOPRIVATE/GONOPROXY must not leak into these tests.
		t.Setenv("GOPROXY", "")
		t.Setenv("GOPRIVATE", "")
		t.Setenv("GONOPROXY", "")
		applier := NewGoBumpApplier(nil)
		applier.goProxyURL = server.URL
		return applier
	}

	t.Run("sets RequiredGoVersion when above baseline, labeled best-effort", func(t *testing.T) {
		gp := newTestProcessor(t, singleGoBumpYAML)
		analysis := fallbackAnalysis(t, "1.22")

		newApplier().fallbackGoVersions(t.Context(), gp, analysis)

		assert.Equal(t, "1.26", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion)
		var messaged bool
		for _, msg := range gp.GetMessages() {
			if strings.Contains(msg, "best-effort") && strings.Contains(msg, "run with simulation") {
				messaged = true
			}
		}
		assert.True(t, messaged, "expected a best-effort message, got %v", gp.GetMessages())
	})

	t.Run("gated against the baseline", func(t *testing.T) {
		gp := newTestProcessor(t, singleGoBumpYAML)
		analysis := fallbackAnalysis(t, "1.26") // baseline already covers the candidates

		newApplier().fallbackGoVersions(t.Context(), gp, analysis)
		assert.Equal(t, "", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion)
	})

	t.Run("simulated modroots are not probed", func(t *testing.T) {
		gp := newTestProcessor(t, singleGoBumpYAML)
		analysis := fallbackAnalysis(t, "1.22")
		analysis.ByLanguage[0].ByModroot[0].Simulated = true

		newApplier().fallbackGoVersions(t.Context(), gp, analysis)
		assert.Equal(t, "", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion)
	})

	t.Run("total probe failure warns and proceeds", func(t *testing.T) {
		t.Setenv("GOPROXY", "")
		t.Setenv("GOPRIVATE", "")
		t.Setenv("GONOPROXY", "")
		failing := fakeGoProxy(t, nil)
		applier := NewGoBumpApplier(nil)
		applier.goProxyURL = failing.URL

		gp := newTestProcessor(t, singleGoBumpYAML)
		analysis := fallbackAnalysis(t, "1.22")

		applier.fallbackGoVersions(t.Context(), gp, analysis)
		assert.Equal(t, "", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion)
		var warned bool
		for _, msg := range gp.GetMessages() {
			if strings.Contains(msg, "could not determine required Go version") {
				warned = true
			}
		}
		assert.True(t, warned, "expected a probe-failure warning, got %v", gp.GetMessages())
	})

	t.Run("non-go languages untouched", func(t *testing.T) {
		gp := newTestProcessor(t, singleGoBumpYAML)
		analysis := fallbackAnalysis(t, "1.22")
		analysis.ByLanguage[0].Language = "rust"

		newApplier().fallbackGoVersions(t.Context(), gp, analysis)
		assert.Equal(t, "", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion)
	})

	t.Run("validates the probed required Go version against known releases", func(t *testing.T) {
		t.Run("known minor accepted", func(t *testing.T) {
			t.Setenv("GOPRIVATE", "")
			t.Setenv("GONOPROXY", "")
			modServer := fakeGoProxy(t, map[string]string{
				"/example.com/a/@v/v1.2.0.mod": "module example.com/a\n\ngo 1.26\n",
			})
			releaseServer := releaseFixtureServer(t, "1.26.0")
			t.Setenv("GOPROXY", releaseServer.URL) // wires Analyzer.goReleases via gorelease.NewIndex

			analyzer := NewAnalyzer(releaseServer.Client())
			applier := NewGoBumpApplier(analyzer)
			applier.goProxyURL = modServer.URL // separate server for the go.mod probe

			gp := newTestProcessor(t, singleGoBumpYAML)
			analysis := fallbackAnalysis(t, "1.22")

			applier.fallbackGoVersions(t.Context(), gp, analysis)

			assert.Equal(t, "1.26", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion)
			for _, msg := range gp.GetMessages() {
				assert.NotContains(t, msg, "not a known Go release")
			}
		})

		t.Run("1.99 rejected + message", func(t *testing.T) {
			t.Setenv("GOPRIVATE", "")
			t.Setenv("GONOPROXY", "")
			modServer := fakeGoProxy(t, map[string]string{
				"/example.com/a/@v/v1.2.0.mod": "module example.com/a\n\ngo 1.99\n",
			})
			releaseServer := releaseFixtureServer(t, "1.26.0") // 1.99 was never released
			t.Setenv("GOPROXY", releaseServer.URL)

			analyzer := NewAnalyzer(releaseServer.Client())
			applier := NewGoBumpApplier(analyzer)
			applier.goProxyURL = modServer.URL

			gp := newTestProcessor(t, singleGoBumpYAML)
			analysis := fallbackAnalysis(t, "1.22")

			applier.fallbackGoVersions(t.Context(), gp, analysis)

			assert.Equal(t, "", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion,
				"an unknown Go release must never become a floor")
			var rejected bool
			for _, msg := range gp.GetMessages() {
				if strings.Contains(msg, "candidate dependencies claim to require Go 1.99, which is not a known Go release") &&
					strings.Contains(msg, "check the dependency's go.mod") {
					rejected = true
				}
			}
			assert.True(t, rejected, "expected the unknown-release rejection message, got %v", gp.GetMessages())
		})

		t.Run("release index offline fails open with a warning", func(t *testing.T) {
			t.Setenv("GOPRIVATE", "")
			t.Setenv("GONOPROXY", "")
			modServer := fakeGoProxy(t, map[string]string{
				"/example.com/a/@v/v1.2.0.mod": "module example.com/a\n\ngo 1.26\n",
			})
			failingIndex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "boom", http.StatusInternalServerError)
			}))
			t.Cleanup(failingIndex.Close)
			t.Setenv("GOPROXY", failingIndex.URL)

			analyzer := NewAnalyzer(failingIndex.Client())
			applier := NewGoBumpApplier(analyzer)
			applier.goProxyURL = modServer.URL

			gp := newTestProcessor(t, singleGoBumpYAML)
			analysis := fallbackAnalysis(t, "1.22")

			applier.fallbackGoVersions(t.Context(), gp, analysis)

			assert.Equal(t, "1.26", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion,
				"an unreachable release index must fail open and keep the probed result")
			var warned bool
			for _, msg := range gp.GetMessages() {
				if strings.Contains(msg, "could not validate required Go 1.26") && strings.Contains(msg, "index unavailable") {
					warned = true
				}
			}
			assert.True(t, warned, "expected an index-unavailable warning, got %v", gp.GetMessages())
		})
	})

	t.Run("GOPROXY=off disables the probe entirely and messages once per modroot", func(t *testing.T) {
		t.Setenv("GOPROXY", "off")
		t.Setenv("GOPRIVATE", "")
		t.Setenv("GONOPROXY", "")
		applier := NewGoBumpApplier(nil)
		require.True(t, applier.probeDisabled)
		// Point goProxyURL at the shared fixture too: if the probe were not
		// actually skipped, it would succeed against this server and defeat
		// the assertion below.
		applier.goProxyURL = server.URL

		gp := newTestProcessor(t, singleGoBumpYAML)
		analysis := fallbackAnalysis(t, "1.22")

		applier.fallbackGoVersions(t.Context(), gp, analysis)
		assert.Equal(t, "", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion)
		var messaged bool
		for _, msg := range gp.GetMessages() {
			if strings.Contains(msg, "GOPROXY=off") && strings.Contains(msg, "skipping best-effort Go version probe") {
				messaged = true
			}
		}
		assert.True(t, messaged, "expected a GOPROXY=off skip message, got %v", gp.GetMessages())
	})

	t.Run("GOPRIVATE candidate skipped end-to-end, all-private warns", func(t *testing.T) {
		t.Setenv("GOPROXY", "")
		t.Setenv("GOPRIVATE", "example.com/*")
		t.Setenv("GONOPROXY", "")
		applier := NewGoBumpApplier(nil)
		applier.goProxyURL = server.URL // never hit: the only candidate is private

		gp := newTestProcessor(t, singleGoBumpYAML)
		analysis := fallbackAnalysis(t, "1.22") // candidate: example.com/a@v1.2.0

		applier.fallbackGoVersions(t.Context(), gp, analysis)
		assert.Equal(t, "", analysis.ByLanguage[0].ByModroot[0].RequiredGoVersion)
		var warned bool
		for _, msg := range gp.GetMessages() {
			if strings.Contains(msg, "could not determine required Go version") && strings.Contains(msg, "private modules skipped") {
				warned = true
			}
		}
		assert.True(t, warned, "expected an all-private warning naming the skipped count, got %v", gp.GetMessages())
	})
}

// TestGoBumpApplier_ReleaseIndex covers the releaseIndex() accessor: nil-safe
// like httpClient() when no Analyzer is wired, and otherwise sourced from
// Analyzer.goReleases - the per-run gorelease.Index both validation sites
// consult.
func TestGoBumpApplier_ReleaseIndex(t *testing.T) {
	t.Run("nil Analyzer - nil index", func(t *testing.T) {
		applier := &GoBumpApplier{}
		assert.Nil(t, applier.releaseIndex())
	})

	t.Run("wired from Analyzer.goReleases", func(t *testing.T) {
		analyzer := NewAnalyzer(nil)
		applier := &GoBumpApplier{Analyzer: analyzer}
		assert.Same(t, analyzer.goReleases, applier.releaseIndex())
	})
}

func TestNewGoBumpApplier_GOPROXYWiring(t *testing.T) {
	tests := []struct {
		name              string
		goproxy           string
		wantGoProxyURL    string
		wantProbeDisabled bool
	}{
		{name: "unset - default", goproxy: "", wantGoProxyURL: defaultGoProxyURL, wantProbeDisabled: false},
		{name: "usable URL", goproxy: "https://proxy.example.com", wantGoProxyURL: "https://proxy.example.com", wantProbeDisabled: false},
		{name: "direct - unusable, falls back to default", goproxy: "direct", wantGoProxyURL: defaultGoProxyURL, wantProbeDisabled: false},
		{name: "off - unusable, falls back to default, probe disabled", goproxy: "off", wantGoProxyURL: defaultGoProxyURL, wantProbeDisabled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOPROXY", tt.goproxy)
			applier := NewGoBumpApplier(nil)
			assert.Equal(t, tt.wantGoProxyURL, applier.goProxyURL)
			assert.Equal(t, tt.wantProbeDisabled, applier.probeDisabled)
		})
	}
}

func TestNewGoBumpApplier_GOPRIVATEWiring(t *testing.T) {
	t.Setenv("GOPROXY", "")
	t.Setenv("GOPRIVATE", "example.com/private/*")
	t.Setenv("GONOPROXY", "")

	applier := NewGoBumpApplier(nil)
	assert.Equal(t, "example.com/private/*", applier.goPrivate)
	assert.Equal(t, "", applier.goNoProxy)
	assert.True(t, applier.skipPrivateModule("example.com/private/foo"))
	assert.False(t, applier.skipPrivateModule("example.com/public/foo"))
}
