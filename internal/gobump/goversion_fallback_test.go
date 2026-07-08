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
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m)
		require.NoError(t, err)
		assert.Equal(t, "1.26", got)
	})

	t.Run("go.mod without a go directive contributes nothing", func(t *testing.T) {
		server := fakeGoProxy(t, map[string]string{
			"/example.com/a/@v/v1.2.0.mod": "module example.com/a\n",
		})
		m := &ModrootAnalysis{DesiredDeps: []string{"example.com/a@v1.2.0"}}
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m)
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("uppercase module paths are proxy-escaped", func(t *testing.T) {
		server := fakeGoProxy(t, map[string]string{
			"/github.com/!some!org/dep/@v/v1.0.0.mod": "module github.com/SomeOrg/dep\n\ngo 1.25\n",
		})
		m := &ModrootAnalysis{DesiredDeps: []string{"github.com/SomeOrg/dep@v1.0.0"}}
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m)
		require.NoError(t, err)
		assert.Equal(t, "1.25", got)
	})

	t.Run("no candidates - empty without error", func(t *testing.T) {
		server := fakeGoProxy(t, nil)
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, &ModrootAnalysis{})
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("every fetch failed - error for the caller to warn about", func(t *testing.T) {
		server := fakeGoProxy(t, nil) // 404s everything
		m := &ModrootAnalysis{DesiredDeps: []string{"example.com/a@v1.2.0"}}
		got, err := fallbackRequiredGoVersion(t.Context(), server.Client(), server.URL, m)
		require.Error(t, err)
		assert.Equal(t, "", got)
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
}
