package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanPackages_DeterministicFromCache: a scan served entirely from the
// cache must produce byte-identical findings and bumps every time - their
// order feeds candidate order and so the written deps.
func TestScanPackages_DeterministicFromCache(t *testing.T) {
	scanner := newTestScanner(newMockHTTPClient(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unexpected OSV request: every package and advisory is cached")
	})))

	var pkgs []Package
	for i := range 12 {
		name := fmt.Sprintf("example.com/mod%02d", i)
		pkgs = append(pkgs, Package{Name: name, Version: "v1.0.0", Ecosystem: "Go"})
		var vulns []*osvschema.Vulnerability
		for j := range 3 {
			vuln := mockVulnerability(fmt.Sprintf("GO-2026-%02d%d", i, j), "Go", name, fmt.Sprintf("1.%d.0", j+1))
			scanner.cache.SetAdvisory(vuln.GetId(), vuln)
			vulns = append(vulns, vuln)
		}
		scanner.cache.Set(cacheKeyFor("Go", name, "1.0.0"), vulns)
	}

	render := func() string {
		result, err := scanner.ScanPackages(t.Context(), pkgs)
		require.NoError(t, err)
		b, err := json.Marshal(result)
		require.NoError(t, err)
		return string(b)
	}
	want := render()
	for range 50 {
		require.Equal(t, want, render())
	}
}

// TestProcessVulnerability_IncompatibleFix: GHSA records the
// docker/distribution fix as 2.8.2-beta.1 (no +incompatible); for a module
// without a /vN path the only valid spelling of the release is
// v2.8.2+incompatible.
func TestProcessVulnerability_IncompatibleFix(t *testing.T) {
	scanner := newTestScanner(&http.Client{})
	vuln := mockVulnerability("GHSA-hqxw-f8mx-cpmw", "Go", "github.com/docker/distribution", "2.8.2-beta.1")
	got := scanner.processVulnerability(t.Context(), vuln,
		Package{Name: "github.com/docker/distribution", Version: "2.8.1+incompatible", Ecosystem: "Go"})
	require.NotNil(t, got)
	assert.Equal(t, "v2.8.2+incompatible", got.FixedVersion)
}

func TestCanonicalModuleVersion(t *testing.T) {
	tests := []struct{ path, version, want string }{
		{"github.com/docker/distribution", "v2.8.2", "v2.8.2+incompatible"},
		{"github.com/docker/distribution", "v2.8.2+incompatible", "v2.8.2+incompatible"},
		{"github.com/docker/distribution", "v2.0.0-20200101000000-abcdefabcdef", "v2.0.0-20200101000000-abcdefabcdef+incompatible"},
		{"github.com/foo/bar/v2", "v2.3.0", "v2.3.0"},
		{"github.com/foo/bar", "v1.3.0", "v1.3.0"},
		{"github.com/foo/bar", "v0.3.0", "v0.3.0"},
		{"gopkg.in/yaml.v3", "v3.0.1", "v3.0.1"},
		{"github.com/foo/bar", "not-a-version", "not-a-version"},
		{"github.com/foo/bar", "", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, CanonicalModuleVersion(tt.path, tt.version), "%s@%s", tt.path, tt.version)
	}
}

func TestPreferVersion(t *testing.T) {
	for _, pair := range [][2]string{{"v2.8.2", "v2.8.2+incompatible"}, {"2.8.2", "2.8.2+incompatible"}} {
		assert.Equal(t, pair[1], PreferVersion(pair[0], pair[1]))
		assert.Equal(t, pair[1], PreferVersion(pair[1], pair[0]))
	}
	assert.Equal(t, "v1.2.0", PreferVersion("v1.2", "v1.2.0"))
	assert.Equal(t, "v1.2.0", PreferVersion("v1.2.0", "v1.2"))
}
