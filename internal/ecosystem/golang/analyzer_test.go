package golang

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/isometry/choam/internal/logging"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

func TestAnalyzer_AnalyzeBumps(t *testing.T) {
	tests := []struct {
		name        string
		deps        []string
		goModInfo   *GoModInfo
		wantKeep    []string
		wantRemove  map[string]string // dep -> action type
		wantReasons map[string]string // dep -> reason substring
	}{
		{
			name: "deduplicate same module different versions - keep latest",
			deps: []string{
				"github.com/gin-gonic/gin@v1.9.0",
				"github.com/gin-gonic/gin@v1.9.1",
				"github.com/gin-gonic/gin@v1.8.5",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/gin-gonic/gin": "v1.8.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{"github.com/gin-gonic/gin@v1.9.1"},
			wantRemove: map[string]string{
				"github.com/gin-gonic/gin@v1.9.0": "deduplicated",
				"github.com/gin-gonic/gin@v1.8.5": "deduplicated",
			},
		},
		{
			name: "keep bump newer than go.mod version",
			deps: []string{
				"github.com/stretchr/testify@v1.9.0",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/stretchr/testify": "v1.8.4",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{"github.com/stretchr/testify@v1.9.0"},
		},
		{
			name: "remove bump matching go.mod version (no-op)",
			deps: []string{
				"github.com/sirupsen/logrus@v1.9.3",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/sirupsen/logrus": "v1.9.3",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantRemove: map[string]string{
				"github.com/sirupsen/logrus@v1.9.3": "remove-noop",
			},
			wantReasons: map[string]string{
				"github.com/sirupsen/logrus@v1.9.3": "matches effective version",
			},
		},
		{
			name: "remove bump older than go.mod version (downgrade)",
			deps: []string{
				"github.com/pkg/errors@v0.9.0",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/pkg/errors": "v0.9.1",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantRemove: map[string]string{
				"github.com/pkg/errors@v0.9.0": "remove-downgrade",
			},
			wantReasons: map[string]string{
				"github.com/pkg/errors@v0.9.0": "older than effective version",
			},
		},
		{
			name: "remove bump for module not in go.mod",
			deps: []string{
				"github.com/unknown/module@v1.0.0",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/known/module": "v1.0.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantRemove: map[string]string{
				"github.com/unknown/module@v1.0.0": "remove-missing",
			},
			wantReasons: map[string]string{
				"github.com/unknown/module@v1.0.0": "not found in go.mod",
			},
		},
		{
			name: "malformed bump without @ separator",
			deps: []string{
				"github.com/malformed/nodeps",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{},
				Replacements:    map[string]*modfile.Replace{},
			},
			wantKeep: []string{"github.com/malformed/nodeps"},
		},
		{
			name: "empty and whitespace deps ignored",
			deps: []string{
				"",
				"  ",
				"github.com/valid/module@v1.0.0",
				"\t",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/valid/module": "v0.9.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{"github.com/valid/module@v1.0.0"},
		},
		{
			name: "complex scenario - multiple modules, mixed outcomes",
			deps: []string{
				"github.com/gin-gonic/gin@v1.9.1",
				"github.com/gin-gonic/gin@v1.9.0",    // duplicate, older
				"github.com/stretchr/testify@v1.9.0", // keep (newer)
				"github.com/sirupsen/logrus@v1.9.3",  // remove (no-op)
				"github.com/pkg/errors@v0.9.0",       // remove (downgrade)
				"github.com/unknown/module@v1.0.0",   // remove (missing)
				"github.com/spf13/cobra@v1.8.0",      // keep (newer)
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/gin-gonic/gin":    "v1.8.0",
					"github.com/stretchr/testify": "v1.8.4",
					"github.com/sirupsen/logrus":  "v1.9.3",
					"github.com/pkg/errors":       "v0.9.1",
					"github.com/spf13/cobra":      "v1.7.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{
				"github.com/gin-gonic/gin@v1.9.1",
				"github.com/spf13/cobra@v1.8.0",
				"github.com/stretchr/testify@v1.9.0",
			},
			wantRemove: map[string]string{
				"github.com/sirupsen/logrus@v1.9.3": "remove-noop",
				"github.com/pkg/errors@v0.9.0":      "remove-downgrade",
				"github.com/unknown/module@v1.0.0":  "remove-missing",
			},
		},
		{
			name: "version comparison with v prefix on both",
			deps: []string{
				"github.com/test/module@v1.5.0",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/test/module": "v1.4.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{"github.com/test/module@v1.5.0"},
		},
		{
			name: "v2+ module path normalization - OSV returns path without /v2 suffix",
			deps: []string{
				"github.com/cli/go-gh@v2.11.1",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/cli/go-gh/v2": "v2.10.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{"github.com/cli/go-gh/v2@v2.11.1"},
		},
		{
			name: "v3 module path normalization - add /v3 suffix",
			deps: []string{
				"gopkg.in/yaml@v3.0.1",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"gopkg.in/yaml/v3": "v3.0.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{"gopkg.in/yaml/v3@v3.0.1"},
		},
		{
			name: "major version upgrade v1 to v2 - filtered as incompatible",
			deps: []string{
				"github.com/cli/go-gh@v2.11.1",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/cli/go-gh": "v1.2.1",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{},
			wantRemove: map[string]string{
				"github.com/cli/go-gh@v2.11.1": "remove-missing",
			},
			wantReasons: map[string]string{
				"github.com/cli/go-gh@v2.11.1": "not found",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzer()
			analysis, filteredDeps := a.analyzeBumps(t.Context(), tt.deps, tt.goModInfo)

			if len(filteredDeps) != len(tt.wantKeep) {
				t.Errorf("filteredDeps count = %d, want %d", len(filteredDeps), len(tt.wantKeep))
			}

			filteredMap := make(map[string]bool)
			for _, dep := range filteredDeps {
				filteredMap[dep] = true
			}

			for _, expectedDep := range tt.wantKeep {
				if !filteredMap[expectedDep] {
					t.Errorf("expected dep %q not found in filtered deps", expectedDep)
				}
			}

			analysisMap := make(map[string]bumpAnalysis)
			for _, a := range analysis {
				key := a.Module
				if a.BumpVersion != "" {
					key = a.Module + "@" + a.BumpVersion
				}
				analysisMap[key] = a
			}

			if tt.wantRemove != nil {
				for dep, expectedAction := range tt.wantRemove {
					if a, ok := analysisMap[dep]; ok {
						if a.Action != expectedAction {
							t.Errorf("dep %q action = %q, want %q", dep, a.Action, expectedAction)
						}
					}
				}
			}

			if tt.wantReasons != nil {
				for dep, expectedReasonSubstr := range tt.wantReasons {
					if a, ok := analysisMap[dep]; ok {
						if a.Reason == "" {
							t.Errorf("dep %q has empty reason, want substring %q", dep, expectedReasonSubstr)
						} else if !contains(a.Reason, expectedReasonSubstr) {
							t.Errorf("dep %q reason = %q, want to contain %q", dep, a.Reason, expectedReasonSubstr)
						}
					}
				}
			}

			for _, keptDep := range tt.wantKeep {
				if a, ok := analysisMap[keptDep]; ok {
					if a.Action != "keep" {
						t.Errorf("kept dep %q action = %q, want %q", keptDep, a.Action, "keep")
					}
				} else {
					t.Errorf("kept dep %q not found in analysis", keptDep)
				}
			}
		})
	}
}

func TestAnalyzer_GetEffectiveVersion(t *testing.T) {
	tests := []struct {
		name            string
		module          string
		originalVersion string
		replacements    map[string]*modfile.Replace
		expected        string
	}{
		{
			name:            "no replacement - return original",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements:    map[string]*modfile.Replace{},
			expected:        "v1.5.0",
		},
		{
			name:            "exact version replacement with version",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module@v1.5.0": {
					Old: module.Version{Path: "github.com/test/module", Version: "v1.5.0"},
					New: module.Version{Path: "github.com/other/module", Version: "v2.0.0"},
				},
			},
			expected: "v2.0.0",
		},
		{
			name:            "exact version replacement with local path",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module@v1.5.0": {
					Old: module.Version{Path: "github.com/test/module", Version: "v1.5.0"},
					New: module.Version{Path: "./local/module"},
				},
			},
			expected: "v999.999.999",
		},
		{
			name:            "module-level replacement with version",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module": {
					Old: module.Version{Path: "github.com/test/module"},
					New: module.Version{Path: "github.com/fork/module", Version: "v2.5.0"},
				},
			},
			expected: "v2.5.0",
		},
		{
			name:            "module-level replacement with local path",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module": {
					Old: module.Version{Path: "github.com/test/module"},
					New: module.Version{Path: "../local"},
				},
			},
			expected: "v999.999.999",
		},
		{
			name:            "exact replacement takes precedence over module replacement",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module@v1.5.0": {
					Old: module.Version{Path: "github.com/test/module", Version: "v1.5.0"},
					New: module.Version{Path: "github.com/exact/module", Version: "v3.0.0"},
				},
				"github.com/test/module": {
					Old: module.Version{Path: "github.com/test/module"},
					New: module.Version{Path: "github.com/module/module", Version: "v2.0.0"},
				},
			},
			expected: "v3.0.0",
		},
		{
			name:            "replacement with relative path",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module": {
					Old: module.Version{Path: "github.com/test/module"},
					New: module.Version{Path: "./vendor/module"},
				},
			},
			expected: "v999.999.999",
		},
		{
			name:            "replacement with absolute path",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module": {
					Old: module.Version{Path: "github.com/test/module"},
					New: module.Version{Path: "/abs/path/module"},
				},
			},
			expected: "v999.999.999",
		},
		{
			name:            "replacement with empty path (treated as local)",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module": {
					Old: module.Version{Path: "github.com/test/module"},
					New: module.Version{Path: ""},
				},
			},
			expected: "v999.999.999",
		},
		{
			name:            "replacement without version uses original",
			module:          "github.com/test/module",
			originalVersion: "v1.5.0",
			replacements: map[string]*modfile.Replace{
				"github.com/test/module": {
					Old: module.Version{Path: "github.com/test/module"},
					New: module.Version{Path: "github.com/other/module"},
				},
			},
			expected: "v1.5.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzer()
			result := a.getEffectiveVersion(t.Context(), tt.module, tt.originalVersion, tt.replacements)
			if result != tt.expected {
				t.Errorf("getEffectiveVersion() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestAnalyzer_AnalyzeBumps_SortingStability(t *testing.T) {
	deps := []string{
		"github.com/z-package/zoo@v1.0.0",      // indirect
		"github.com/a-package/alpha@v1.0.0",    // direct
		"github.com/m-package/middle@v1.0.0",   // indirect
		"github.com/new-package/newpkg@v1.0.0", // indirect (in AllRequirements but not Requirements)
	}
	goModInfo := &GoModInfo{
		Requirements: map[string]string{
			"github.com/a-package/alpha": "v0.9.0",
		},
		AllRequirements: map[string]string{
			"github.com/a-package/alpha":    "v0.9.0",
			"github.com/z-package/zoo":      "v0.9.0",
			"github.com/m-package/middle":   "v0.9.0",
			"github.com/new-package/newpkg": "v0.9.0",
		},
		Replacements: map[string]*modfile.Replace{},
	}

	a := newAnalyzer()
	_, filteredDeps := a.analyzeBumps(t.Context(), deps, goModInfo)

	expected := []string{
		"github.com/m-package/middle@v1.0.0",
		"github.com/new-package/newpkg@v1.0.0",
		"github.com/z-package/zoo@v1.0.0",
		"github.com/a-package/alpha@v1.0.0",
	}

	if len(filteredDeps) != len(expected) {
		t.Fatalf("got %d deps, want %d\nGot: %v\nWant: %v", len(filteredDeps), len(expected), filteredDeps, expected)
	}

	for i, dep := range filteredDeps {
		if dep != expected[i] {
			t.Errorf("filteredDeps[%d] = %q, want %q", i, dep, expected[i])
		}
	}
}

func TestAnalyzer_AnalyzeBumps_DependencyOrdering(t *testing.T) {
	tests := []struct {
		name        string
		deps        []string
		goModInfo   *GoModInfo
		wantOrdered []string
	}{
		{
			name: "indirect before direct",
			deps: []string{
				"github.com/direct/package@v1.5.0",
				"github.com/indirect/package@v1.2.0",
			},
			goModInfo: &GoModInfo{
				Requirements: map[string]string{
					"github.com/direct/package": "v1.0.0",
				},
				AllRequirements: map[string]string{
					"github.com/direct/package":   "v1.0.0",
					"github.com/indirect/package": "v1.0.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantOrdered: []string{
				"github.com/indirect/package@v1.2.0",
				"github.com/direct/package@v1.5.0",
			},
		},
		{
			name: "all indirect - alphabetical",
			deps: []string{
				"github.com/z/pkg@v1.0.0",
				"github.com/a/pkg@v1.0.0",
				"github.com/m/pkg@v1.0.0",
			},
			goModInfo: &GoModInfo{
				Requirements: map[string]string{},
				AllRequirements: map[string]string{
					"github.com/z/pkg": "v0.9.0",
					"github.com/a/pkg": "v0.9.0",
					"github.com/m/pkg": "v0.9.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantOrdered: []string{
				"github.com/a/pkg@v1.0.0",
				"github.com/m/pkg@v1.0.0",
				"github.com/z/pkg@v1.0.0",
			},
		},
		{
			name: "mixed types - correct grouping",
			deps: []string{
				"github.com/new/pkg@v1.0.0",
				"github.com/direct-z/pkg@v1.0.0",
				"github.com/indirect-a/pkg@v1.0.0",
				"github.com/direct-a/pkg@v1.0.0",
				"github.com/indirect-z/pkg@v1.0.0",
			},
			goModInfo: &GoModInfo{
				Requirements: map[string]string{
					"github.com/direct-z/pkg": "v0.9.0",
					"github.com/direct-a/pkg": "v0.9.0",
				},
				AllRequirements: map[string]string{
					"github.com/direct-z/pkg":   "v0.9.0",
					"github.com/direct-a/pkg":   "v0.9.0",
					"github.com/indirect-a/pkg": "v0.9.0",
					"github.com/indirect-z/pkg": "v0.9.0",
					"github.com/new/pkg":        "v0.9.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantOrdered: []string{
				"github.com/indirect-a/pkg@v1.0.0",
				"github.com/indirect-z/pkg@v1.0.0",
				"github.com/new/pkg@v1.0.0",
				"github.com/direct-a/pkg@v1.0.0",
				"github.com/direct-z/pkg@v1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzer()
			_, filteredDeps := a.analyzeBumps(t.Context(), tt.deps, tt.goModInfo)

			if len(filteredDeps) != len(tt.wantOrdered) {
				t.Fatalf("got %d deps, want %d\nGot: %v\nWant: %v", len(filteredDeps), len(tt.wantOrdered), filteredDeps, tt.wantOrdered)
			}

			for i, dep := range filteredDeps {
				if dep != tt.wantOrdered[i] {
					t.Errorf("filteredDeps[%d] = %q, want %q", i, dep, tt.wantOrdered[i])
				}
			}
		})
	}
}

func TestAnalyzer_AnalyzeBumps_PreReleaseVersions(t *testing.T) {
	tests := []struct {
		name      string
		deps      []string
		goModInfo *GoModInfo
		wantKeep  []string
	}{
		{
			name: "pre-release version v2 when current is v1 - filtered as major upgrade",
			deps: []string{
				"github.com/test/module@v2.0.0-rc.1",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/test/module": "v1.9.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{},
		},
		{
			name: "stable version newer than pre-release - same major version",
			deps: []string{
				"github.com/test/module@v2.0.0",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/test/module": "v2.0.0-beta",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{"github.com/test/module@v2.0.0"},
		},
		{
			name: "pre-release version within same major version",
			deps: []string{
				"github.com/test/module@v1.10.0-rc.1",
			},
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/test/module": "v1.9.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantKeep: []string{"github.com/test/module@v1.10.0-rc.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzer()
			_, filteredDeps := a.analyzeBumps(t.Context(), tt.deps, tt.goModInfo)

			if len(filteredDeps) != len(tt.wantKeep) {
				t.Fatalf("got %d deps, want %d", len(filteredDeps), len(tt.wantKeep))
			}

			for i, dep := range filteredDeps {
				if dep != tt.wantKeep[i] {
					t.Errorf("filteredDeps[%d] = %q, want %q", i, dep, tt.wantKeep[i])
				}
			}
		})
	}
}

func TestAnalyzer_NormalizeModulePath(t *testing.T) {
	tests := []struct {
		name           string
		module         string
		version        string
		goModInfo      *GoModInfo
		wantNormalized string
		wantFound      bool
	}{
		{
			name:    "v1 module - no suffix needed",
			module:  "github.com/stretchr/testify",
			version: "v1.9.0",
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/stretchr/testify": "v1.8.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantNormalized: "github.com/stretchr/testify",
			wantFound:      true,
		},
		{
			name:    "v2 module - needs /v2 suffix",
			module:  "github.com/cli/go-gh",
			version: "v2.11.1",
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/cli/go-gh/v2": "v2.10.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantNormalized: "github.com/cli/go-gh/v2",
			wantFound:      true,
		},
		{
			name:    "v3 module - needs /v3 suffix",
			module:  "gopkg.in/yaml",
			version: "v3.0.1",
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"gopkg.in/yaml/v3": "v3.0.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantNormalized: "gopkg.in/yaml/v3",
			wantFound:      true,
		},
		{
			name:    "v2 module already has suffix - use as-is",
			module:  "github.com/cli/go-gh/v2",
			version: "v2.11.1",
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/cli/go-gh/v2": "v2.10.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantNormalized: "github.com/cli/go-gh/v2",
			wantFound:      true,
		},
		{
			name:    "module not found even with correction",
			module:  "github.com/unknown/module",
			version: "v2.0.0",
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/other/module": "v1.0.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantNormalized: "github.com/unknown/module",
			wantFound:      false,
		},
		{
			name:    "v0 module - no suffix needed",
			module:  "github.com/example/v0module",
			version: "v0.5.0",
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/example/v0module": "v0.4.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantNormalized: "github.com/example/v0module",
			wantFound:      true,
		},
		{
			name:    "major version upgrade v1 to v2 - not compatible",
			module:  "github.com/cli/go-gh",
			version: "v2.11.1",
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/cli/go-gh": "v1.2.1",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantNormalized: "github.com/cli/go-gh",
			wantFound:      false,
		},
		{
			name:    "major version upgrade v2 to v3 - not compatible",
			module:  "github.com/example/module/v3",
			version: "v3.0.0",
			goModInfo: &GoModInfo{
				AllRequirements: map[string]string{
					"github.com/example/module/v2": "v2.5.0",
				},
				Replacements: map[string]*modfile.Replace{},
			},
			wantNormalized: "github.com/example/module/v3",
			wantFound:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnalyzer()
			gotNormalized, gotFound := a.normalizeModulePath(t.Context(), tt.module, tt.version, tt.goModInfo)

			if gotNormalized != tt.wantNormalized {
				t.Errorf("normalizeModulePath() normalized = %q, want %q", gotNormalized, tt.wantNormalized)
			}
			if gotFound != tt.wantFound {
				t.Errorf("normalizeModulePath() found = %v, want %v", gotFound, tt.wantFound)
			}
		})
	}
}

// TestAnalyzer_LogsCarryCtxAttribution is the acceptance test for threading
// ctx through analyzeBumps/normalizeModulePath/getEffectiveVersion: every
// slog.Debug record this package emits must reach the logger stashed on ctx
// (see internal/logging), so a per-file run can attribute its debug output.
func TestAnalyzer_LogsCarryCtxAttribution(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler).With("file", "example.yaml")
	ctx := logging.Into(t.Context(), logger)

	a := newAnalyzer()
	goModInfo := &GoModInfo{
		Requirements:    map[string]string{"example.com/mod": "v1.0.0"},
		AllRequirements: map[string]string{"example.com/mod": "v1.0.0"},
		Replacements:    map[string]*modfile.Replace{},
	}
	a.analyzeBumps(ctx, []string{"example.com/mod@v1.1.0"}, goModInfo)

	out := buf.String()
	if !strings.Contains(out, "file=example.yaml") {
		t.Fatalf("expected debug output to carry file=example.yaml, got:\n%s", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one debug record")
	}
	for _, line := range lines {
		if !strings.Contains(line, "file=example.yaml") {
			t.Errorf("record missing file attribution: %s", line)
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
