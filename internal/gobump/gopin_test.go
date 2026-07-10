package gobump

import (
	"strings"
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGoPackagePin(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantBase  string
		wantMinor string
		wantOK    bool
	}{
		{"bare go", "go", "go", "", true},
		{"go-1.24", "go-1.24", "go", "1.24", true},
		{"go-fips no minor", "go-fips", "go-fips", "", true},
		{"go-fips-1.24", "go-fips-1.24", "go-fips", "1.24", true},
		{"go-1.9", "go-1.9", "go", "1.9", true},
		{"go-1.10 distinct from go-1.9", "go-1.10", "go", "1.10", true},
		{"golang is not a toolchain pin", "golang", "", "", false},
		{"rust is not go", "rust", "", "", false},
		{"empty value", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, minor, ok := parseGoPackagePin(tt.value)
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				return
			}
			assert.Equal(t, tt.wantBase, base)
			assert.Equal(t, tt.wantMinor, minor)
		})
	}
}

func TestGoToolchainPins(t *testing.T) {
	t.Run("go/build pinned, go/install unpinned, subpackage go/build pinned differently, non-go steps ignored", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "git-checkout"},
				{Uses: "go/build", With: map[string]string{"go-package": "go-1.24"}},
				{Uses: "go/install"},
				{Uses: "cargo/build", With: map[string]string{"modroot": "."}},
			},
			Subpackages: []melange.Subpackage{
				{Name: "sub", Pipeline: []melange.Pipeline{
					{Uses: "go/build", With: map[string]string{"go-package": "go-fips-1.23"}},
				}},
			},
		}

		pins := goToolchainPins(cfg)
		require.Len(t, pins, 3)
		assert.Equal(t, GoToolchainPin{Package: "go-1.24", Minor: "1.24"}, pins[0])
		assert.Equal(t, GoToolchainPin{Package: "", Minor: ""}, pins[1])
		assert.Equal(t, GoToolchainPin{Package: "go-fips-1.23", Minor: "1.23"}, pins[2])
	})

	t.Run("templated go-package resolved via vars block", func(t *testing.T) {
		cfg := &melange.Configuration{
			Vars: map[string]string{"go-pkg": "go-1.24"},
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"go-package": "${{vars.go-pkg}}"}},
			},
		}

		pins := goToolchainPins(cfg)
		require.Len(t, pins, 1)
		assert.Equal(t, GoToolchainPin{Package: "go-1.24", Minor: "1.24"}, pins[0])
	})

	t.Run("unresolvable template keeps raw value and is treated as unpinned", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"go-package": "${{vars.missing}}"}},
			},
		}

		pins := goToolchainPins(cfg)
		require.Len(t, pins, 1)
		assert.Equal(t, "${{vars.missing}}", pins[0].Package)
		assert.Equal(t, "", pins[0].Minor)
	})

	t.Run("no matching steps returns empty", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "git-checkout"}, {Uses: "cargo/build"}},
		}
		assert.Empty(t, goToolchainPins(cfg))
	})
}

func TestDistinctMinorConstraints(t *testing.T) {
	t.Run("empty input returns unpinned only", func(t *testing.T) {
		assert.Equal(t, []string{""}, distinctMinorConstraints(nil))
	})

	t.Run("mixed pins incl. duplicates and unpinned, numeric ordering", func(t *testing.T) {
		pins := []GoToolchainPin{
			{Minor: "1.24"},
			{Minor: "1.9"},
			{Minor: ""},
			{Minor: "1.10"},
			{Minor: "1.24"},
			{Minor: "1.9"},
		}
		assert.Equal(t, []string{"", "1.9", "1.10", "1.24"}, distinctMinorConstraints(pins))
	})

	t.Run("all pinned, no unpinned entries", func(t *testing.T) {
		pins := []GoToolchainPin{{Minor: "1.25"}, {Minor: "1.24"}}
		assert.Equal(t, []string{"1.24", "1.25"}, distinctMinorConstraints(pins))
	})
}

func TestGoPinFloor(t *testing.T) {
	deps124, err := ecogolang.New().Analyze(t.Context(), map[string][]byte{"go.mod": []byte("module m\n\ngo 1.24\n")})
	require.NoError(t, err)

	t.Run("max of baselines and required raises across go modroots", func(t *testing.T) {
		analysis := &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{
			{Language: "go", ByModroot: []ModrootAnalysis{
				{Modroot: ".", Deps: deps124},                            // baseline 1.24, no raise
				{Modroot: "cmd/a", RequiredGoVersion: "1.26"},            // raise, no parsed manifest
				{Modroot: "cmd/b", Deps: deps124, RequiredGoVersion: ""}, // baseline only
			}},
			{Language: "rust", ByModroot: []ModrootAnalysis{{Modroot: "."}}}, // ignored
		}}
		assert.Equal(t, "1.26", goPinFloor(analysis))
	})

	t.Run("baseline alone sets the floor", func(t *testing.T) {
		analysis := &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{
			{Language: "go", ByModroot: []ModrootAnalysis{{Modroot: ".", Deps: deps124}}},
		}}
		assert.Equal(t, "1.24", goPinFloor(analysis))
	})

	t.Run("no go information at all", func(t *testing.T) {
		analysis := &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{
			{Language: "go", ByModroot: []ModrootAnalysis{{Modroot: "."}}},
		}}
		assert.Equal(t, "", goPinFloor(analysis))
	})
}

// goPinFixtureYAML carries every pin shape reconcileGoPackagePins must
// handle, with comments in rewrite range to prove preservation.
const goPinFixtureYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

vars:
  go-pkg: go-1.22

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  # main build step
  - uses: go/build
    with:
      go-package: go-1.22
      packages: ./cmd/app

  - uses: go/install
    with:
      go-package: go # unversioned - floats to latest

subpackages:
  - name: sub-fips
    pipeline:
      - uses: go/build
        with:
          # FIPS-validated toolchain
          go-package: go-fips-1.23
  - name: sub-templated
    pipeline:
      - uses: go/build
        with:
          go-package: ${{vars.go-pkg}}
  - name: sub-weird
    pipeline:
      - uses: go/build
        with:
          go-package: golang
  - name: sub-current
    pipeline:
      - uses: go/build
        with:
          go-package: go-1.30
`

func goPinTestProcessor(t *testing.T) *GoBumpProcessor {
	t.Helper()
	gp := NewGoBumpProcessor("/test/example.yaml", "example", "1.0.0", 0)
	gp.OriginalYAML = []byte(goPinFixtureYAML)
	gp.SetCurrentYAML([]byte(goPinFixtureYAML))
	gp.Config = &melange.Configuration{Vars: map[string]string{"go-pkg": "go-1.22"}}
	return gp
}

func TestReconcileGoPackagePins(t *testing.T) {
	t.Run("raises too-old pins, preserving comments; warns on templated and unrecognized; leaves the rest", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(gp, "1.25.3"))

		content := string(gp.GetCurrentYAML())

		// Too-old versioned pins raised to the floor's minor.
		assert.Contains(t, content, "go-package: go-1.25\n")
		assert.NotContains(t, content, "go-package: go-1.22")
		assert.Contains(t, content, "go-package: go-fips-1.25")
		assert.NotContains(t, content, "go-fips-1.23")

		// Comments (head and inline) preserved around the rewrites.
		assert.Contains(t, content, "# main build step")
		assert.Contains(t, content, "# FIPS-validated toolchain")
		assert.Contains(t, content, "# unversioned - floats to latest")

		// Unversioned, templated, unrecognized, and already-sufficient pins untouched.
		assert.Contains(t, content, "go-package: go #")
		assert.Contains(t, content, "go-package: ${{vars.go-pkg}}")
		assert.Contains(t, content, "go-package: golang")
		assert.Contains(t, content, "go-package: go-1.30")

		assert.True(t, gp.ActualChangesApplied)

		messages := strings.Join(gp.GetMessages(), "\n")
		assert.Contains(t, messages, "raised go-package pin go-1.22 -> go-1.25")
		assert.Contains(t, messages, "raised go-package pin go-fips-1.23 -> go-fips-1.25 (subpackage sub-fips")
		assert.Contains(t, messages, "update the variable manually")
		assert.Contains(t, messages, `unrecognized go-package "golang"`)

		// The file still parses and the pins reflect the rewrite.
		pins, err := newMelangeLoader().FindGoPackagePins(gp.GetCurrentYAML())
		require.NoError(t, err)
		values := make([]string, 0, len(pins))
		for _, pin := range pins {
			values = append(values, pin.Value)
		}
		assert.ElementsMatch(t, []string{"go-1.25", "go", "go-fips-1.25", "${{vars.go-pkg}}", "golang", "go-1.30"}, values)

		// Every versioned raw pin's outcome is recorded (raised or identity)
		// for the stdlib check's rebuild side; templated, unversioned, and
		// unrecognized pins record nothing.
		assert.Equal(t, map[string]string{
			"1.22": "1.25", // raised
			"1.23": "1.25", // raised (go-fips)
			"1.30": "1.30", // already sufficient - identity
		}, gp.RaisedPinMinors)
	})

	t.Run("templated pin resolving at or above the floor stays silent", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		gp.Config.Vars["go-pkg"] = "go-1.30"
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(gp, "1.25"))

		for _, msg := range gp.GetMessages() {
			assert.NotContains(t, msg, "update the variable manually")
		}
	})

	t.Run("nil gp.Config degrades templated pin to a warning, not a silent skip", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		gp.Config = nil // no renderer can be built - the templated value can't be evaluated
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(gp, "1.25.3"))

		content := string(gp.GetCurrentYAML())
		// The templated pin is never rewritten.
		assert.Contains(t, content, "go-package: ${{vars.go-pkg}}")

		messages := strings.Join(gp.GetMessages(), "\n")
		assert.Contains(t, messages, `go-package "${{vars.go-pkg}}"`)
		assert.Contains(t, messages, "could not be evaluated")
		assert.Contains(t, messages, "verify manually against required Go 1.25.3")
	})

	t.Run("empty pinFloor is a no-op", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(gp, ""))

		assert.Equal(t, goPinFixtureYAML, string(gp.GetCurrentYAML()))
		assert.False(t, gp.ActualChangesApplied)
		assert.Empty(t, gp.GetMessages())
		assert.Nil(t, gp.RaisedPinMinors, "a no-op reconciliation must record nothing")
	})

	t.Run("all pins sufficient - no rewrite, no change flag, identity outcomes recorded", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(gp, "1.20"))

		assert.Equal(t, goPinFixtureYAML, string(gp.GetCurrentYAML()))
		assert.False(t, gp.ActualChangesApplied)
		assert.Equal(t, map[string]string{
			"1.22": "1.22",
			"1.23": "1.23",
			"1.30": "1.30",
		}, gp.RaisedPinMinors)
	})

	t.Run("templated pin below the floor records nothing", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		gp.Config.Vars["go-pkg"] = "go-1.21" // templated pin renders below the floor
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(gp, "1.25"))

		_, templatedRecorded := gp.RaisedPinMinors["1.21"]
		assert.False(t, templatedRecorded, "templated pins are never edited, so they must not record an outcome")
	})

	t.Run("double run is byte-stable", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(gp, "1.25"))
		firstPass := string(gp.GetCurrentYAML())
		require.NoError(t, applier.reconcileGoPackagePins(gp, "1.25"))
		assert.Equal(t, firstPass, string(gp.GetCurrentYAML()))
	})
}

func TestRebuildConstraintsFor(t *testing.T) {
	t.Run("nil recordings map to nil", func(t *testing.T) {
		assert.Nil(t, rebuildConstraintsFor([]string{"", "1.21"}, nil))
	})

	t.Run("identity-only recordings map to nil", func(t *testing.T) {
		assert.Nil(t, rebuildConstraintsFor([]string{"1.21"}, map[string]string{"1.21": "1.21"}))
	})

	t.Run("raises apply; unpinned and unrecorded constraints stay put", func(t *testing.T) {
		raised := map[string]string{"1.21": "1.25", "1.24": "1.24"}
		got := rebuildConstraintsFor([]string{"", "1.21", "1.23", "1.24"}, raised)
		assert.Equal(t, map[string]string{"1.21": "1.25"}, got)
	})

	t.Run("recordings for minors absent from the constraints are ignored", func(t *testing.T) {
		assert.Nil(t, rebuildConstraintsFor([]string{""}, map[string]string{"1.21": "1.25"}))
	})
}
