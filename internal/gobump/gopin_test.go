package gobump

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestGoPinFloors(t *testing.T) {
	deps124, err := ecogolang.New().Analyze(t.Context(), map[string][]byte{"go.mod": []byte("module m\n\ngo 1.24\n")})
	require.NoError(t, err)

	t.Run("per-modroot floors keyed by modroot: baseline and required raise", func(t *testing.T) {
		analysis := &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{
			{Language: "go", ByModroot: []ModrootAnalysis{
				{Modroot: ".", Deps: deps124},                            // baseline 1.24, no raise
				{Modroot: "cmd/a", RequiredGoVersion: "1.26"},            // raise, no parsed manifest
				{Modroot: "cmd/b", Deps: deps124, RequiredGoVersion: ""}, // baseline only
			}},
			{Language: "rust", ByModroot: []ModrootAnalysis{{Modroot: "."}}}, // ignored
		}}
		assert.Equal(t, map[string]string{
			".":     "1.24",
			"cmd/a": "1.26",
			"cmd/b": "1.24",
		}, goPinFloors(analysis))
	})

	t.Run("modroot with no baseline or required maps to empty (no requirement)", func(t *testing.T) {
		analysis := &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{
			{Language: "go", ByModroot: []ModrootAnalysis{{Modroot: "."}}},
		}}
		assert.Equal(t, map[string]string{".": ""}, goPinFloors(analysis))
	})

	t.Run("no go languages yields an empty map", func(t *testing.T) {
		analysis := &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{
			{Language: "rust", ByModroot: []ModrootAnalysis{{Modroot: "."}}},
		}}
		assert.Empty(t, goPinFloors(analysis))
	})
}

// goPinFixtureYAML carries every non-modroot pin shape reconcileGoPackagePins
// must handle, with comments in rewrite range to prove preservation. All pins
// build the default modroot ".", so a single-key floors map exercises them.
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

// dotFloor is the single-modroot floors map most fixture pins (all at ".") use.
func dotFloor(v string) map[string]string { return map[string]string{".": v} }

func TestReconcileGoPackagePins(t *testing.T) {
	ctx := context.Background()

	t.Run("raises too-old base-go pins, preserving comments; warns on variant, templated and unrecognized; leaves the rest", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.25.3")))

		content := string(gp.GetCurrentYAML())

		// Too-old base-"go" versioned pin raised to the floor's minor.
		assert.Contains(t, content, "go-package: go-1.25\n")
		assert.NotContains(t, content, "go-package: go-1.22")

		// Variant toolchain (go-fips) is NEVER auto-rewritten - it is warned about.
		assert.Contains(t, content, "go-package: go-fips-1.23")
		assert.NotContains(t, content, "go-fips-1.25")

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
		assert.Contains(t, messages, "modroot .")
		// Variant guard: warn, name the toolchain, do not rewrite.
		assert.Contains(t, messages, "go-package pin go-fips-1.23 (subpackage sub-fips, modroot .)")
		assert.Contains(t, messages, "variant toolchain")
		assert.Contains(t, messages, "raise it manually")
		assert.Contains(t, messages, "update the variable manually")
		assert.Contains(t, messages, `unrecognized go-package "golang"`)

		// The file still parses and the pins reflect the rewrite.
		pins, err := newMelangeLoader().FindGoPackagePins(gp.GetCurrentYAML())
		require.NoError(t, err)
		values := make([]string, 0, len(pins))
		for _, pin := range pins {
			values = append(values, pin.Value)
		}
		assert.ElementsMatch(t, []string{"go-1.25", "go", "go-fips-1.23", "${{vars.go-pkg}}", "golang", "go-1.30"}, values)

		// Versioned raw pins record an outcome (raised or identity) for the
		// stdlib rebuild side; the warned-not-rewritten go-fips pin records its
		// UNCHANGED minor (it will still build with 1.23). Templated,
		// unversioned, and unrecognized pins record nothing.
		assert.Equal(t, map[string]string{
			"1.22": "1.25", // raised (base go)
			"1.23": "1.23", // go-fips warned, not rewritten - still 1.23
			"1.30": "1.30", // already sufficient - identity
		}, gp.RaisedPinMinors)
	})

	t.Run("templated pin resolving at or above the floor stays silent", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		gp.Config.Vars["go-pkg"] = "go-1.30"
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.25")))

		for _, msg := range gp.GetMessages() {
			assert.NotContains(t, msg, "update the variable manually")
		}
	})

	t.Run("nil gp.Config degrades templated pin to a warning, not a silent skip", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		gp.Config = nil // no renderer can be built - the templated value can't be evaluated
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.25.3")))

		content := string(gp.GetCurrentYAML())
		// The templated pin is never rewritten.
		assert.Contains(t, content, "go-package: ${{vars.go-pkg}}")

		messages := strings.Join(gp.GetMessages(), "\n")
		assert.Contains(t, messages, `go-package "${{vars.go-pkg}}"`)
		assert.Contains(t, messages, "could not be evaluated")
		assert.Contains(t, messages, "verify manually against required Go 1.25.3")
	})

	t.Run("empty floors is a no-op", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, nil))

		assert.Equal(t, goPinFixtureYAML, string(gp.GetCurrentYAML()))
		assert.False(t, gp.ActualChangesApplied)
		assert.Empty(t, gp.GetMessages())
		assert.Nil(t, gp.RaisedPinMinors, "a no-op reconciliation must record nothing")
	})

	t.Run("all pins sufficient - no rewrite, no change flag, identity outcomes recorded", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		applier := NewGoBumpApplier(nil)

		// Floor below every versioned pin's minor: nothing to raise or warn.
		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.20")))

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

		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.25")))

		_, templatedRecorded := gp.RaisedPinMinors["1.21"]
		assert.False(t, templatedRecorded, "templated pins are never edited, so they must not record an outcome")
	})

	t.Run("double run is byte-stable", func(t *testing.T) {
		gp := goPinTestProcessor(t)
		applier := NewGoBumpApplier(nil)

		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.25")))
		firstPass := string(gp.GetCurrentYAML())
		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.25")))
		assert.Equal(t, firstPass, string(gp.GetCurrentYAML()))
	})
}

// goPinModrootFixtureYAML exercises the per-modroot association: distinct
// modroots (one templated), a go/install with no modroot, and a subpackage
// building an unrelated modroot.
const goPinModrootFixtureYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

vars:
  app-root: ./cmd/app

pipeline:
  - uses: go/build
    with:
      go-package: go-1.22
      modroot: ./cmd/app
  - uses: go/install
    with:
      go-package: go-1.19
  - uses: go/build
    with:
      go-package: go-1.22
      modroot: ${{vars.app-root}}

subpackages:
  - name: sub-other
    pipeline:
      - uses: go/build
        with:
          # deliberately held back for a lower-requirement modroot
          go-package: go-1.22
          modroot: ./cmd/other
`

func goPinModrootProcessor(t *testing.T) *GoBumpProcessor {
	t.Helper()
	gp := NewGoBumpProcessor("/test/example.yaml", "example", "1.0.0", 0)
	gp.OriginalYAML = []byte(goPinModrootFixtureYAML)
	gp.SetCurrentYAML([]byte(goPinModrootFixtureYAML))
	gp.Config = &melange.Configuration{Vars: map[string]string{"app-root": "./cmd/app"}}
	return gp
}

func TestReconcileGoPackagePins_PerModroot(t *testing.T) {
	ctx := context.Background()

	t.Run("only pins whose own modroot has a floor are raised; other modroots untouched", func(t *testing.T) {
		gp := goPinModrootProcessor(t)
		applier := NewGoBumpApplier(nil)

		// ./cmd/app demands 1.25.3; ./cmd/other is present but demands nothing.
		floors := map[string]string{"./cmd/app": "1.25.3", "./cmd/other": ""}
		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, floors))

		content := string(gp.GetCurrentYAML())

		// Three pins land on go-1.25: the literal ./cmd/app pin, the
		// templated-modroot pin (renders to ./cmd/app), and the go/install pin
		// (no modroot - raised by the file-wide max floor).
		assert.Equal(t, 3, strings.Count(content, "go-package: go-1.25\n"))
		assert.NotContains(t, content, "go-package: go-1.19", "go/install raised off the max floor")
		// The sub-other pin building ./cmd/other is left exactly as written -
		// the core FIPS/variant fix: a raise proven for ./cmd/app must not
		// rewrite a pin for a different, lower-requirement modroot.
		assert.Contains(t, content, "modroot: ./cmd/other")
		assert.Contains(t, content, "go-package: go-1.22\n          modroot: ./cmd/other")
		assert.Contains(t, content, "# deliberately held back for a lower-requirement modroot")

		// Divergent min-semantics: minor 1.22 is raised for ./cmd/app but held
		// at 1.22 for ./cmd/other, so the recorded effective is the older 1.22.
		assert.Equal(t, "1.22", gp.RaisedPinMinors["1.22"],
			"sub-other still builds ./cmd/other with 1.22, so the shared minor records the older toolchain")
		assert.Equal(t, "1.25", gp.RaisedPinMinors["1.19"], "go/install raised by the max floor")
	})

	t.Run("pin whose modroot is absent from analysis is left untouched", func(t *testing.T) {
		gp := goPinModrootProcessor(t)
		applier := NewGoBumpApplier(nil)

		// ./cmd/other is not present in floors at all (unanalyzed).
		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, map[string]string{"./cmd/app": "1.25.3"}))

		content := string(gp.GetCurrentYAML())
		assert.Contains(t, content, "go-package: go-1.22\n          modroot: ./cmd/other",
			"a modroot the analysis never covered gets no floor and no raise")
	})
}

// goPinFipsFixtureYAML isolates a single variant-toolchain pin that would need
// a raise, to prove the file is left byte-identical.
const goPinFipsFixtureYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: go/build
    with:
      # FIPS-validated toolchain - held back deliberately
      go-package: go-fips-1.23
      modroot: .
`

func TestReconcileGoPackagePins_VariantByteIdentical(t *testing.T) {
	gp := NewGoBumpProcessor("/test/example.yaml", "example", "1.0.0", 0)
	gp.OriginalYAML = []byte(goPinFipsFixtureYAML)
	gp.SetCurrentYAML([]byte(goPinFipsFixtureYAML))
	gp.Config = &melange.Configuration{}
	applier := NewGoBumpApplier(nil)

	require.NoError(t, applier.reconcileGoPackagePins(context.Background(), gp, map[string]string{".": "1.25.3"}))

	// A variant toolchain in need of a raise must leave the file byte-identical.
	assert.Equal(t, goPinFipsFixtureYAML, string(gp.GetCurrentYAML()))
	assert.False(t, gp.ActualChangesApplied)

	messages := strings.Join(gp.GetMessages(), "\n")
	assert.Contains(t, messages, "variant toolchain")
	assert.Contains(t, messages, "raise it manually")
	// It still records its unchanged minor for the stdlib rebuild side.
	assert.Equal(t, map[string]string{"1.23": "1.23"}, gp.RaisedPinMinors)
}

func TestRecordPinOutcome_MinPerOriginalMinor(t *testing.T) {
	t.Run("records the minimum effective when pins sharing an original minor diverge", func(t *testing.T) {
		gp := &GoBumpProcessor{}
		recordPinOutcome(gp, "1.22", "1.25") // one pin raised
		recordPinOutcome(gp, "1.22", "1.22") // another held back at its own minor
		assert.Equal(t, "1.22", gp.RaisedPinMinors["1.22"],
			"the older effective wins so the stdlib rebuild side assumes the oldest toolchain in use")
	})

	t.Run("order-independent: smaller recorded first still keeps the smaller", func(t *testing.T) {
		gp := &GoBumpProcessor{}
		recordPinOutcome(gp, "1.22", "1.22")
		recordPinOutcome(gp, "1.22", "1.25")
		assert.Equal(t, "1.22", gp.RaisedPinMinors["1.22"])
	})

	t.Run("distinct original minors are recorded independently", func(t *testing.T) {
		gp := &GoBumpProcessor{}
		recordPinOutcome(gp, "1.22", "1.25")
		recordPinOutcome(gp, "1.30", "1.30")
		assert.Equal(t, map[string]string{"1.22": "1.25", "1.30": "1.30"}, gp.RaisedPinMinors)
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

	t.Run("a minor held back by the min-semantics maps to itself (omitted)", func(t *testing.T) {
		// recordPinOutcome collapsed a divergent 1.22 to identity, so the
		// rebuild side sees no raise for it - a 1.22 build still happens.
		assert.Nil(t, rebuildConstraintsFor([]string{"1.22"}, map[string]string{"1.22": "1.22"}))
	})
}

// TestReconcileGoPackagePins_FloorValidation covers the defense-in-depth
// floor validation at the pin write site (B2): a floor that isn't a known Go
// release must never be written into a pin, even though fallbackGoVersions
// already validates its own RequiredGoVersion input - this also catches a
// bogus pristineGoBaseline, which is never filtered.
func TestReconcileGoPackagePins_FloorValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown floor leaves every pin untouched, warns per pin", func(t *testing.T) {
		releaseServer := releaseFixtureServer(t, "1.25.3") // no 1.99 series ever shipped
		t.Setenv("GOPROXY", releaseServer.URL)
		analyzer := NewAnalyzer(releaseServer.Client())
		applier := NewGoBumpApplier(analyzer)

		gp := goPinTestProcessor(t)
		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.99")))

		assert.Equal(t, goPinFixtureYAML, string(gp.GetCurrentYAML()),
			"an unknown Go release must never be written as a pin floor")
		assert.False(t, gp.ActualChangesApplied)

		messages := strings.Join(gp.GetMessages(), "\n")
		assert.Contains(t, messages, "not a known Go release")
		assert.Contains(t, messages, "check the dependency's go.mod")
	})

	t.Run("known floor still raises when a release index is wired", func(t *testing.T) {
		releaseServer := releaseFixtureServer(t, "1.25.3")
		t.Setenv("GOPROXY", releaseServer.URL)
		analyzer := NewAnalyzer(releaseServer.Client())
		applier := NewGoBumpApplier(analyzer)

		gp := goPinTestProcessor(t)
		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.25.3")))

		content := string(gp.GetCurrentYAML())
		assert.Contains(t, content, "go-package: go-1.25\n")
		assert.True(t, gp.ActualChangesApplied)
	})

	t.Run("release index offline fails open: raise proceeds with a warning", func(t *testing.T) {
		failingIndex := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		t.Cleanup(failingIndex.Close)
		t.Setenv("GOPROXY", failingIndex.URL)
		analyzer := NewAnalyzer(failingIndex.Client())
		applier := NewGoBumpApplier(analyzer)

		gp := goPinTestProcessor(t)
		require.NoError(t, applier.reconcileGoPackagePins(ctx, gp, dotFloor("1.25.3")))

		content := string(gp.GetCurrentYAML())
		assert.Contains(t, content, "go-package: go-1.25\n", "an unreachable index must fail open")
		assert.True(t, gp.ActualChangesApplied)

		messages := strings.Join(gp.GetMessages(), "\n")
		assert.Contains(t, messages, "index unavailable")
	})
}
