package gobump

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/isometry/choam/internal/config"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/simulate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseSpec parses a melange spec the way the bump command does
// (melange.ParseConfiguration on a file).
func parseSpec(t *testing.T, spec string) *melange.Configuration {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.yaml")
	require.NoError(t, os.WriteFile(path, []byte(spec), 0o644))
	cfg, err := melange.ParseConfiguration(t.Context(), path)
	require.NoError(t, err)
	return cfg
}

// goUnits discovers cfg's go units (no bump steps) and the notes.
func goUnits(t *testing.T, cfg *melange.Configuration) ([]analysisUnit, []string) {
	t.Helper()
	units, notes := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
	return units["go"], notes
}

func TestDiscoverGoInstall(t *testing.T) {
	t.Run("without version: a unit like go/build", func(t *testing.T) {
		cfg := &melange.Configuration{Pipeline: []melange.Pipeline{{
			Uses: "go/install",
			With: map[string]string{"package": "./cmd/tool", "tags": "extra", "go-package": "go-1.25"},
		}}}
		units, notes := goUnits(t, cfg)
		require.Len(t, units, 1)
		assert.Equal(t, ".", units[0].Modroot)
		assert.Equal(t, []string{"./cmd/tool"}, units[0].Packages)
		assert.Equal(t, []string{"extra", "netgo", "osusergo"}, units[0].Tags)
		assert.Equal(t, "1.25", units[0].GoMinor)
		assert.Equal(t, []string{"amd64", "arm64"}, units[0].Arches)
		assert.Empty(t, notes)
	})

	t.Run("working-directory is the modroot", func(t *testing.T) {
		for workDir, want := range map[string]string{"sub/mod": "sub/mod", "/home/build/sub": "sub", "/home/build": "."} {
			cfg := &melange.Configuration{Pipeline: []melange.Pipeline{{
				Uses: "go/install", WorkDir: workDir, With: map[string]string{"package": "./cmd/tool"},
			}}}
			units, _ := goUnits(t, cfg)
			require.Len(t, units, 1, workDir)
			assert.Equal(t, want, units[0].Modroot, workDir)
		}
		cfg := &melange.Configuration{Pipeline: []melange.Pipeline{{
			Uses: "go/install", WorkDir: "/opt/elsewhere", With: map[string]string{"package": "./cmd/tool"},
		}}}
		units, notes := goUnits(t, cfg)
		assert.Empty(t, units)
		assert.Equal(t, []string{`go/install ./cmd/tool: working-directory "/opt/elsewhere" is outside the build workspace - not analyzed`}, notes)
	})

	t.Run("with version: not affected by bumps, no unit", func(t *testing.T) {
		cfg := &melange.Configuration{Pipeline: []melange.Pipeline{
			{Uses: "go/install", With: map[string]string{"package": "golang.org/x/tools/cmd/stringer", "version": "v0.30.0"}},
			{Uses: "go/build", With: map[string]string{"packages": "./cmd/app"}},
		}}
		units, notes := goUnits(t, cfg)
		require.Len(t, units, 1)
		assert.Equal(t, []string{"./cmd/app"}, units[0].Packages, "only the go/build unit")
		assert.Equal(t, []string{"go/install golang.org/x/tools/cmd/stringer@v0.30.0 is not affected by bumps (go install pkg@version ignores the checkout's go.mod)"}, notes)
		assert.Equal(t, []string{"golang.org/x/tools/cmd/stringer@v0.30.0"}, scanBuildSteps(t.Context(), cfg).versionedInstalls)
	})

	t.Run("missing package input: ignored", func(t *testing.T) {
		units, _ := goUnits(t, &melange.Configuration{Pipeline: []melange.Pipeline{{Uses: "go/install"}}})
		assert.Empty(t, units)
	})
}

func TestDiscoverBuildEnv(t *testing.T) {
	goBuild := func(with map[string]string, env map[string]string) melange.Pipeline {
		return melange.Pipeline{Uses: "go/build", With: with, Environment: env}
	}
	withEnv := func(env map[string]string, steps ...melange.Pipeline) *melange.Configuration {
		cfg := &melange.Configuration{Pipeline: steps}
		cfg.Environment.Environment = env
		return cfg
	}
	for _, tt := range []struct {
		name  string
		cfg   *melange.Configuration
		env   simulate.BuildEnv
		tags  []string
		notes []string
	}{
		{name: "absent: melange default", cfg: withEnv(nil, goBuild(nil, nil)), tags: []string{"netgo", "osusergo"}},
		{name: "CGO_ENABLED=0", cfg: withEnv(map[string]string{"CGO_ENABLED": "0"}, goBuild(nil, nil)),
			env: simulate.BuildEnv{CGO: "0"}, tags: []string{"netgo", "osusergo"}},
		{name: "CGO_ENABLED=1", cfg: withEnv(map[string]string{"CGO_ENABLED": " 1 "}, goBuild(nil, nil)),
			env: simulate.BuildEnv{CGO: "1"}, tags: []string{"netgo", "osusergo"}},
		{name: "step environment wins over the package's", cfg: withEnv(map[string]string{"CGO_ENABLED": "0"}, goBuild(nil, map[string]string{"CGO_ENABLED": "1"})),
			env: simulate.BuildEnv{CGO: "1"}, tags: []string{"netgo", "osusergo"}},
		{name: "templated CGO_ENABLED renders", cfg: func() *melange.Configuration {
			cfg := withEnv(map[string]string{"CGO_ENABLED": "${{vars.cgo}}"}, goBuild(nil, nil))
			cfg.Vars = map[string]string{"cgo": "0"}
			return cfg
		}(), env: simulate.BuildEnv{CGO: "0"}, tags: []string{"netgo", "osusergo"}},
		{name: "unrenderable CGO_ENABLED: unknown", cfg: withEnv(map[string]string{"CGO_ENABLED": "${{vars.missing}}"}, goBuild(nil, nil)),
			tags:  []string{"netgo", "osusergo"},
			notes: []string{`go/build (modroot .): CGO_ENABLED "${{vars.missing}}" not understood - linkage evaluated with cgo enabled (melange's default)`}},
		{name: "non-literal CGO_ENABLED: unknown", cfg: withEnv(map[string]string{"CGO_ENABLED": "yes"}, goBuild(nil, nil)),
			tags:  []string{"netgo", "osusergo"},
			notes: []string{`go/build (modroot .): CGO_ENABLED "yes" not understood - linkage evaluated with cgo enabled (melange's default)`}},
		{name: "go/build experiments input is GOEXPERIMENT", cfg: withEnv(nil, goBuild(map[string]string{"experiments": "nojsonv2"}, nil)),
			env: simulate.BuildEnv{GOExperiment: "nojsonv2"}, tags: []string{"netgo", "osusergo"}},
		{name: "environment GOEXPERIMENT is overridden by go/build", cfg: withEnv(map[string]string{"GOEXPERIMENT": "boringcrypto"}, goBuild(nil, nil)),
			tags:  []string{"netgo", "osusergo"},
			notes: []string{"go/build (modroot .): environment GOEXPERIMENT=boringcrypto is overridden by the pipeline's experiments input"}},
		{name: "GOFLAGS: -tags overridden by go/build, other flags not mirrored",
			cfg:  withEnv(map[string]string{"GOFLAGS": "-tags=foo,bar -buildvcs=false -trimpath"}, goBuild(nil, nil)),
			tags: []string{"netgo", "osusergo"},
			notes: []string{
				"go/build (modroot .): GOFLAGS -tags=foo,bar is overridden by the pipeline's own -tags - not applied",
				"go/build (modroot .): linkage not evaluated with GOFLAGS -buildvcs=false -trimpath (not mirrored)",
			}},
		{name: "steps sharing a modroot disagree on CGO", cfg: withEnv(nil,
			goBuild(map[string]string{"packages": "./a"}, map[string]string{"CGO_ENABLED": "0"}),
			goBuild(map[string]string{"packages": "./b", "experiments": "b,a"}, map[string]string{"CGO_ENABLED": "1"})),
			env: simulate.BuildEnv{GOExperiment: "a,b"}, tags: []string{"netgo", "osusergo"},
			notes: []string{"modroot .: build steps disagree on CGO_ENABLED - linkage evaluated with cgo enabled"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			units, notes := goUnits(t, tt.cfg)
			require.Len(t, units, 1)
			assert.Equal(t, tt.env, units[0].Env)
			assert.Equal(t, tt.tags, units[0].Tags)
			assert.Equal(t, tt.notes, notes)
		})
	}

	t.Run("no build step: package environment, GOFLAGS -tags merged", func(t *testing.T) {
		cfg := withEnv(map[string]string{"CGO_ENABLED": "0", "GOEXPERIMENT": "boringcrypto", "GOFLAGS": "-tags=foo -mod=vendor"})
		cfg.Package.Annotations = map[string]string{"choam/bump-go": "."}
		units, notes := goUnits(t, cfg)
		require.Len(t, units, 1)
		assert.Equal(t, simulate.BuildEnv{CGO: "0", GOExperiment: "boringcrypto"}, units[0].Env)
		assert.Equal(t, []string{"foo"}, units[0].Tags)
		assert.Equal(t, []string{"environment: linkage not evaluated with GOFLAGS -mod=vendor (not mirrored)"}, notes)
	})

	t.Run("specs parsed by melange", func(t *testing.T) {
		// The shapes of the real apks specs: terraform-1.14 and kgateway
		// quote "0", opentofu-1.12 writes a bare 0.
		for name, value := range map[string]string{`"0"`: "0", "0": "0", `"1"`: "1"} {
			cfg := parseSpec(t, `package:
  name: example
  version: 1.0.0
  epoch: 0
environment:
  contents:
    packages: [go]
  environment:
    CGO_ENABLED: `+name+`
pipeline:
  - uses: go/build
    with:
      packages: ./cmd/example
      output: example
`)
			units, notes := goUnits(t, cfg)
			require.Len(t, units, 1, name)
			assert.Equal(t, simulate.BuildEnv{CGO: value}, units[0].Env, name)
			assert.Empty(t, notes, name)
		}
	})
}

// TestDiscoverApksSpecs runs the real discovery over checked-out apks specs
// (read-only), when CHOAM_APKS_DIR points at them: a golden of the derived
// build target for specs whose environment shape matters.
func TestDiscoverApksSpecs(t *testing.T) {
	dir := os.Getenv("CHOAM_APKS_DIR")
	if dir == "" {
		t.Skip("set CHOAM_APKS_DIR to an apks checkout to run")
	}
	for spec, want := range map[string]simulate.BuildEnv{
		"terraform-1.14.yaml": {CGO: "0"},
		"kgateway.yaml":       {CGO: "0"},
		"opentofu-1.12.yaml":  {CGO: "0"},
		"kubeconform.yaml":    {},
	} {
		t.Run(spec, func(t *testing.T) {
			cfg, err := melange.ParseConfiguration(t.Context(), filepath.Join(dir, spec))
			require.NoError(t, err)
			units, notes := goUnits(t, cfg)
			require.NotEmpty(t, units)
			for _, unit := range units {
				t.Logf("%s: modroot %s packages %v tags %v arches %v env %+v", spec, unit.Modroot, unit.Packages, unit.Tags, unit.Arches, unit.Env)
				assert.Equal(t, want, unit.Env, unit.Modroot)
				assert.Equal(t, []string{"amd64", "arm64"}, unit.Arches)
			}
			assert.Empty(t, notes)
		})
	}
}

func TestDiscoverAnalysisUnits(t *testing.T) {
	loader := config.NewLoader()

	t.Run("union of existing bump step modroots", func(t *testing.T) {
		steps, err := loader.FindBumpSteps([]byte(certManagerLikeYAML))
		require.NoError(t, err)

		units, _ := discoverAnalysisUnits(t.Context(), &melange.Configuration{}, steps, nil)
		require.Contains(t, units, "go")
		assert.ElementsMatch(t, []string{"cmd/a", "cmd/b", ".", "test/e2e"}, roots(units["go"]))
	})

	t.Run("go/build modroot signal, top-level pipeline", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "git-checkout"},
				{Uses: "go/build", With: map[string]string{"modroot": "cmd/foo"}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.Equal(t, []string{"cmd/foo"}, roots(units["go"]))
	})

	t.Run("go/build with no explicit modroot defaults to \".\"", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "go/build"}},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.Equal(t, []string{"."}, roots(units["go"]))
	})

	t.Run("cargo/build signal", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "cargo/build", With: map[string]string{"modroot": "."}}},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.Equal(t, []string{"."}, roots(units["rust"]))
	})

	t.Run("go/build signal found only in a subpackage pipeline", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "git-checkout"}},
			Subpackages: []melange.Subpackage{
				{Name: "sub", Pipeline: []melange.Pipeline{
					{Uses: "go/build", With: map[string]string{"modroot": "cmd/sub"}},
				}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.Equal(t, []string{"cmd/sub"}, roots(units["go"]))
	})

	t.Run("multiple go/build steps across top-level and subpackages, all collected", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"modroot": "cmd/a"}},
			},
			Subpackages: []melange.Subpackage{
				{Name: "sub1", Pipeline: []melange.Pipeline{
					{Uses: "go/build", With: map[string]string{"modroot": "cmd/b"}},
				}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.ElementsMatch(t, []string{"cmd/a", "cmd/b"}, roots(units["go"]))
	})

	t.Run("annotation opt-in with explicit modroot list", func(t *testing.T) {
		cfg := &melange.Configuration{
			Package: melange.Package{Annotations: map[string]string{
				"choam/bump-rust": "cmd/foo, cmd/bar",
			}},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.ElementsMatch(t, []string{"cmd/foo", "cmd/bar"}, roots(units["rust"]))
	})

	t.Run("annotation present but empty defaults to \".\"", func(t *testing.T) {
		cfg := &melange.Configuration{
			Package: melange.Package{Annotations: map[string]string{"choam/bump-java": ""}},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.Equal(t, []string{"."}, roots(units["java"]))
	})

	t.Run("all three sources additively union for the same language", func(t *testing.T) {
		bumpSteps := []config.BumpStep{{Language: "go", Modroots: []string{"cmd/existing"}}}
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "go/build", With: map[string]string{"modroot": "cmd/build"}}},
			Package: melange.Package{Annotations: map[string]string{
				"choam/bump-go": "cmd/annotated",
			}},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, bumpSteps, nil)
		assert.ElementsMatch(t, []string{"cmd/existing", "cmd/build", "cmd/annotated"}, roots(units["go"]))
	})

	t.Run("engine, tidy and go-package pin per modroot", func(t *testing.T) {
		bumpSteps := []config.BumpStep{
			{Action: "go/bump", Modroots: []string{"cmd/legacy"}},
			{Action: "bump", Language: "go", Modroots: []string{"cmd/untidy"}, NoTidy: true},
			{Action: "bump", Language: "go", Modroots: []string{"cmd/legacy"}}, // first covering step wins
		}
		cfg := &melange.Configuration{Pipeline: []melange.Pipeline{
			{Uses: "go/build", With: map[string]string{"modroot": "cmd/new", "go-package": "go-1.26"}},
			{Uses: "go/build", With: map[string]string{"modroot": "cmd/new", "go-package": "go-fips-1.25"}},
		}}
		byRoot := make(map[string]analysisUnit)
		units, _ := discoverAnalysisUnits(t.Context(), cfg, bumpSteps, nil)
		for _, unit := range units["go"] {
			byRoot[unit.Modroot] = unit
		}
		assert.Equal(t, simulate.EngineGobump, byRoot["cmd/legacy"].Engine)
		assert.Equal(t, simulate.EngineOmnibump, byRoot["cmd/untidy"].Engine)
		assert.True(t, byRoot["cmd/untidy"].NoTidy)
		assert.Equal(t, simulate.EngineOmnibump, byRoot["cmd/new"].Engine, "a root without a step gets choam's default `uses: bump`")
		assert.False(t, byRoot["cmd/new"].NoTidy)
		assert.Equal(t, "1.25", byRoot["cmd/new"].GoMinor, "the lowest pinned go minor")
		assert.Equal(t, "", byRoot["cmd/legacy"].GoMinor)
	})

	t.Run("multiple languages coexist without conflict", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"modroot": "."}},
				{Uses: "cargo/build", With: map[string]string{"modroot": "cli"}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.Equal(t, []string{"."}, roots(units["go"]))
		assert.Equal(t, []string{"cli"}, roots(units["rust"]))
	})

	t.Run("nothing found at all - not bumpable", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "git-checkout"}, {Runs: "make build"}},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.Empty(t, units)
	})

	t.Run("maven has no structured build signal - annotation only", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "maven/pombump"}}, // not a build step with modroot
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.NotContains(t, units, "java")

		cfg.Package.Annotations = map[string]string{"choam/bump-java": "."}
		units, _ = discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		assert.Equal(t, []string{"."}, roots(units["java"]))
	})

	t.Run("go/build packages captured per modroot", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"modroot": ".", "packages": "./cmd/terraform ."}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		require.Len(t, units["go"], 1)
		assert.Equal(t, ".", units["go"][0].Modroot)
		assert.ElementsMatch(t, []string{".", "./cmd/terraform"}, units["go"][0].Packages)
	})

	t.Run("packages unioned across go/build steps sharing a modroot", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"packages": "./cmd/a"}},
				{Uses: "go/build", With: map[string]string{"packages": "./cmd/b ./cmd/a"}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		require.Len(t, units["go"], 1)
		assert.Equal(t, []string{"./cmd/a", "./cmd/b"}, units["go"][0].Packages)
	})

	t.Run("template expressions in packages are rendered", func(t *testing.T) {
		cfg := &melange.Configuration{
			Package: melange.Package{Name: "example", Version: "1.0.0"},
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"packages": "./cmd/${{package.name}}"}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		require.Len(t, units["go"], 1)
		assert.Equal(t, []string{"./cmd/example"}, units["go"][0].Packages)
	})

	t.Run("bump-step-only modroot has empty packages", func(t *testing.T) {
		bumpSteps := []config.BumpStep{{Language: "go", Modroots: []string{"cmd/only"}}}
		units, _ := discoverAnalysisUnits(t.Context(), &melange.Configuration{}, bumpSteps, nil)
		require.Len(t, units["go"], 1)
		assert.Empty(t, units["go"][0].Packages)
		assert.Empty(t, units["go"][0].Tags)
	})

	t.Run("go/build tags: toolchaintags default plus tags, unioned", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"tags": "foo, bar"}},
				{Uses: "go/build", With: map[string]string{"toolchaintags": "netgo", "tags": "baz"}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		require.Len(t, units["go"], 1)
		assert.Equal(t, []string{"bar", "baz", "foo", "netgo", "osusergo"}, units["go"][0].Tags)
	})

	t.Run("go/build empty toolchaintags override drops the default", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"toolchaintags": ""}},
			},
		}
		units, _ := discoverAnalysisUnits(t.Context(), cfg, nil, nil)
		require.Len(t, units["go"], 1)
		assert.Empty(t, units["go"][0].Tags)
	})
}
