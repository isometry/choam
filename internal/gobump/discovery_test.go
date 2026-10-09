package gobump

import (
	"os"
	"path/filepath"
	"testing"

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

func TestGoTargetArches(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []string
		want []string
	}{
		{"absent: melange's default", nil, []string{"amd64", "arm64"}},
		{"x86_64", []string{"x86_64"}, []string{"amd64"}},
		{"aarch64", []string{"aarch64"}, []string{"arm64"}},
		{"both, any order", []string{"aarch64", "x86_64"}, []string{"amd64", "arm64"}},
		{"GOARCH spellings", []string{"arm64", "amd64"}, []string{"amd64", "arm64"}},
		{"all", []string{"all"}, []string{"amd64", "arm64"}},
		{"others mapped", []string{"armv7", "ppc64le", "x86_64"}, []string{"amd64", "arm", "ppc64le"}},
		{"unknown only: default", []string{"pdp11"}, []string{"amd64", "arm64"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &melange.Configuration{Package: melange.Package{TargetArchitecture: tt.in}}
			assert.Equal(t, tt.want, goTargetArches(t.Context(), cfg))
		})
	}

	t.Run("threaded onto every go unit", func(t *testing.T) {
		cfg := &melange.Configuration{
			Package:  melange.Package{TargetArchitecture: []string{"x86_64"}, Annotations: map[string]string{"choam/bump-go": "cmd/annotated"}},
			Pipeline: []melange.Pipeline{{Uses: "go/build"}},
		}
		units, _ := goUnits(t, cfg)
		require.Len(t, units, 2)
		for _, unit := range units {
			assert.Equal(t, []string{"amd64"}, unit.Arches, unit.Modroot)
		}
	})
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
