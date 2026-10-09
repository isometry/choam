package simulate

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Build-target replay fixtures (offline file:// GOPROXY, real go toolchain,
// fake scanner): reachability is the union over the package's target arches
// and honours the spec's CGO_ENABLED; the final set is compiled on every
// target arch.

const (
	modArmDep = "example.com/armdep" // imported only from main's _arm64.go file
	modCgoDep = "example.com/cgodep" // imported only from main's cgo-constrained file
	modDep    = "example.com/dep"    // v1.1.0 does not compile for arm64

	advArm = "GO-TEST-ARM"
	advCgo = "GO-TEST-CGO"
	advDep = "GO-TEST-DEP"
)

// buildTargetCase: armdep is linked only into the arm64 build, cgodep only
// into a cgo build; both have a HIGH advisory fixed in v1.1.0.
func buildTargetCase() replayCase {
	src := func(pkg string) string {
		return "package " + pkg + "\n\nfunc Name() string { return \"" + pkg + "\" }\n"
	}
	return replayCase{
		name: "build-target-linkage",
		modules: map[string]map[string]string{
			modArmDep + "@v1.0.0": stubModule(modArmDep, "armdep.go", src("armdep"), nil),
			modArmDep + "@v1.1.0": stubModule(modArmDep, "armdep.go", src("armdep"), nil),
			modCgoDep + "@v1.0.0": stubModule(modCgoDep, "cgodep.go", src("cgodep"), nil),
			modCgoDep + "@v1.1.0": stubModule(modCgoDep, "cgodep.go", src("cgodep"), nil),
		},
		main: map[string]string{
			"go.mod":        "module example.com/app\n\ngo 1.21\n\nrequire (\n\t" + modArmDep + " v1.0.0\n\t" + modCgoDep + " v1.0.0\n)\n",
			"main.go":       "package main\n\nfunc main() {}\n",
			"link_arm64.go": "package main\n\nimport \"" + modArmDep + "\"\n\nvar _ = armdep.Name\n",
			"link_cgo.go":   "//go:build cgo\n\npackage main\n\nimport \"" + modCgoDep + "\"\n\nvar _ = cgodep.Name\n",
		},
		sc: func() *fakeScanner {
			return &fakeScanner{advisories: []fakeAdvisory{
				{module: modArmDep, id: advArm, fixed: "v1.1.0", severity: "HIGH"},
				{module: modCgoDep, id: advCgo, fixed: "v1.1.0", severity: "HIGH"},
			}}
		},
		req: ModrootRequest{
			Modroot: ".",
			Seeds: []Candidate{
				{Module: modArmDep, Version: "v1.1.0", FromCVE: true, VulnIDs: []string{advArm}, Severity: "HIGH"},
				{Module: modCgoDep, Version: "v1.1.0", FromCVE: true, VulnIDs: []string{advCgo}, Severity: "HIGH"},
			},
			Baseline: map[string]string{modArmDep: "v1.0.0", modCgoDep: "v1.0.0"},
			Tags:     replayTags,
		},
	}
}

// TestReplay_BuildTargetLinkage: an advisory in a package imported only
// from an _arm64.go file is a security fix under the arch union (melange
// builds arm64 too) and unlinked under an x86_64-only target; one imported
// only from a cgo file is a fix unless the spec sets CGO_ENABLED=0.
func TestReplay_BuildTargetLinkage(t *testing.T) {
	c := buildTargetCase()
	f := c.fixture(t)
	both := []string{modArmDep + "@v1.1.0", modCgoDep + "@v1.1.0"}
	for _, tt := range []struct {
		name     string
		arches   []string
		env      BuildEnv
		fixed    []string
		unlinked []string
	}{
		{name: "default: both arches, cgo on", fixed: both},
		{name: "arches in either order", arches: []string{"arm64", "amd64"}, fixed: both},
		{name: "x86_64 only", arches: []string{"amd64"}, fixed: []string{modCgoDep + "@v1.1.0"}, unlinked: []string{modArmDep}},
		{name: "aarch64 only", arches: []string{"arm64"}, fixed: both},
		{name: "spec CGO_ENABLED=1", env: BuildEnv{CGO: "1"}, fixed: both},
		{name: "spec CGO_ENABLED=0", env: BuildEnv{CGO: "0"}, fixed: []string{modArmDep + "@v1.1.0"}, unlinked: []string{modCgoDep}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			run := c
			run.req.Arches, run.req.Env = tt.arches, tt.env
			result, err := run.run(t, f.fresh(t), EngineOmnibump, false)
			require.NoError(t, err)
			logResult(t, result)
			assert.Equal(t, tt.fixed, result.FinalDeps)
			var fixedModules []string
			for _, dep := range tt.fixed {
				fixedModules = append(fixedModules, dep[:len(dep)-len("@v1.1.0")])
			}
			assert.Equal(t, fixedModules, result.CVEBackedModules, "linked on any target arch: a security fix")
			for _, module := range tt.unlinked {
				assert.NotContains(t, result.Linked, module)
				assert.True(t, slices.ContainsFunc(result.Dropped, func(d DroppedCandidate) bool { return d.Module == module }),
					"%s must be dropped as unlinked: %+v", module, result.Dropped)
			}
			assert.Empty(t, result.Residuals)
		})
	}
}

// crossArchCase: dep v1.1.0 fixes an advisory and compiles for amd64, but
// one of its _arm64.go files does not compile.
func crossArchCase() replayCase {
	src := "package dep\n\nfunc Name() string { return \"dep\" }\n"
	broken := stubModule(modDep, "dep.go", src, nil)
	broken["dep_arm64.go"] = "package dep\n\nvar _ int = \"not an int\"\n"
	return replayCase{
		name: "cross-arch-compile",
		modules: map[string]map[string]string{
			modDep + "@v1.0.0": stubModule(modDep, "dep.go", src, nil),
			modDep + "@v1.1.0": broken,
		},
		main: map[string]string{
			"go.mod":  "module example.com/app\n\ngo 1.21\n\nrequire " + modDep + " v1.0.0\n",
			"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"" + modDep + "\"\n)\n\nfunc main() { fmt.Println(dep.Name()) }\n",
		},
		sc: func() *fakeScanner {
			return &fakeScanner{advisories: []fakeAdvisory{{module: modDep, id: advDep, fixed: "v1.1.0", severity: "HIGH"}}}
		},
		req: ModrootRequest{
			Modroot:  ".",
			Seeds:    []Candidate{{Module: modDep, Version: "v1.1.0", FromCVE: true, VulnIDs: []string{advDep}, Severity: "HIGH"}},
			Baseline: map[string]string{modDep: "v1.0.0"},
			Tags:     replayTags,
		},
	}
}

// TestReplay_CrossArchCompile: the gate runs on the primary arch, then the
// final set is compiled once on each other target arch - a break there
// fails the simulation closed (ErrCompileGate); an x86_64-only package is
// not compiled for arm64 at all.
func TestReplay_CrossArchCompile(t *testing.T) {
	c := crossArchCase()
	f := c.fixture(t)

	_, err := c.run(t, f.fresh(t), EngineOmnibump, false)
	require.ErrorIs(t, err, ErrCompileGate)
	assert.ErrorContains(t, err, "GOARCH=arm64")

	amd64 := c
	amd64.req.Arches = []string{"amd64"}
	result, err := amd64.run(t, f.fresh(t), EngineOmnibump, false)
	require.NoError(t, err)
	assert.Equal(t, []string{modDep + "@v1.1.0"}, result.FinalDeps)
}
