package simulate

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunEnvTimeout_KillsProcessGroup: a timed-out go command whose child
// (here a backgrounded sleep standing in for git) keeps the output pipes
// open must return promptly - the whole process group is killed - and be
// classified as an infrastructure failure, not a verdict.
func TestRunEnvTimeout_KillsProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups are unix-only")
	}
	script := filepath.Join(t.TempDir(), "go")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nsleep 30 &\nsleep 30\n"), 0o755))

	tc := &GoToolchain{goBin: script, timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err := tc.run(t.Context(), t.TempDir(), "mod", "tidy")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfrastructure)
	assert.Less(t, elapsed, waitDelay, "the group kill, not the WaitDelay backstop, must end the wait")
}

func TestCheckModuleArg(t *testing.T) {
	tests := []struct {
		path, version string
		ok            bool
	}{
		{"github.com/a/b", "v1.2.3", true},
		{"github.com/a/b", "", true},
		{"github.com/a/b", "0123abcd", true},
		{"nodot/local", "v1.0.0", true},
		{"-modfile=/tmp/x", "v1.0.0", false},
		{"-x", "", false},
		{"github.com/a/b", "-exec=evil", false},
		{"github.com/a/b", "v1.0.0 -x", false},
		{"", "v1.0.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.path+"@"+tt.version, func(t *testing.T) {
			err := checkModuleArg(tt.path, tt.version)
			if tt.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestGoToolchain_RejectsFlagLikeArguments: argument validation runs before
// any go command is built (the binary here would fail the test if run).
func TestGoToolchain_RejectsFlagLikeArguments(t *testing.T) {
	tc := &GoToolchain{goBin: "/nonexistent/go", timeout: time.Second, modRequires: map[string]map[string]string{}}
	dir := t.TempDir()
	ctx := t.Context()

	assert.ErrorContains(t, tc.Get(ctx, dir, "-modfile=x@v1.0.0"), "refusing")
	assert.ErrorContains(t, tc.Get(ctx, dir, "github.com/a/b@-x"), "refusing")
	_, err := tc.ModuleVersions(ctx, dir, "-json")
	assert.ErrorContains(t, err, "refusing")
	_, err = tc.ResolveQuery(ctx, dir, "github.com/a/b", "-u")
	assert.ErrorContains(t, err, "refusing")
	_, err = tc.ModuleRequires(ctx, dir, "github.com/a/b", "-v")
	assert.ErrorContains(t, err, "refusing")
	assert.ErrorContains(t, tc.Replace(ctx, dir, "-x", "github.com/a/b", "v1.0.0"), "refusing")
}

// TestTargetBuildEnv pins the single source of the build environment Linked,
// LinkedStd and Typecheck run under: GOOS=linux, the arch, GOEXPERIMENT always
// set, and CGO_ENABLED from the spec - 1 when unset or not understood.
func TestTargetBuildEnv(t *testing.T) {
	for _, tt := range []struct {
		arch string
		env  BuildEnv
		cgo  string
	}{
		{"amd64", BuildEnv{}, "1"},
		{"arm64", BuildEnv{}, "1"},
		{"arm64", BuildEnv{CGO: "1"}, "1"},
		{"amd64", BuildEnv{CGO: "0"}, "0"},
		{"riscv64", BuildEnv{CGO: "bogus"}, "1"},
	} {
		env := targetBuildEnv(tt.arch, tt.env)
		assert.Equal(t, []string{"GOOS=linux", "GOARCH=" + tt.arch, "CGO_ENABLED=" + tt.cgo, "GOEXPERIMENT=" + tt.env.GOExperiment}, env, "%+v", tt)
	}
	assert.Equal(t, []string{"GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=1", "GOEXPERIMENT=boringcrypto"},
		targetBuildEnv("arm64", BuildEnv{GOExperiment: "boringcrypto"}))

	assert.Equal(t, []string{"list", "-deps", "-tags", "a,b", "./cmd/x"}, targetListArgs([]string{"list", "-deps"}, []string{"./cmd/x"}, []string{"a", "b"}))
	assert.Equal(t, []string{"list", "./..."}, targetListArgs([]string{"list"}, nil, nil))
}

// TestTargetArches: normalization is order-independent (the type-check gate's
// primary arch never depends on input order), deduplicated, and empty means
// both Wolfi arches.
func TestTargetArches(t *testing.T) {
	assert.Equal(t, []string{"amd64", "arm64"}, TargetArches(nil))
	inputs := [][]string{
		{"arm64", "amd64"}, {"amd64", "arm64"}, {"arm64", "amd64", "arm64"}, {"amd64", "amd64", "arm64"},
	}
	for range 20 {
		for _, in := range inputs {
			in := slices.Clone(in)
			rand.Shuffle(len(in), func(i, j int) { in[i], in[j] = in[j], in[i] })
			assert.Equal(t, []string{"amd64", "arm64"}, TargetArches(in))
		}
	}
	assert.Equal(t, []string{"arm64"}, TargetArches([]string{"arm64"}))
	assert.Equal(t, []string{"arm64", "riscv64", "s390x"}, TargetArches([]string{"s390x", "riscv64", "arm64"}))
	in := []string{"arm64", "amd64"}
	TargetArches(in)
	assert.Equal(t, []string{"arm64", "amd64"}, in, "the input is not modified")
}

// depsJSON renders go list -json package objects as one stream.
func depsJSON(objects ...string) []byte { return []byte(strings.Join(objects, "\n")) }

func TestParseDeps_FiltersAndReplace(t *testing.T) {
	output := depsJSON(
		`{"ImportPath":"fmt","Standard":true}`,
		`{"ImportPath":"example.com/app","Module":{"Path":"example.com/app","Main":true}}`,
		`{"ImportPath":"example.com/dep/sub","Module":{"Path":"example.com/dep","Version":"v1.0.0"}}`,
		`{"ImportPath":"example.com/old/pkg","Module":{"Path":"example.com/old","Version":"v1.0.0","Replace":{"Path":"example.com/new","Version":"v1.2.0"}}}`,
		`{"ImportPath":"example.com/local","Module":{"Path":"example.com/local","Replace":{"Path":"../local"}}}`,
		`{"ImportPath":"example.com/vendored"}`,
	)
	pkgs, embeds, err := parseDeps(output)
	require.NoError(t, err)
	assert.Empty(t, embeds)
	require.Len(t, pkgs, 6)

	linkage := linkageOf(pkgs, nil)
	assert.Equal(t, map[string]struct{}{
		"example.com/app": {}, "example.com/dep/sub": {}, "example.com/old/pkg": {}, "example.com/local": {},
	}, linkage.Packages, "module packages only: no stdlib, no module-less package")
	assert.Equal(t, map[string]struct{}{
		"example.com/app": {}, "example.com/dep": {}, "example.com/new": {}, "../local": {},
	}, linkage.Modules, "a replaced module is named by its replacement (local paths too, as the template did)")
	assert.Equal(t, map[string]struct{}{"fmt": {}}, stdOf(pkgs))
}

func TestParseDeps_ErrorClassification(t *testing.T) {
	embedPkg := func(pattern, errText string) string {
		return `{"ImportPath":"example.com/app/cmd","Module":{"Path":"example.com/app"},"Incomplete":true,` +
			`"EmbedPatterns":["` + pattern + `"],"Error":{"Pos":"cmd/embed.go:27:12","Err":"` + errText + `"}}`
	}
	importer := func(errText string) string {
		return `{"ImportPath":"example.com/app","Module":{"Path":"example.com/app"},"Incomplete":true,` +
			`"DepsErrors":[{"ImportStack":["example.com/app","example.com/app/cmd"],"Err":"` + errText + `"}]}`
	}
	cases := []struct {
		name    string
		objects []string
		embeds  []UnmatchedEmbed
		err     string // "" = tolerated
	}{
		{name: "no matching files", objects: []string{
			embedPkg("manifests/*.yaml", "pattern manifests/*.yaml: no matching files found"),
			importer("pattern manifests/*.yaml: no matching files found"),
		}, embeds: []UnmatchedEmbed{{Package: "example.com/app/cmd", Pattern: "manifests/*.yaml"}}},
		{name: "empty directory", objects: []string{
			embedPkg("all:dist", "pattern all:dist: cannot embed directory dist: contains no embeddable files"),
		}, embeds: []UnmatchedEmbed{{Package: "example.com/app/cmd", Pattern: "all:dist"}}},
		{name: "embed text for an undeclared pattern", objects: []string{
			embedPkg("other/*", "pattern gen/*.txt: no matching files found"),
		}, err: "package example.com/app/cmd: pattern gen/*.txt"},
		{name: "invalid embed pattern", objects: []string{
			embedPkg("../x", "pattern ../x: invalid pattern syntax"),
		}, err: "invalid pattern syntax"},
		{name: "embed outside module", objects: []string{
			embedPkg("vendor/x", "pattern vendor/x: cannot embed directory vendor/x: in different module"),
		}, err: "in different module"},
		{name: "missing module", objects: []string{
			`{"ImportPath":"example.com/missing","Incomplete":true,"Error":{"Err":"no required module provides package example.com/missing; to add it:\n\tgo get example.com/missing"}}`,
		}, err: "go list -deps: package example.com/missing: no required module provides package example.com/missing; to add it:"},
		{name: "cannot find package", objects: []string{
			`{"ImportPath":"example.com/app/gen","Incomplete":true,"Error":{"Err":"cannot find package \"example.com/app/gen\""}}`,
		}, err: "package example.com/app/gen: cannot find package"},
		{name: "build constraints", objects: []string{
			`{"ImportPath":"example.com/win","Module":{"Path":"example.com/win"},"Incomplete":true,"Error":{"Err":"build constraints exclude all Go files in /x/win"}}`,
		}, err: "package example.com/win: build constraints exclude all Go files"},
		{name: "parse error", objects: []string{
			`{"ImportPath":"example.com/app","Module":{"Path":"example.com/app"},"Incomplete":true,"Error":{"Err":"main.go:3:1: expected declaration, found oops"}}`,
		}, err: "expected declaration"},
		{name: "dependency error only", objects: []string{
			importer("no required module provides package example.com/gen"),
		}, err: "package example.com/app: dependency error: no required module provides package example.com/gen"},
		{name: "incomplete without detail", objects: []string{
			`{"ImportPath":"example.com/app","Module":{"Path":"example.com/app"},"Incomplete":true}`,
		}, err: "package example.com/app: incomplete, no error reported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs, embeds, err := parseDeps(depsJSON(tc.objects...))
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				assert.NotContains(t, err.Error(), "\n", "one-line cause")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.embeds, embeds)
			assert.Len(t, pkgs, len(tc.objects), "a tolerated package keeps its place in the graph")
		})
	}
}

func TestParseDeps_Malformed(t *testing.T) {
	_, _, err := parseDeps([]byte(`{"ImportPath":"a"} {`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing go list -deps -json output")
}

func TestUnmatchedEmbed(t *testing.T) {
	for text, want := range map[string]string{
		"pattern manifests/*.yaml: no matching files found":                         "manifests/*.yaml",
		"pattern all:static: no matching files found":                               "all:static",
		"pattern web: cannot embed directory web: contains no embeddable files":     "web",
		"pattern a b: cannot embed directory a b: contains no embeddable files":     "a b",
		"pattern x: cannot embed irregular file x":                                  "",
		"pattern x: cannot embed file x: invalid name .git":                         "",
		"pattern : no matching files found":                                         "",
		"no matching files found":                                                   "",
		"cannot embed directory web: contains no embeddable files":                  "",
		"no required module provides package example.com/x; to add it:\n\tgo get x": "",
	} {
		got, ok := unmatchedEmbed(text)
		assert.Equal(t, want, got, text)
		assert.Equal(t, want != "", ok, text)
	}
}

// TestParseDeps_Deterministic: the embed gaps are sorted and deduplicated
// across arches whatever the object order.
func TestParseDeps_Deterministic(t *testing.T) {
	objects := []string{
		`{"ImportPath":"example.com/b","Module":{"Path":"example.com/m"},"Incomplete":true,"EmbedPatterns":["z/*","a/*"],"Error":{"Err":"pattern z/*: no matching files found"}}`,
		`{"ImportPath":"example.com/a","Module":{"Path":"example.com/m"},"Incomplete":true,"EmbedPatterns":["gen/*"],"Error":{"Err":"pattern gen/*: no matching files found"}}`,
		`{"ImportPath":"example.com/c","Module":{"Path":"example.com/m"}}`,
	}
	want := []UnmatchedEmbed{{Package: "example.com/a", Pattern: "gen/*"}, {Package: "example.com/b", Pattern: "z/*"}}
	for i := range 20 {
		shuffled := slices.Clone(objects)
		rand.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		var perArch [][]UnmatchedEmbed
		for range 2 { // two arches, same gaps
			_, embeds, err := parseDeps(depsJSON(shuffled...))
			require.NoError(t, err)
			perArch = append(perArch, embeds)
		}
		assert.Equal(t, want, mergeEmbeds(perArch), "run %d", i)
	}
}
