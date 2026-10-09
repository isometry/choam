package simulate

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
// LinkedStd and Compile run under: GOOS=linux, the arch, GOEXPERIMENT always
// set, and CGO_ENABLED from the spec - 1 when unset or not understood - with
// Compile alone falling back to 0 where the host cannot build linux cgo.
func TestTargetBuildEnv(t *testing.T) {
	native := runtime.GOOS == "linux"
	for _, tt := range []struct {
		arch    string
		env     BuildEnv
		compile bool
		cgo     string
	}{
		{"amd64", BuildEnv{}, false, "1"},
		{"arm64", BuildEnv{}, false, "1"},
		{"arm64", BuildEnv{CGO: "1"}, false, "1"},
		{"amd64", BuildEnv{CGO: "0"}, false, "0"},
		{"amd64", BuildEnv{CGO: "0"}, true, "0"},
		{"riscv64", BuildEnv{}, true, map[bool]string{true: "1", false: "0"}[native && runtime.GOARCH == "riscv64"]},
		{runtime.GOARCH, BuildEnv{CGO: "1"}, true, map[bool]string{true: "1", false: "0"}[native]},
	} {
		env := targetBuildEnv(tt.arch, tt.env, tt.compile)
		assert.Equal(t, []string{"GOOS=linux", "GOARCH=" + tt.arch, "CGO_ENABLED=" + tt.cgo, "GOEXPERIMENT=" + tt.env.GOExperiment}, env, "%+v", tt)
		assert.Equal(t, tt.compile && tt.cgo == "0" && tt.env.CGO != "0", CompileCgoLimited(tt.arch, tt.env) && tt.compile, "%+v", tt)
	}
	assert.Equal(t, []string{"GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=1", "GOEXPERIMENT=boringcrypto"},
		targetBuildEnv("arm64", BuildEnv{GOExperiment: "boringcrypto"}, false))

	assert.Equal(t, []string{"list", "-deps", "-tags", "a,b", "./cmd/x"}, targetListArgs([]string{"list", "-deps"}, []string{"./cmd/x"}, []string{"a", "b"}))
	assert.Equal(t, []string{"list", "./..."}, targetListArgs([]string{"list"}, nil, nil))
}

// TestTargetArches: normalization is order-independent (the compile gate's
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

// TestLostCacheEntry: a compile error that is the build cache losing an
// export file under the compile is recognised (Compile then reports an
// infrastructure failure, not a verdict); ordinary errors are not.
func TestLostCacheEntry(t *testing.T) {
	tc := &GoToolchain{goCache: filepath.Join("/cache", "go-build")}
	lost := "# example.com/p\np.go:12:2: could not import time (open " + filepath.Join("/cache", "go-build", "50", "50a2-d") + ": no such file or directory)"
	assert.True(t, tc.lostCacheEntry(lost))
	assert.False(t, tc.lostCacheEntry("p.go:3:2: undefined: api.KeyValue"))
	assert.False(t, tc.lostCacheEntry("p.go:3:2: open /elsewhere/x: no such file or directory"))
	assert.False(t, (&GoToolchain{}).lostCacheEntry(lost), "unknown GOCACHE: never assumed")
}
