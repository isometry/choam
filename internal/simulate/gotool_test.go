package simulate

import (
	"os"
	"path/filepath"
	"runtime"
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
