package simulate

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/stretchr/testify/require"
)

// TestTypecheckBench measures the type-check engine on a real checkout (a
// temporary copy of it), e.g. to size the cache on large specs. Skipped
// unless set:
//
//	CHOAM_TYPECHECK_BENCH=<checkout modroot>[:<go/build packages>]
//	CHOAM_TYPECHECK_BENCH_BUMP=<mod@ver> [<mod@ver>...]   (optional, `go get` before the bump step)
//	CHOAM_TYPECHECK_BENCH_CGO=0|1                        (optional; the spec's CGO_ENABLED)
//
// Steps: cold (empty cache), warm re-run, after the bump, then the second
// arch (arm64). It reports wall times, cache hits/misses, failed packages,
// peak and retained heap and the cache entry count. Modules are downloaded
// before timing.
func TestTypecheckBench(t *testing.T) {
	spec := os.Getenv("CHOAM_TYPECHECK_BENCH")
	if spec == "" {
		t.Skip("set CHOAM_TYPECHECK_BENCH=<checkout dir>[:<patterns>] to run the type-check benchmark")
	}
	src, patterns, _ := strings.Cut(spec, ":")
	target := BuildTarget{Patterns: strings.Fields(patterns), Env: BuildEnv{CGO: os.Getenv("CHOAM_TYPECHECK_BENCH_CGO")}}
	ctx := t.Context()

	dir := t.TempDir()
	out, err := exec.Command("cp", "-R", src+"/.", dir).CombinedOutput()
	require.NoError(t, err, string(out))
	toolchain, err := NewToolchain(ctx, 30*time.Minute)
	require.NoError(t, err)
	for _, arch := range []string{"amd64", "arm64"} {
		_, err := toolchain.runEnv(ctx, dir, targetBuildEnv(arch, target.Env),
			targetListArgs([]string{"list", "-e", "-deps", "-f", "{{.ImportPath}}"}, target.Patterns, target.Tags)...)
		require.NoError(t, err, "downloading modules")
	}

	var peak atomic.Uint64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak.Load() {
				peak.Store(ms.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()

	var table strings.Builder
	tw := tabwriter.NewWriter(&table, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "step\tarch\ttypecheck\thits\tmisses\tfailed")
	measure := func(step, arch string) {
		var report *CheckReport
		start := time.Now()
		hits, misses := cacheDelta(toolchain, func() {
			report, err = toolchain.Typecheck(ctx, dir, target, arch)
		})
		require.NoError(t, err)
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\n", step, arch, time.Since(start).Round(time.Millisecond), hits, misses, len(report.Failed))
		for _, pkg := range slices.Sorted(maps.Keys(report.Failed)) {
			t.Logf("%s/%s: %s:\n  %s", step, arch, pkg, strings.Join(report.Failed[pkg], "\n  "))
		}
	}

	measure("cold", "amd64")
	measure("warm", "amd64")
	if bump := strings.Fields(os.Getenv("CHOAM_TYPECHECK_BENCH_BUMP")); len(bump) > 0 {
		for _, moduleAtVersion := range bump {
			require.NoError(t, toolchain.Get(ctx, dir, moduleAtVersion))
		}
		measure("bump", "amd64")
	}
	measure("cross-arch", "arm64")

	close(stop)
	<-sampled
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	require.NoError(t, tw.Flush())
	t.Logf("%s (patterns %q, CGO %q)\n%speak heap %d MiB, retained after GC (cache) %d MiB, cache entries %d",
		src, target.Patterns, target.Env.CGO, table.String(), peak.Load()>>20, ms.HeapAlloc>>20, len(toolchain.typecheckCache.entries))
}
