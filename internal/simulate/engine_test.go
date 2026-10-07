package simulate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	omnibump "github.com/chainguard-dev/omnibump/pkg/languages/golang"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

// omnibumpApply applies entries to the module at dir with EngineOmnibump
// (filter + DoUpdate): deps ("module@version") and replaces
// ("old=new@version"), in order.
func omnibumpApply(ctx context.Context, tc Toolchain, dir string, req ModrootRequest, deps []string) error {
	_, err := omnibumpApplySkips(ctx, tc, dir, req, deps)
	return err
}

func omnibumpApplySkips(ctx context.Context, tc Toolchain, dir string, req ModrootRequest, deps []string) ([]string, error) {
	req.Engine = EngineOmnibump
	l := &loop{tc: tc, dir: dir, req: req, opts: Options{}.WithDefaults()}
	if err := l.savePristine(ctx); err != nil {
		return nil, err
	}
	eng, err := l.newEngine(ctx)
	if err != nil {
		return nil, err
	}
	keep := make([]*candState, 0, len(deps))
	for _, dep := range deps {
		coord, version, _ := strings.Cut(dep, "@")
		c := Candidate{Module: coord, Version: version}
		if old, module, isReplace := strings.Cut(coord, "="); isReplace {
			c = Candidate{Module: module, Version: version, Replace: true, ReplaceOld: old}
		}
		keep = append(keep, &candState{Candidate: c})
	}
	var names []string
	for _, c := range keep {
		if eng.upstreamSkip(c) != "" {
			names = append(names, c.Module+"@"+c.Version)
		}
	}
	if fail := eng.apply(ctx, keep); fail != nil {
		return names, fail.err
	}
	return names, nil
}

func readModFile(t *testing.T, dir string) *modfile.File {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	require.NoError(t, err)
	mf, err := modfile.Parse("go.mod", content, nil)
	require.NoError(t, err)
	return mf
}

func requireVersions(mf *modfile.File) map[string]string {
	versions := make(map[string]string, len(mf.Require))
	for _, r := range mf.Require {
		versions[r.Mod.Path] = r.Mod.Version
	}
	return versions
}

// doUpdateFixture: a main module requiring a and b (b requires a v1.0.0),
// e1/e2 at v1.1.0, with a go directive and toolchain line; g is served but
// imported by nothing.
func doUpdateFixture(t *testing.T) (*GoToolchain, string) {
	t.Helper()
	pkg := func(path, name string, requires map[string]string) map[string]string {
		src := "package " + name + "\n\nfunc Name() string { return \"" + name + "\" }\n"
		return stubModule(path, name+".go", src, requires)
	}
	f := newReplayFixture(t, map[string]map[string]string{
		"example.com/a@v1.0.0":  pkg("example.com/a", "a", nil),
		"example.com/a@v1.1.0":  pkg("example.com/a", "a", nil),
		"example.com/a@v1.2.0":  pkg("example.com/a", "a", nil),
		"example.com/b@v1.0.0":  pkg("example.com/b", "b", map[string]string{"example.com/a": "v1.0.0"}),
		"example.com/e1@v1.0.0": pkg("example.com/e1", "e1", nil),
		"example.com/e1@v1.1.0": pkg("example.com/e1", "e1", nil),
		"example.com/e2@v1.0.0": pkg("example.com/e2", "e2", nil),
		"example.com/e2@v1.1.0": pkg("example.com/e2", "e2", nil),
		"example.com/g@v1.0.0":  pkg("example.com/g", "g", nil),
	}, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.22.3\n\ntoolchain go1.22.3\n\nrequire (\n" +
			"\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n\texample.com/e1 v1.1.0\n\texample.com/e2 v1.1.0\n)\n",
		"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/a\"\n\t\"example.com/b\"\n\t\"example.com/e1\"\n\t\"example.com/e2\"\n)\n\n" +
			"func main() { fmt.Println(a.Name(), b.Name(), e1.Name(), e2.Name()) }\n",
	})
	return f.tc, f.dir
}

// TestOmnibumpEngine_DoUpdateSemantics runs the real DoUpdate on the file://
// proxy fixture: equal/older entries are skipped by the raw-go.mod filter, an
// already-required module is set exactly (its dependents untouched), an
// absent module the build never imports is fetched then pruned by the final
// tidy, and the go directive is lowered to the build's Go - never raised -
// with the toolchain line dropped.
func TestOmnibumpEngine_DoUpdateSemantics(t *testing.T) {
	tc, dir := doUpdateFixture(t)
	ctx := t.Context()
	pristine, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	require.NoError(t, err)
	reset := func() { require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), pristine, 0o644)) }

	t.Run("lowered", func(t *testing.T) {
		defer reset()
		skipped, err := omnibumpApplySkips(ctx, tc, dir, ModrootRequest{GoVersion: "1.21.0"},
			[]string{"example.com/e1@v1.1.0", "example.com/e2@v1.0.0", "example.com/a@v1.2.0", "example.com/g@v1.0.0"})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"example.com/e1@v1.1.0", "example.com/e2@v1.0.0"}, skipped,
			"equal and older entries are skipped against the raw go.mod")

		mf := readModFile(t, dir)
		got := requireVersions(mf)
		assert.Equal(t, "v1.2.0", got["example.com/a"], "an already-required module is set exactly")
		assert.Equal(t, "v1.0.0", got["example.com/b"], "dependents are not moved")
		assert.Equal(t, "v1.1.0", got["example.com/e1"])
		assert.Equal(t, "v1.1.0", got["example.com/e2"])
		assert.NotContains(t, got, "example.com/g", "the final tidy prunes an entry nothing imports")
		assert.Equal(t, "1.21.0", mf.Go.Version, "go directive lowered to the build's Go")
		assert.Nil(t, mf.Toolchain, "toolchain line removed")
	})

	t.Run("never raised", func(t *testing.T) {
		defer reset()
		require.NoError(t, omnibumpApply(ctx, tc, dir, ModrootRequest{GoVersion: "1.30.0"}, []string{"example.com/a@v1.1.0"}))
		mf := readModFile(t, dir)
		assert.Equal(t, "1.22.3", mf.Go.Version, "a newer build Go never raises the go directive")
		assert.Equal(t, "v1.1.0", requireVersions(mf)["example.com/a"])
	})

	t.Run("no tidy", func(t *testing.T) {
		defer reset()
		require.NoError(t, omnibumpApply(ctx, tc, dir, ModrootRequest{NoTidy: true, GoVersion: "1.22.3"},
			[]string{"example.com/g@v1.0.0", "example.com/a@v1.2.0"}))
		got := requireVersions(readModFile(t, dir))
		assert.Equal(t, "v1.0.0", got["example.com/g"], "a module absent from go.mod is added via go get")
		assert.Equal(t, "v1.2.0", got["example.com/a"])
	})
}

// TestRunLoop_OmnibumpPrunedEntryDropped: an entry for a module the build
// never imports is fetched and then pruned by omnibump's final tidy
// (warn-skipped at build time): the loop drops it as pruned. Reachability is
// made unavailable (a build pattern that does not exist) so the entry is not
// already shed as unlinked before the apply.
func TestRunLoop_OmnibumpPrunedEntryDropped(t *testing.T) {
	tc, dir := doUpdateFixture(t)
	sc := &fakeScanner{advisories: []fakeAdvisory{{module: "example.com/a", id: "GO-A", fixed: "v1.2.0"}}}
	result, err := RunLoop(t.Context(), tc, sc, dir, ModrootRequest{
		Modroot: ".",
		Seeds: []Candidate{
			{Module: "example.com/g", Version: "v1.0.0"},
			{Module: "example.com/a", Version: "v1.2.0", FromCVE: true, VulnIDs: []string{"GO-A"}},
		},
		Baseline: map[string]string{"example.com/a": "v1.0.0"},
		Packages: []string{"./does-not-exist"},
		Engine:   EngineOmnibump,
	}, Options{NoCompile: true})
	require.NoError(t, err)
	logResult(t, result)
	assert.Equal(t, []string{"example.com/a@v1.2.0"}, result.FinalDeps)
	assert.Contains(t, result.Dropped, DroppedCandidate{Module: "example.com/g", Version: "v1.0.0",
		Reason: "pruned by go mod tidy: not required by the tidied go.mod"})
}

// TestRunLoop_OmnibumpDowngradeVerification: omnibump's post-tidy
// verification rejects an entry the tidy left below its version
// (ErrPackageDowngrade). The tidied result is what the sustain checks see,
// so a CVE pin is promoted to a replace directive - as for gobump's
// identical verification.
func TestRunLoop_OmnibumpDowngradeVerification(t *testing.T) {
	tc, dir := doUpdateFixture(t)
	real := omnibumpUpdate
	t.Cleanup(func() { omnibumpUpdate = real })
	omnibumpUpdate = func(ctx context.Context, pkgs map[string]*omnibump.Package, cfg *omnibump.UpdateConfig) (*modfile.File, error) {
		mf, err := real(ctx, pkgs, cfg)
		pkg, ok := pkgs["example.com/a"]
		if err != nil || !ok || pkg.Replace {
			return mf, err
		}
		// Model a tidy that reverts the pin: a back to v1.1.0.
		path := filepath.Join(cfg.Modroot, "go.mod")
		content, rerr := os.ReadFile(path)
		require.NoError(t, rerr)
		edited, perr := modfile.Parse("go.mod", content, nil)
		require.NoError(t, perr)
		require.NoError(t, edited.AddRequire("example.com/a", "v1.1.0"))
		out, ferr := edited.Format()
		require.NoError(t, ferr)
		require.NoError(t, os.WriteFile(path, out, 0o644))
		return nil, fmt.Errorf("%w: package example.com/a with v1.1.0 is less than the desired version %s", omnibump.ErrPackageDowngrade, pkg.Version)
	}

	result, err := RunLoop(t.Context(), tc, &fakeScanner{advisories: []fakeAdvisory{{module: "example.com/a", id: "GO-A", fixed: "v1.2.0"}}}, dir,
		ModrootRequest{
			Modroot:  ".",
			Seeds:    []Candidate{{Module: "example.com/a", Version: "v1.2.0", FromCVE: true, VulnIDs: []string{"GO-A"}}},
			Baseline: map[string]string{"example.com/a": "v1.0.0"},
			Engine:   EngineOmnibump,
		}, Options{NoCompile: true})
	require.NoError(t, err)
	logResult(t, result)
	assert.Empty(t, result.FinalDeps)
	assert.Equal(t, []string{"example.com/a=example.com/a@v1.2.0"}, result.FinalReplaces, "reverted CVE pin promoted to a replace")
	assert.Equal(t, "v1.2.0", result.Resolved["example.com/a"])
	assert.Empty(t, result.Residuals)
}

// TestRunLoop_AmbiguousImportBothEngines: fetching the split-out module
// m/sub while the old monolith m still carries its package fails with
// "ambiguous import" (the genproto shape). Both engines repair it by
// advancing the monolith (the remedy) - the classification survives
// omnibump's wrapped error text. Reachability is made unavailable so the
// not-yet-linked split module is not shed before the apply.
//
// The engines then differ. gobump gets the remedy first and m/sub after it.
// omnibump applies the remedy's concrete version as an in-place require edit,
// which runs after every `go get`, so fetching m/sub stays ambiguous until
// the loop promotes the m/sub fix to a replace directive (replaces apply
// first). Under gobump the m/sub entry is then redundant (implied by the
// remedy), so both results are re-applied from scratch.
func TestRunLoop_AmbiguousImportBothEngines(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		subSrc := "package sub\n\nfunc Name() string { return \"sub\" }\n"
		mSrc := "package m\n\nfunc Name() string { return \"m\" }\n"
		f := newReplayFixture(t, map[string]map[string]string{
			"example.com/m@v1.0.0":     {"go.mod": "module example.com/m\n\ngo 1.21\n", "m.go": mSrc, "sub/sub.go": subSrc},
			"example.com/m@v1.1.0":     {"go.mod": "module example.com/m\n\ngo 1.21\n", "m.go": mSrc},
			"example.com/m/sub@v1.1.0": stubModule("example.com/m/sub", "sub.go", subSrc, nil),
		}, map[string]string{
			"go.mod":  "module example.com/app\n\ngo 1.21\n\nrequire example.com/m v1.0.0\n",
			"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/m\"\n\t\"example.com/m/sub\"\n)\n\nfunc main() { fmt.Println(m.Name(), sub.Name()) }\n",
		})
		sc := &fakeScanner{advisories: []fakeAdvisory{{module: "example.com/m/sub", id: "GO-SUB", fixed: "v1.1.0"}}}
		result, err := RunLoop(t.Context(), f.tc, sc, f.dir, ModrootRequest{
			Modroot:  ".",
			Seeds:    []Candidate{{Module: "example.com/m/sub", Version: "v1.1.0", FromCVE: true, VulnIDs: []string{"GO-SUB"}}},
			Baseline: map[string]string{"example.com/m": "v1.0.0"},
			Packages: []string{"./does-not-exist"},
			Engine:   eng,
		}, Options{NoCompile: true})
		require.NoError(t, err)
		logResult(t, result)
		assert.Empty(t, result.Residuals)
		assert.Equal(t, "v1.1.0", result.Resolved["example.com/m"])
		assert.Equal(t, "v1.1.0", result.Resolved["example.com/m/sub"])
		assert.Equal(t, []string{"example.com/m@v1.1.0"}, result.FinalDeps)
		if eng == EngineGobump {
			// The m/sub entry is implied by the remedied monolith: the
			// final go.mod is identical without it.
			assert.Empty(t, result.FinalReplaces)
		} else {
			assert.Equal(t, []string{"example.com/m/sub=example.com/m/sub@v1.1.0"}, result.FinalReplaces)
		}
		assert.Empty(t, f.compileFailuresWith(t, eng, append(result.FinalReplaces, result.FinalDeps...)))
	})
}

func TestRawSkip(t *testing.T) {
	raw, err := modfile.Parse("go.mod", []byte("module example.com/app\n\ngo 1.21\n\nrequire (\n"+
		"\texample.com/a v1.1.0\n\texample.com/p v1.0.0\n\texample.com/x v1.0.0\n)\n\n"+
		"replace example.com/p => example.com/p v1.0.0\n\nreplace example.com/x => example.com/fork v1.3.0\n"), nil)
	require.NoError(t, err)
	cases := []struct {
		name string
		c    Candidate
		skip bool
	}{
		{"older", Candidate{Module: "example.com/a", Version: "v1.0.0"}, true},
		{"equal", Candidate{Module: "example.com/a", Version: "v1.1.0"}, true},
		{"newer", Candidate{Module: "example.com/a", Version: "v1.2.0"}, false},
		{"absent", Candidate{Module: "example.com/new", Version: "v1.0.0"}, false},
		{"latest query", Candidate{Module: "example.com/a", Version: latestQuery}, false},
		{"main module", Candidate{Module: "example.com/app", Version: "v9.0.0"}, true},
		{"deps entry for a replace-pinned module", Candidate{Module: "example.com/p", Version: "v1.5.0"}, true},
		{"replace entry for a replace-pinned module", Candidate{Module: "example.com/p", Version: "v1.5.0", Replace: true}, false},
		{"replace target compared by its version", Candidate{Module: "example.com/fork", Version: "v1.2.0"}, true},
		{"new self-replace at the required version creates the pin", Candidate{Module: "example.com/a", Version: "v1.1.0", Replace: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rawSkip(raw, &candState{Candidate: tc.c})
			assert.Equal(t, tc.skip, got != "", "rawSkip = %q", got)
		})
	}
}

func TestOmnibumpClassify(t *testing.T) {
	a := &candState{Candidate: Candidate{Module: "example.com/a", Version: "v1.2.0"}}
	ab := &candState{Candidate: Candidate{Module: "example.com/a/b", Version: "v0.3.0"}}
	keep := []*candState{a, ab}
	e := &omnibumpEngine{}
	ctx := t.Context()

	f := e.classify(ctx, fmt.Errorf("%w: package example.com/a with v1.1.0 is less than the desired version v1.2.0", omnibump.ErrPackageDowngrade), keep)
	assert.Equal(t, stepVerify, f.step)
	assert.Same(t, a, f.cand)

	f = e.classify(ctx, errors.New("failed to run 'go get': exit status 1 with output: go: example.com/a/b@v0.3.0: unknown revision"), keep)
	assert.Equal(t, stepGet, f.step)
	assert.Same(t, ab, f.cand, "the longest named module path wins")

	f = e.classify(ctx, errors.New("failed to run 'go mod tidy': exit status 1 with output: go: example.com/app imports example.com/a/b: ambiguous import"), keep)
	assert.Equal(t, stepTidy, f.step)

	f = e.classify(ctx, errors.New("failed to normalize go.mod version: boom"), keep)
	assert.Equal(t, stepSetup, f.step)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	f = e.classify(cancelled, errors.New("failed to run 'go get': signal: killed"), keep)
	assert.Equal(t, stepSetup, f.step)
	assert.ErrorIs(t, f.err, context.Canceled, "a cancellation propagates, never a candidate failure")
}

func TestOmnibumpEnv(t *testing.T) {
	raw := func(directive string) *modfile.File {
		mf, err := modfile.Parse("go.mod", []byte("module m\n\ngo "+directive+"\n"), nil)
		require.NoError(t, err)
		return mf
	}
	assert.Equal(t, "local", omnibumpEnv(raw("1.26.6"), "1.27.1", "1.27.1")["GOTOOLCHAIN"])
	assert.Equal(t, "local", omnibumpEnv(raw("1.28.0"), "1.27.1", "1.27.1")["GOTOOLCHAIN"], "lowered to the build's Go")
	assert.Equal(t, "auto", omnibumpEnv(raw("1.28.0"), "1.29.0", "1.27.1")["GOTOOLCHAIN"], "host older than the directive left")
	assert.Equal(t, "auto", omnibumpEnv(raw("1.21"), "", "")["GOTOOLCHAIN"], "unknown host")
	env := omnibumpEnv(raw("1.21"), "1.27.1", "1.27.1")
	assert.Equal(t, "-mod=mod", env["GOFLAGS"])
	assert.Equal(t, "off", env["GOWORK"])
}

func TestWithProcessEnvRestores(t *testing.T) {
	t.Setenv("CHOAM_TEST_SET", "before")
	require.NoError(t, os.Unsetenv("CHOAM_TEST_UNSET"))
	vars := map[string]string{"CHOAM_TEST_SET": "during", "CHOAM_TEST_UNSET": "during"}

	require.NoError(t, withProcessEnv(vars, func() error {
		assert.Equal(t, "during", os.Getenv("CHOAM_TEST_SET"))
		assert.Equal(t, "during", os.Getenv("CHOAM_TEST_UNSET"))
		return nil
	}))
	assert.Equal(t, "before", os.Getenv("CHOAM_TEST_SET"))
	_, set := os.LookupEnv("CHOAM_TEST_UNSET")
	assert.False(t, set)

	assert.Panics(t, func() { _ = withProcessEnv(vars, func() error { panic("boom") }) })
	assert.Equal(t, "before", os.Getenv("CHOAM_TEST_SET"), "restored on panic")
	_, set = os.LookupEnv("CHOAM_TEST_UNSET")
	assert.False(t, set, "restored on panic")
}

func TestOmnibumpVersionReported(t *testing.T) {
	assert.True(t, strings.HasPrefix(OmnibumpVersion(), "v"), "linked omnibump version: %q", OmnibumpVersion())
}
