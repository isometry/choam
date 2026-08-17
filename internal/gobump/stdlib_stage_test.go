package gobump

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/git"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stdlibTestConfig is a package that builds Go code (go/build step) - the
// shape StdlibStage.ShouldRun requires.
func stdlibTestConfig() *melange.Configuration {
	return &melange.Configuration{
		Pipeline: []melange.Pipeline{
			{Uses: "git-checkout", With: map[string]string{
				"repository": "https://github.com/example/example",
				"tag":        "v1.0.0",
			}},
			{Uses: "go/build", With: map[string]string{"packages": "./cmd/app"}},
		},
	}
}

// staleIndex reports the package as one release behind.
func staleIndex() *fakeReleaseIndex {
	return &fakeReleaseIndex{
		asOf:      map[string]string{"": "1.22.0"},
		available: map[string]string{"": "1.24.5"},
	}
}

// fixableScanner has one advisory at the assumed release, none at rebuild.
func fixableScanner() *fakeStdlibScanner {
	return &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
		"1.22.0": {stdlibVuln("GO-STD-1", scan.VulnerableImport{Path: "net/http"})},
	}}
}

func newStdlibTestStage(opts ProcessorOptions, index *fakeReleaseIndex, scanner *fakeStdlibScanner) *StdlibStage {
	stage := NewStdlibStage(nil, opts)
	stage.index = index
	stage.scanner = scanner
	stage.lastCommit = func(context.Context, string) (*git.FileCommitInfo, error) {
		return &git.FileCommitInfo{Time: stdlibCommitTime, Hash: "abc123"}, nil
	}
	stage.linkStd = func(context.Context, *GoBumpProcessor) (map[string]struct{}, error) {
		return nil, errors.New("linkStd must not be called in this test")
	}
	return stage
}

func newStdlibTestProcessor() *GoBumpProcessor {
	gp := NewGoBumpProcessor("/tmp/test.yaml", "test-package", "1.0.0", 1)
	gp.Config = stdlibTestConfig()
	return gp
}

func messagesContain(t *testing.T, gp *GoBumpProcessor, want string) {
	t.Helper()
	for _, msg := range gp.GetMessages() {
		if strings.Contains(msg, want) {
			return
		}
	}
	t.Errorf("expected a message containing %q, got %v", want, gp.GetMessages())
}

func TestStdlibStage_ShouldRun(t *testing.T) {
	t.Run("go build steps and enabled - runs", func(t *testing.T) {
		stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true}, staleIndex(), fixableScanner())
		ok, err := stage.ShouldRun(t.Context(), newStdlibTestProcessor())
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("disabled by options", func(t *testing.T) {
		stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: false}, staleIndex(), fixableScanner())
		ok, err := stage.ShouldRun(t.Context(), newStdlibTestProcessor())
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("no go build steps", func(t *testing.T) {
		stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true}, staleIndex(), fixableScanner())
		gp := newStdlibTestProcessor()
		gp.Config = &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "cargo/build"}},
		}
		ok, err := stage.ShouldRun(t.Context(), gp)
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("nil config", func(t *testing.T) {
		stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true}, staleIndex(), fixableScanner())
		gp := newStdlibTestProcessor()
		gp.Config = nil
		ok, err := stage.ShouldRun(t.Context(), gp)
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestStdlibStage_RecordsBump(t *testing.T) {
	index, scanner := staleIndex(), fixableScanner()
	stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true}, index, scanner)
	gp := newStdlibTestProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.True(t, gp.StdlibChecked)
	require.Len(t, gp.StdlibBumps, 1)
	assert.Equal(t, "1.22.0", gp.StdlibBumps[0].AssumedGoVersion)
	assert.Equal(t, "1.24.5", gp.StdlibBumps[0].RebuildGoVersion)
	assert.Equal(t, []string{"GO-STD-1"}, gp.StdlibBumps[0].VulnIDs)
	assert.False(t, gp.StdlibBumps[0].Validated, "no linked set, no Validate option - unfiltered")
	messagesContain(t, gp, "rebuilding with go1.24.5 fixes GO-STD-1")
	assert.Empty(t, gp.GetErrors())
}

// TestStdlibStage_RebuildSideReflectsSameRunPinRaise: when this run's applier
// raised a go-package pin (recorded on the processor), the stdlib check's
// rebuild target must come from the RAISED pin while the assumed side stays on
// the pristine config's pin.
func TestStdlibStage_RebuildSideReflectsSameRunPinRaise(t *testing.T) {
	index := &fakeReleaseIndex{
		asOf: map[string]string{"1.21": "1.21.11"},
		// Only the raised constraint resolves: a stale "1.21" rebuild lookup
		// would error the evaluation and fail this test.
		available: map[string]string{"1.25": "1.25.4"},
	}
	scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
		"1.21.11": {stdlibVuln("GO-STD-1", scan.VulnerableImport{Path: "net/http"})},
		"1.25.4":  nil,
	}}
	stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true}, index, scanner)

	gp := newStdlibTestProcessor()
	gp.Config.Pipeline[1].With["go-package"] = "go-1.21" // the pristine pin
	gp.RaisedPinMinors = map[string]string{"1.21": "1.25"}

	require.NoError(t, stage.Apply(t.Context(), gp))

	require.Len(t, gp.StdlibBumps, 1)
	assert.Equal(t, "1.21.11", gp.StdlibBumps[0].AssumedGoVersion)
	assert.Equal(t, "1.21", gp.StdlibBumps[0].GoPackagePin)
	assert.Equal(t, "1.25", gp.StdlibBumps[0].RebuildGoPackagePin)
	assert.Equal(t, "1.25.4", gp.StdlibBumps[0].RebuildGoVersion)
	messagesContain(t, gp, "rebuilding with go1.25.4 (pin raised to 1.25) fixes GO-STD-1")
}

func TestStdlibStage_SkipGates(t *testing.T) {
	tests := []struct {
		name        string
		commitInfo  *git.FileCommitInfo
		commitErr   error
		wantMessage string
	}{
		{
			name:        "dirty file skips (idempotency guard)",
			commitInfo:  &git.FileCommitInfo{Time: stdlibCommitTime, Dirty: true},
			wantMessage: "uncommitted changes - skipping stdlib staleness check (a bump may already be pending)",
		},
		{
			name:        "untracked file skips",
			commitErr:   git.ErrUntracked,
			wantMessage: "no commit history - skipping stdlib staleness check",
		},
		{
			name:        "not in a repository skips",
			commitErr:   git.ErrNotInRepository,
			wantMessage: "not in a git repository - skipping stdlib staleness check",
		},
		{
			name:        "unexpected git error skips with warning",
			commitErr:   errors.New("index corrupt"),
			wantMessage: "could not determine the melange file's last commit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, scanner := staleIndex(), fixableScanner()
			stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true}, index, scanner)
			stage.lastCommit = func(context.Context, string) (*git.FileCommitInfo, error) {
				return tt.commitInfo, tt.commitErr
			}
			gp := newStdlibTestProcessor()

			require.NoError(t, stage.Apply(t.Context(), gp), "the stage must never fail the run")
			assert.Empty(t, gp.StdlibBumps)
			assert.False(t, gp.StdlibChecked)
			assert.Zero(t, index.asOfCalls, "skip must happen before any release lookup")
			messagesContain(t, gp, tt.wantMessage)
		})
	}
}

func TestStdlibStage_ShallowWarnsAndContinues(t *testing.T) {
	index, scanner := staleIndex(), fixableScanner()
	stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true}, index, scanner)
	stage.lastCommit = func(context.Context, string) (*git.FileCommitInfo, error) {
		return &git.FileCommitInfo{Time: stdlibCommitTime, Shallow: true}, nil
	}
	gp := newStdlibTestProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))
	require.Len(t, gp.StdlibBumps, 1, "shallow history warns but must not skip")
	messagesContain(t, gp, "repository history is shallow")
}

func TestStdlibStage_IndexFailureDegradesToSkip(t *testing.T) {
	index := &fakeReleaseIndex{asOfErr: errors.New("proxy unreachable")}
	stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true}, index, fixableScanner())
	gp := newStdlibTestProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp), "index failure must degrade, never error")
	assert.Empty(t, gp.StdlibBumps)
	assert.False(t, gp.StdlibChecked)
	messagesContain(t, gp, "staleness check unavailable")
	assert.Empty(t, gp.GetErrors())
}

func TestStdlibStage_NilIndexDegradesToSkip(t *testing.T) {
	stage := NewStdlibStage(nil, ProcessorOptions{StdlibCheck: true})
	stage.lastCommit = func(context.Context, string) (*git.FileCommitInfo, error) {
		t.Fatal("lastCommit must not be called without an index")
		return nil, nil
	}
	gp := newStdlibTestProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))
	assert.Empty(t, gp.StdlibBumps)
	messagesContain(t, gp, "release index/scanner unavailable")
}

func TestStdlibStage_ReusesSimulationLinkedSet(t *testing.T) {
	index, scanner := staleIndex(), fixableScanner()
	stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true, Validate: true}, index, scanner)
	linkStdCalls := 0
	stage.linkStd = func(context.Context, *GoBumpProcessor) (map[string]struct{}, error) {
		linkStdCalls++
		return nil, errors.New("unexpected clone")
	}
	gp := newStdlibTestProcessor()
	gp.LinkedStdPackages = map[string]struct{}{"net/http": {}} // simulation provided it

	require.NoError(t, stage.Apply(t.Context(), gp))

	assert.Zero(t, linkStdCalls, "no fallback clone when the simulation already provided the linked set")
	require.Len(t, gp.StdlibBumps, 1)
	assert.True(t, gp.StdlibBumps[0].Validated)
	assert.Equal(t, []string{"GO-STD-1"}, gp.StdlibBumps[0].VulnIDs)
}

func TestStdlibStage_FallbackCloneOnlyWhenFixableVulnsFound(t *testing.T) {
	t.Run("fixable vulns trigger the clone and filtering applies", func(t *testing.T) {
		index, scanner := staleIndex(), fixableScanner()
		stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true, Validate: true}, index, scanner)
		linkStdCalls := 0
		stage.linkStd = func(context.Context, *GoBumpProcessor) (map[string]struct{}, error) {
			linkStdCalls++
			return map[string]struct{}{"crypto/tls": {}}, nil // net/http NOT linked
		}
		gp := newStdlibTestProcessor()

		require.NoError(t, stage.Apply(t.Context(), gp))

		assert.Equal(t, 1, linkStdCalls)
		assert.Empty(t, gp.StdlibBumps, "the filtered re-evaluation demotes the unlinked finding")
		assert.True(t, gp.StdlibChecked)
		messagesContain(t, gp, "GO-STD-1")
		messagesContain(t, gp, "not linked into build artifacts")
	})

	t.Run("no fixable vulns - no clone", func(t *testing.T) {
		index := staleIndex()
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{}} // nothing anywhere
		stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true, Validate: true}, index, scanner)
		linkStdCalls := 0
		stage.linkStd = func(context.Context, *GoBumpProcessor) (map[string]struct{}, error) {
			linkStdCalls++
			return map[string]struct{}{"net/http": {}}, nil
		}
		gp := newStdlibTestProcessor()

		require.NoError(t, stage.Apply(t.Context(), gp))
		assert.Zero(t, linkStdCalls, "a pointless clone must be avoided")
		assert.True(t, gp.StdlibChecked)
	})

	t.Run("no-validate - no clone, unfiltered", func(t *testing.T) {
		index, scanner := staleIndex(), fixableScanner()
		stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true, Validate: false}, index, scanner)
		linkStdCalls := 0
		stage.linkStd = func(context.Context, *GoBumpProcessor) (map[string]struct{}, error) {
			linkStdCalls++
			return nil, nil
		}
		gp := newStdlibTestProcessor()

		require.NoError(t, stage.Apply(t.Context(), gp))
		assert.Zero(t, linkStdCalls)
		require.Len(t, gp.StdlibBumps, 1)
		assert.False(t, gp.StdlibBumps[0].Validated)
	})

	t.Run("clone failure fails open to unfiltered findings", func(t *testing.T) {
		index, scanner := staleIndex(), fixableScanner()
		stage := newStdlibTestStage(ProcessorOptions{StdlibCheck: true, Validate: true}, index, scanner)
		stage.linkStd = func(context.Context, *GoBumpProcessor) (map[string]struct{}, error) {
			return nil, errors.New("clone failed")
		}
		gp := newStdlibTestProcessor()

		require.NoError(t, stage.Apply(t.Context(), gp))
		require.Len(t, gp.StdlibBumps, 1, "unfiltered findings must stand when the clone fails")
		assert.False(t, gp.StdlibBumps[0].Validated)
		messagesContain(t, gp, "not filtered by artifact reachability")
	})
}

// TestSimulationStage_UnionsStdPackagesIntoProcessor: per-modroot linked
// stdlib sets from the simulation must union into gp.LinkedStdPackages for
// the stdlib stage to reuse (nil results contribute nothing).
func TestSimulationStage_UnionsStdPackagesIntoProcessor(t *testing.T) {
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot:          ".",
				FinalDeps:        []string{"example.com/old@v1.2.0"},
				CVEBackedModules: []string{"example.com/old"},
				Converged:        true, Iterations: 1,
				StdPackages: map[string]struct{}{"net/http": {}, "crypto/tls": {}},
			},
		},
	}
	stage := newStageWithFake(fake)
	gp := newSimulationProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))
	assert.Equal(t, map[string]struct{}{"net/http": {}, "crypto/tls": {}}, gp.LinkedStdPackages)
}

// TestSimulationStage_NilStdPackagesLeavesLinkedUnknown: an unknown stdlib
// slice must leave LinkedStdPackages nil (unknown), never an empty map
// ("nothing linked" would wrongly demote every stdlib finding).
func TestSimulationStage_NilStdPackagesLeavesLinkedUnknown(t *testing.T) {
	fake := &fakeBumpSimulator{
		results: map[string]*simulate.ModrootResult{
			".": {
				Modroot:          ".",
				FinalDeps:        []string{"example.com/old@v1.2.0"},
				CVEBackedModules: []string{"example.com/old"},
				Converged:        true, Iterations: 1,
			},
		},
	}
	stage := newStageWithFake(fake)
	gp := newSimulationProcessor()

	require.NoError(t, stage.Apply(t.Context(), gp))
	assert.Nil(t, gp.LinkedStdPackages)
}

// --- pipeline-level tests -------------------------------------------------

// stdlibPipelineYAML is a Go-building package with NO bump steps and (in the
// tests below) no dependency vulnerabilities: the stdlib staleness finding
// is the only reason to touch the file.
const stdlibPipelineYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 5

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/build
    with:
      packages: ./cmd/app
`

// blockedTransport fails every HTTP request: pipeline-level tests must never
// touch the network (the vulnerability check's manifest fetches fail fast
// and degrade, exactly like an offline run).
type blockedTransport struct{}

func (blockedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in tests")
}

// buildStdlibPipeline writes yamlContent to disk, builds the REAL production
// pipeline via NewGoBumpPipeline, re-seams its StdlibStage with fakes, and
// returns the pipeline plus a processor wired exactly as adapter.ProcessFile
// wires one.
func buildStdlibPipeline(t *testing.T, yamlContent string, opts ProcessorOptions) (*processor.Pipeline, *GoBumpProcessor, string) {
	t.Helper()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "example.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte(yamlContent), 0o644))

	cfg, err := melange.ParseConfiguration(t.Context(), filePath)
	require.NoError(t, err)

	gp := NewGoBumpProcessor(filePath, cfg.Package.Name, cfg.Package.Version, int64(cfg.Package.Epoch))
	gp.Config = cfg
	gp.OriginalYAML = []byte(yamlContent)
	gp.SetCurrentYAML([]byte(yamlContent))
	gp.SetOptions(processor.ProcessorOptions{DryRun: opts.DryRun, BackupSuffix: opts.BackupSuffix, TempDir: opts.TempDir})

	analyzer := NewAnalyzer(&http.Client{Transport: blockedTransport{}, Timeout: time.Second})
	pipeline := NewGoBumpPipeline(analyzer, opts)

	var seamed bool
	for _, stage := range pipeline.Stages {
		if stdlibStage, ok := stage.(*StdlibStage); ok {
			stdlibStage.index = staleIndex()
			stdlibStage.scanner = fixableScanner()
			stdlibStage.lastCommit = func(context.Context, string) (*git.FileCommitInfo, error) {
				return &git.FileCommitInfo{Time: stdlibCommitTime, Hash: "abc123"}, nil
			}
			stdlibStage.linkStd = func(context.Context, *GoBumpProcessor) (map[string]struct{}, error) {
				return nil, errors.New("no clone in tests")
			}
			seamed = true
		}
	}
	require.True(t, seamed, "NewGoBumpPipeline must contain a StdlibStage")

	return pipeline, gp, filePath
}

// TestPipeline_StdlibOnlyBumpsEpochAndWrites proves the critical end-to-end
// path: with ZERO dependency changes (no bump steps, no vulnerabilities, the
// applier skipped), a stdlib staleness finding alone must bump package.epoch
// in CurrentYAML and persist it to disk through the byte-inequality gate.
func TestPipeline_StdlibOnlyBumpsEpochAndWrites(t *testing.T) {
	opts := ProcessorOptions{StdlibCheck: true, Validate: false}
	pipeline, gp, filePath := buildStdlibPipeline(t, stdlibPipelineYAML, opts)

	require.NoError(t, pipeline.Execute(t.Context(), gp))

	// The stage fired and recorded its finding...
	require.Len(t, gp.StdlibBumps, 1)
	assert.Equal(t, []string{"GO-STD-1"}, gp.StdlibBumps[0].VulnIDs)
	assert.False(t, gp.ActualChangesApplied, "no dependency changes were applied")
	assert.Empty(t, gp.SecurityFixes)

	// ...the epoch stage bumped on it alone...
	assert.True(t, gp.IsEpochChanged())
	assert.Equal(t, int64(5), gp.OldEpoch)
	assert.Equal(t, int64(6), gp.GetNewEpoch())

	// ...and the file writer persisted it.
	written, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(written), "epoch: 6")
	assert.NotEqual(t, stdlibPipelineYAML, string(written))

	result := gp.ToResult()
	assert.True(t, result.EpochChanged)
	assert.True(t, result.FileWasWritten)
	assert.True(t, result.StdlibChecked)
	require.Len(t, result.StdlibBumps, 1)
}

// TestPipeline_StdlibDryRunRecordsIntentWithoutWriting covers the EpochStage
// DryRun branch: the intent is recorded but neither CurrentYAML nor the file
// on disk changes.
func TestPipeline_StdlibDryRunRecordsIntentWithoutWriting(t *testing.T) {
	opts := ProcessorOptions{StdlibCheck: true, Validate: false, DryRun: true}
	pipeline, gp, filePath := buildStdlibPipeline(t, stdlibPipelineYAML, opts)

	require.NoError(t, pipeline.Execute(t.Context(), gp))

	require.Len(t, gp.StdlibBumps, 1)
	assert.True(t, gp.IsEpochChanged(), "dry-run records the epoch intent")
	assert.Equal(t, int64(6), gp.GetNewEpoch())
	messagesContain(t, gp, "would update epoch: 5 -> 6")

	onDisk, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, stdlibPipelineYAML, string(onDisk), "dry run must not write")
	assert.False(t, gp.HasFileChanges(), "dry run must not touch CurrentYAML")
}

// TestPipeline_StdlibCheckDisabledNoBump: with the stage disabled nothing in
// the same no-dep-change package bumps the epoch or writes the file.
func TestPipeline_StdlibCheckDisabledNoBump(t *testing.T) {
	opts := ProcessorOptions{StdlibCheck: false, Validate: false}
	pipeline, gp, filePath := buildStdlibPipeline(t, stdlibPipelineYAML, opts)

	require.NoError(t, pipeline.Execute(t.Context(), gp))

	assert.Empty(t, gp.StdlibBumps)
	assert.False(t, gp.IsEpochChanged())
	onDisk, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, stdlibPipelineYAML, string(onDisk))
}

// TestEpochStage_SingleBumpWithDepAndStdlibFixes: when BOTH dependency
// security fixes and stdlib findings exist, the (single) epoch stage still
// bumps exactly once.
func TestEpochStage_SingleBumpWithDepAndStdlibFixes(t *testing.T) {
	opts := ProcessorOptions{StdlibCheck: true, Validate: false}
	pipeline, _, _ := buildStdlibPipeline(t, stdlibPipelineYAML, opts)

	var epochStage processor.Stage
	epochStages := 0
	for _, stage := range pipeline.Stages {
		if stage.Name() == "epoch" {
			epochStage = stage
			epochStages++
		}
	}
	require.Equal(t, 1, epochStages, "the pipeline must contain exactly one epoch stage")

	gp := newStdlibTestProcessor()
	gp.SetCurrentYAML([]byte(stdlibPipelineYAML))
	gp.OriginalYAML = []byte(stdlibPipelineYAML)
	gp.CurrentEpoch = 5
	gp.NewEpoch = 5
	gp.OldEpoch = 5
	gp.MarkActualChangesApplied()
	gp.AddSecurityFix(SecurityFix{Module: "example.com/old", Vulnerability: "GO-DEP-1", OldVersion: "v1.0.0", NewVersion: "v1.2.0"})
	gp.StdlibBumps = []StdlibBump{{AssumedGoVersion: "1.22.0", RebuildGoVersion: "1.24.5", VulnIDs: []string{"GO-STD-1"}}}

	shouldRun, err := epochStage.ShouldRun(t.Context(), gp)
	require.NoError(t, err)
	require.True(t, shouldRun)

	applier, ok := epochStage.(interface {
		Apply(context.Context, processor.Processor) error
	})
	require.True(t, ok)
	require.NoError(t, applier.Apply(t.Context(), gp))

	assert.Equal(t, int64(6), gp.GetNewEpoch(), "dep + stdlib fixes bump the epoch exactly once")
	assert.Contains(t, string(gp.GetCurrentYAML()), "epoch: 6")
}

// TestEpochTrigger_Gates pins the widened CheckFunc semantics via the real
// pipeline's epoch stage.
func TestEpochTrigger_Gates(t *testing.T) {
	opts := ProcessorOptions{StdlibCheck: true, Validate: false}
	pipeline, _, _ := buildStdlibPipeline(t, stdlibPipelineYAML, opts)

	var epochStage processor.Stage
	for _, stage := range pipeline.Stages {
		if stage.Name() == "epoch" {
			epochStage = stage
		}
	}
	require.NotNil(t, epochStage)

	tests := []struct {
		name    string
		mutate  func(*GoBumpProcessor)
		wantRun bool
	}{
		{"nothing at all", func(*GoBumpProcessor) {}, false},
		{"stdlib bump alone", func(gp *GoBumpProcessor) {
			gp.StdlibBumps = []StdlibBump{{VulnIDs: []string{"GO-STD-1"}}}
		}, true},
		{"security fixes without applied changes", func(gp *GoBumpProcessor) {
			gp.SecurityFixes = []SecurityFix{{Module: "m"}}
		}, false},
		{"applied changes without security fixes", func(gp *GoBumpProcessor) {
			gp.MarkActualChangesApplied()
		}, false},
		{"applied changes with security fixes", func(gp *GoBumpProcessor) {
			gp.MarkActualChangesApplied()
			gp.SecurityFixes = []SecurityFix{{Module: "m"}}
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gp := newStdlibTestProcessor()
			tt.mutate(gp)
			shouldRun, err := epochStage.ShouldRun(t.Context(), gp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantRun, shouldRun)
		})
	}
}
