package gobump

import (
	"context"
	"errors"
	"strings"
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/isometry/choam/internal/ecosystem"
	ecogolang "github.com/isometry/choam/internal/ecosystem/golang"
	"github.com/isometry/choam/internal/git"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
)

// fakeApkSource serves canned CGA- records per queried version and upstream
// records by ID (a missing ID is a 404).
type fakeApkSource struct {
	byVersion map[string][]*osvschema.Vulnerability
	records   map[string]*osvschema.Vulnerability
	err       error
	recordErr error
	queried   []scan.Package
}

func (f *fakeApkSource) Advisories(_ context.Context, pkgs []scan.Package) ([]*osvschema.Vulnerability, error) {
	f.queried = append(f.queried, pkgs...)
	if f.err != nil {
		return nil, f.err
	}
	return f.byVersion[pkgs[0].Version], nil
}

func (f *fakeApkSource) Advisory(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	if f.recordErr != nil {
		return nil, f.recordErr
	}
	return f.records[id], nil
}

func goRecord(id, ecosystem, module string) *osvschema.Vulnerability {
	return &osvschema.Vulnerability{Id: id, Affected: []*osvschema.Affected{{Package: &osvschema.Package{Ecosystem: ecosystem, Name: module}}}}
}

func newApkTestStage(src *fakeApkSource, scanner simulate.Scanner) *ApkAdvisoryStage {
	stage := NewApkAdvisoryStage(nil, Options{ApkAdvisoryCheck: true})
	stage.advisories = src
	stage.scanner = scanner
	return stage
}

// newApkTestProcessor is pkg 3.6.0 at epoch 1 (main module
// github.com/example/self) whose validated analysis scanned x/net, grpc and
// example.com/b and found CVE-A (x/net, fixed) and CVE-B (example.com/b,
// residual).
func newApkTestProcessor() *Processor {
	gp := NewProcessor("/t.yaml", "pkg", "3.6.0", 1)
	gp.Config = &melange.Configuration{}
	gp.Validated = true
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{{ByModroot: []ModrootAnalysis{{
		Deps: &ecosystem.ModuleDeps{Raw: &ecogolang.GoModInfo{ModFile: &modfile.File{Module: &modfile.Module{Mod: module.Version{Path: "github.com/example/self"}}}}},
		ScannedPackages: []scan.Package{
			{Name: "golang.org/x/net", Ecosystem: "Go", Version: "0.50.0"},
			{Name: "google.golang.org/grpc", Ecosystem: "Go", Version: "1.83.2"},
			{Name: "example.com/b", Ecosystem: "Go", Version: "1.0.0"},
		},
		ScanResult: &scan.ScanResult{Vulnerabilities: []scan.Vulnerability{
			{ID: "CVE-A", Aliases: []string{"GO-A", "GHSA-a"}},
			{ID: "CVE-B", Aliases: []string{"GO-B"}},
		}},
	}}}}}
	gp.AddResiduals([]simulate.Residual{{Module: "example.com/b", VulnIDs: []string{"CVE-B"}, Reason: "no released fix"}})
	return gp
}

func notesContain(t *testing.T, gp *Processor, want string) {
	t.Helper()
	for _, note := range gp.Notes {
		if strings.Contains(note, want) {
			return
		}
	}
	t.Errorf("expected a note containing %q, got %v", want, gp.Notes)
}

var apkTestRecords = map[string]*osvschema.Vulnerability{
	"GO-A":   goRecord("GO-A", "Go", "golang.org/x/net"),
	"GO-B":   goRecord("GO-B", "Go", "example.com/b"),
	"GO-S":   goRecord("GO-S", "Go", "stdlib"),
	"GO-M":   goRecord("GO-M", "Go", "github.com/example/self"),
	"GHSA-x": goRecord("GHSA-x", "Go", "github.com/example/pkg"),
	// tofu-controller shape: grpc advisories (one GO-, one GHSA-only) that
	// the shipped grpc version is already past.
	"GO-G6":   goRecord("GO-G6", "Go", "google.golang.org/grpc"),
	"GHSA-g7": goRecord("GHSA-g7", "Go", "google.golang.org/grpc"),
	// Stdlib+module records, like GO-2026-6612: GO-A2 is CVE-A again (x/net
	// fixed), GO-N9 a CVE the pristine scan never flagged.
	"GO-A2": dualRecord("GO-A2", "golang.org/x/net"),
	"GO-N9": dualRecord("GO-N9", "golang.org/x/net"),
}

func dualRecord(id, module string) *osvschema.Vulnerability {
	return &osvschema.Vulnerability{Id: id, Affected: []*osvschema.Affected{
		{Package: &osvschema.Package{Ecosystem: "Go", Name: "stdlib"}},
		{Package: &osvschema.Package{Ecosystem: "Go", Name: module}},
	}}
}

func TestApkAdvisoryStage_ShouldRun(t *testing.T) {
	gp := newApkTestProcessor()
	ok, err := NewApkAdvisoryStage(nil, Options{}).ShouldRun(t.Context(), gp)
	require.NoError(t, err)
	assert.False(t, ok, "off unless enabled")

	ok, err = newApkTestStage(&fakeApkSource{}, nil).ShouldRun(t.Context(), gp)
	require.NoError(t, err)
	assert.True(t, ok)

	gp.Config = nil
	ok, err = newApkTestStage(&fakeApkSource{}, nil).ShouldRun(t.Context(), gp)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestApkAdvisoryStage_Apply(t *testing.T) {
	provenR2 := apkRecord("CGA-a", []string{"CVE-A", "GO-A"}, "3.6.0-r2")
	run := func(t *testing.T, gp *Processor, scanner *fakeStdlibScanner, recs ...*osvschema.Vulnerability) *fakeApkSource {
		t.Helper()
		src := &fakeApkSource{byVersion: map[string][]*osvschema.Vulnerability{"3.6.0-r1": recs}, records: apkTestRecords}
		require.NoError(t, newApkTestStage(src, scanner).Apply(t.Context(), gp))
		return src
	}
	clean := func() *fakeStdlibScanner {
		return &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{}}
	}

	t.Run("proven raise", func(t *testing.T) {
		gp := newApkTestProcessor()
		src := run(t, gp, nil, provenR2)
		assert.Equal(t, []scan.Package{
			{Name: "pkg", Ecosystem: "Wolfi", Version: "3.6.0-r1"},
			{Name: "pkg", Ecosystem: "Chainguard", Version: "3.6.0-r1"},
		}, src.queried)
		require.Len(t, gp.ApkAdvisories, 1)
		assert.Equal(t, ApkAdvisory{ID: "CGA-a", Upstream: []string{"CVE-A", "GO-A"}, FixedVersion: "3.6.0-r2", FixedEpoch: 2, Status: apkProven, Modules: []string{"golang.org/x/net"}}, gp.ApkAdvisories[0])
		assert.Equal(t, int64(2), gp.ApkEpochTarget)
		assert.Equal(t, int64(2), apkNewEpoch(gp))
		assert.Empty(t, gp.Notes)
		messagesContain(t, gp, "apk: CVE-A (CGA-a, fixed in 3.6.0-r2) proven fixed here")
	})

	t.Run("tofu-controller shape: grpc r6/r7 proven, r9 stdlib+x/net without stdlib proof", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil,
			apkRecord("CGA-g6", []string{"CVE-G6", "GO-G6"}, "3.6.0-r6"),
			apkRecord("CGA-g7", []string{"CVE-G7", "GHSA-g7"}, "3.6.0-r7"),
			apkRecord("CGA-n9", []string{"CVE-N9", "GO-N9"}, "3.6.0-r9"))
		statuses := map[string]string{}
		for _, adv := range gp.ApkAdvisories {
			statuses[adv.ID] = adv.Status
		}
		assert.Equal(t, map[string]string{"CGA-g6": apkProven, "CGA-g7": apkProven, "CGA-n9": apkUnproven}, statuses)
		assert.Equal(t, int64(7), gp.ApkEpochTarget)
		assert.Empty(t, gp.FirstPartyVulnIDs, "no PATCH-NEEDED")
		assert.Empty(t, gp.Notes, "r9 sits above every proven advisory")
		messagesContain(t, gp, "apk: CVE-N9 (CGA-n9, fixed in 3.6.0-r9) not proven fixed here ("+apkCauseNoRebuildToolchain+")")
	})

	t.Run("tofu-controller shape on a dirty file: the rebuild toolchain proves r9", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.Config = stdlibTestConfig()
		stdlib := newStdlibTestStage(Options{StdlibCheck: true}, staleIndex(), fixableScanner())
		stdlib.lastCommit = func(context.Context, string) (*git.FileCommitInfo, error) {
			return &git.FileCommitInfo{Time: stdlibCommitTime, Dirty: true}, nil
		}
		require.NoError(t, stdlib.Apply(t.Context(), gp))
		require.Empty(t, gp.StdlibBumps, "the staleness trigger is skipped on a dirty file")

		run(t, gp, clean(),
			apkRecord("CGA-g6", []string{"CVE-G6", "GO-G6"}, "3.6.0-r6"),
			apkRecord("CGA-g7", []string{"CVE-G7", "GHSA-g7"}, "3.6.0-r7"),
			apkRecord("CGA-n9", []string{"CVE-N9", "GO-N9"}, "3.6.0-r9"))
		assert.Equal(t, int64(9), gp.ApkEpochTarget)
		assert.Equal(t, int64(9), apkNewEpoch(gp))
	})

	t.Run("non-proven below a proven advisory holds the epoch, with a note", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, apkRecord("CGA-b", []string{"CVE-B", "GO-B"}, "3.6.0-r2"), apkRecord("CGA-a", []string{"CVE-A", "GO-A"}, "3.6.0-r3"))
		assert.Zero(t, gp.ApkEpochTarget)
		notesContain(t, gp, "apk: CVE-B (CGA-b, fixed in 3.6.0-r2) not proven fixed here (module example.com/b residual, unlinked or not proven fixed) - holds the epoch below -r2")
	})

	t.Run("non-proven above every proven one - no note", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, provenR2, apkRecord("CGA-b", []string{"CVE-B", "GO-B"}, "3.6.0-r3"))
		assert.Equal(t, int64(2), gp.ApkEpochTarget)
		assert.Empty(t, gp.Notes)
		messagesContain(t, gp, "apk: CVE-B (CGA-b, fixed in 3.6.0-r3) not proven fixed here")
	})

	t.Run("ordinary bump reaching a non-proven fix says so", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.StdlibBumps = []StdlibBump{{RebuildGoVersion: "1.24.5"}}
		run(t, gp, nil, apkRecord("CGA-b", []string{"CVE-B", "GO-B"}, "3.6.0-r2"))
		assert.Equal(t, int64(2), apkNewEpoch(gp))
		notesContain(t, gp, "epoch 2 reaches -r2 anyway, hiding it from distro-aware scanners")
	})

	t.Run("root-module record - first-party, holds the epoch", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, apkRecord("CGA-m", []string{"CVE-M", "GO-M"}, "3.6.0-r2"), apkRecord("CGA-a", []string{"CVE-A", "GO-A"}, "3.6.0-r3"))
		assert.Equal(t, []string{"CVE-M"}, gp.FirstPartyVulnIDs)
		assert.Zero(t, gp.ApkEpochTarget)
		notesContain(t, gp, "ALERT apk: CVE-M (CGA-m, fixed in 3.6.0-r2) affects github.com/example/self, this package's own module - possible first-party vulnerability; needs a patch, not a dependency bump; holds the epoch below -r2")
	})

	t.Run("module not in the graph - unproven with its reason", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, apkRecord("CGA-x", []string{"CVE-X", "GHSA-x"}, "3.6.0-r2"), apkRecord("CGA-a", []string{"CVE-A", "GO-A"}, "3.6.0-r3"))
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status)
		assert.Empty(t, gp.FirstPartyVulnIDs)
		notesContain(t, gp, "not proven fixed here (module github.com/example/pkg not in the analysed graph) - holds the epoch below -r2")
	})

	t.Run("no fetchable record - unproven", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, apkRecord("CGA-n", []string{"CVE-N", "GO-N"}, "3.6.0-r2"))
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status)
		assert.Equal(t, "no upstream advisory record", gp.ApkAdvisories[0].Reason)
		assert.Empty(t, gp.FirstPartyVulnIDs)
	})

	t.Run("no-fix and upstream-less advisories are dropped", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil,
			apkRecord("CGA-fhrf-8h3x-58xh", []string{"GO-2026-5932"}), apkRecord("CGA-35h6-p7r4-47jm", []string{"GO-2026-5932"}),
			apkRecord("CGA-u", nil, "3.6.0-r2"))
		assert.Empty(t, gp.ApkAdvisories)
		assert.Empty(t, gp.Notes)
		assert.Zero(t, gp.ApkEpochTarget)
		messagesContain(t, gp, "apk: 2 advisories with no fix at 3.6.0-r<N> (no fix, or fixed in another version) - ignored")
		messagesContain(t, gp, "apk: 1 advisory without an upstream CVE/GHSA/GO ID, cannot correlate - ignored")
	})

	t.Run("display ID from upstream only", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, apkRecord("CGA-a", []string{"GO-A"}, "3.6.0-r2"), apkRecord("CGA-a2", []string{"GHSA-a", "GO-A", "CVE-A"}, "3.6.0-r3"))
		messagesContain(t, gp, "apk: GO-A (CGA-a, fixed in 3.6.0-r2)")
		messagesContain(t, gp, "apk: CVE-A (CGA-a2, fixed in 3.6.0-r3)")
	})

	t.Run("pristine advisory fixed by an earlier run, unvalidated - unproven, never first-party", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.Validated = false
		gp.Residuals = nil
		run(t, gp, nil, apkRecord("CGA-a", []string{"GO-A"}, "3.6.0-r2"))
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status)
		assert.Empty(t, gp.FirstPartyVulnIDs)
		assert.Zero(t, gp.ApkEpochTarget)
	})

	t.Run("stdlib proven at the rebuild version", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{"1.24.5": {stdlibVuln("CVE-other")}}}
		run(t, gp, scanner, apkRecord("CGA-s", []string{"CVE-S", "GO-S"}, "3.6.0-r2"))
		assert.Equal(t, apkProven, gp.ApkAdvisories[0].Status)
		assert.Equal(t, []string{"1.24.5"}, scanner.scanned)
		assert.Equal(t, int64(2), gp.ApkEpochTarget)
	})

	t.Run("stdlib still affected at the rebuild version", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		vuln := stdlibVuln("CVE-S")
		vuln.Aliases = []string{"GO-S"}
		run(t, gp, &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{"1.24.5": {vuln}}}, apkRecord("CGA-s", []string{"CVE-S", "GO-S"}, "3.6.0-r2"))
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status)
		assert.Zero(t, gp.ApkEpochTarget)
	})

	t.Run("stdlib with the stdlib stage skipped - no scan", func(t *testing.T) {
		gp := newApkTestProcessor()
		scanner := &fakeStdlibScanner{}
		run(t, gp, scanner, apkRecord("CGA-s", []string{"CVE-S", "GO-S"}, "3.6.0-r2"))
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status)
		assert.Empty(t, scanner.scanned)
	})

	t.Run("stdlib+module record needs both sides", func(t *testing.T) {
		dualR2 := apkRecord("CGA-d", []string{"CVE-A", "GO-A2"}, "3.6.0-r2")

		gp := newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		run(t, gp, clean(), dualR2)
		assert.Equal(t, apkProven, gp.ApkAdvisories[0].Status, "x/net fixed and stdlib clean")
		assert.Equal(t, []string{"golang.org/x/net", "stdlib"}, gp.ApkAdvisories[0].Modules)

		gp = newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		gp.AddResiduals([]simulate.Residual{{Module: "golang.org/x/net", VulnIDs: []string{"CVE-A"}, Reason: "blocked"}})
		run(t, gp, clean(), dualR2)
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status, "stdlib clean cannot prove a residual module")

		gp = newApkTestProcessor()
		run(t, gp, clean(), dualR2)
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status, "x/net fixed but no stdlib proof")

		gp = newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		run(t, gp, clean(), apkRecord("CGA-n9", []string{"CVE-N9", "GO-N9"}, "3.6.0-r2"))
		assert.Equal(t, apkProven, gp.ApkAdvisories[0].Status, "x/net present and never affected, stdlib clean")
	})

	t.Run("one note per CVE and fix across both ecosystems' records", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil,
			apkRecord("CGA-b1", []string{"CVE-B", "GO-B"}, "3.6.0-r2"), apkRecord("CGA-b2", []string{"CVE-B", "GO-B"}, "3.6.0-r2"),
			apkRecord("CGA-m1", []string{"CVE-M", "GO-M"}, "3.6.0-r2"), apkRecord("CGA-m2", []string{"CVE-M", "GO-M"}, "3.6.0-r2"),
			apkRecord("CGA-a", []string{"CVE-A", "GO-A"}, "3.6.0-r3"))
		assert.Len(t, gp.Notes, 2, "one blocker note, one ALERT: %v", gp.Notes)
		assert.Equal(t, []string{"CVE-M"}, gp.FirstPartyVulnIDs)
		assert.Len(t, gp.ApkAdvisories, 5, "every record is still reported")
	})

	t.Run("idempotent at the target", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.CurrentEpoch = 2
		src := run(t, gp, nil, provenR2) // only served at -r1
		assert.Equal(t, "3.6.0-r2", src.queried[0].Version)
		assert.Empty(t, gp.ApkAdvisories)
		assert.Zero(t, gp.ApkEpochTarget)
	})
}

func TestApkAdvisoryStage_Failures(t *testing.T) {
	rec := apkRecord("CGA-a", []string{"CVE-A", "GO-A"}, "3.6.0-r2")

	t.Run("OSV error - skip, no raise", func(t *testing.T) {
		gp := newApkTestProcessor()
		require.NoError(t, newApkTestStage(&fakeApkSource{err: errors.New("boom")}, &fakeStdlibScanner{}).Apply(t.Context(), gp))
		assert.Zero(t, gp.ApkEpochTarget)
		notesContain(t, gp, "apk: advisory check unavailable (boom) - skipping")
	})

	t.Run("upstream record error - skip, no raise", func(t *testing.T) {
		gp := newApkTestProcessor()
		src := &fakeApkSource{byVersion: map[string][]*osvschema.Vulnerability{"3.6.0-r1": {rec}}, recordErr: errors.New("boom")}
		require.NoError(t, newApkTestStage(src, &fakeStdlibScanner{}).Apply(t.Context(), gp))
		assert.Zero(t, gp.ApkEpochTarget)
		assert.Empty(t, gp.ApkAdvisories)
	})

	t.Run("cancellation propagates", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		err := newApkTestStage(&fakeApkSource{err: context.Canceled}, &fakeStdlibScanner{}).Apply(ctx, newApkTestProcessor())
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("no complete dependency analysis - skip, no alerts", func(t *testing.T) {
		for name, mutate := range map[string]func(*Processor){
			"not bumpable":   func(gp *Processor) { gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{} },
			"no analysis":    func(gp *Processor) { gp.VulnerabilityAnalysis = nil },
			"skipped part":   func(gp *Processor) { gp.Skip(t.Context(), "gradle: unsupported") },
			"unscanned root": func(gp *Processor) { gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0].ScanResult = nil },
		} {
			t.Run(name, func(t *testing.T) {
				gp := newApkTestProcessor()
				mutate(gp)
				src := &fakeApkSource{byVersion: map[string][]*osvschema.Vulnerability{"3.6.0-r1": {apkRecord("CGA-x", []string{"CVE-X"}, "3.6.0-r2")}}}
				require.NoError(t, newApkTestStage(src, &fakeStdlibScanner{}).Apply(t.Context(), gp))
				assert.Empty(t, src.queried, "no network")
				assert.Empty(t, gp.FirstPartyVulnIDs)
				assert.Empty(t, gp.Notes)
				assert.Zero(t, gp.ApkEpochTarget)
				messagesContain(t, gp, "apk: no complete dependency analysis was performed - skipping")
			})
		}
	})

	t.Run("analysed project with zero vulnerabilities still alerts", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.Residuals = nil
		gp.VulnerabilityAnalysis.ByLanguage[0].ByModroot[0].ScanResult = &scan.ScanResult{}
		src := &fakeApkSource{byVersion: map[string][]*osvschema.Vulnerability{"3.6.0-r1": {apkRecord("CGA-m", []string{"CVE-M", "GO-M"}, "3.6.0-r2")}}, records: apkTestRecords}
		require.NoError(t, newApkTestStage(src, &fakeStdlibScanner{}).Apply(t.Context(), gp))
		assert.Equal(t, []string{"CVE-M"}, gp.FirstPartyVulnIDs)
	})

	t.Run("no source - skip", func(t *testing.T) {
		gp := newApkTestProcessor()
		require.NoError(t, NewApkAdvisoryStage(nil, Options{ApkAdvisoryCheck: true}).Apply(t.Context(), gp))
		notesContain(t, gp, "apk: advisory source unavailable")
	})
}
