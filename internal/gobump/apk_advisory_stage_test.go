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

// newApkTestProcessor is pkg 3.6.0 at epoch 1 whose validated analysis found
// CVE-A (fixed) and CVE-B (residual).
func newApkTestProcessor() *Processor {
	gp := NewProcessor("/t.yaml", "pkg", "3.6.0", 1)
	gp.Config = &melange.Configuration{}
	gp.Validated = true
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{{ByModroot: []ModrootAnalysis{{
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
	"GO-S":   goRecord("GO-S", "Go", "stdlib"),
	"GHSA-x": goRecord("GHSA-x", "Go", "github.com/example/pkg"),
	// GO-A2 (CVE-A again) affects both the stdlib and x/net, like GO-2026-6612.
	"GO-A2": {Id: "GO-A2", Affected: []*osvschema.Affected{
		{Package: &osvschema.Package{Ecosystem: "Go", Name: "stdlib"}},
		{Package: &osvschema.Package{Ecosystem: "Go", Name: "golang.org/x/net"}},
	}},
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
	residualR2 := apkRecord("CGA-b", []string{"CVE-B", "GO-B"}, "3.6.0-r2")
	stdlibR2 := apkRecord("CGA-s", []string{"CVE-S", "GO-S"}, "3.6.0-r2")
	run := func(t *testing.T, gp *Processor, scanner *fakeStdlibScanner, recs ...*osvschema.Vulnerability) *fakeApkSource {
		t.Helper()
		src := &fakeApkSource{byVersion: map[string][]*osvschema.Vulnerability{"3.6.0-r1": recs}, records: apkTestRecords}
		require.NoError(t, newApkTestStage(src, scanner).Apply(t.Context(), gp))
		return src
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

	t.Run("proven and residual at r2 - raise, with a will-hide note", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, provenR2, residualR2)
		assert.Equal(t, int64(2), gp.ApkEpochTarget)
		notesContain(t, gp, "apk: CVE-B (CGA-b) fixed by Chainguard in 3.6.0-r2, not proven fixed here (residual or unlinked) - raising the epoch will hide it")
	})

	t.Run("unproven alone - no raise, no note", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, residualR2)
		assert.Zero(t, gp.ApkEpochTarget)
		assert.Empty(t, gp.Notes)
		messagesContain(t, gp, "apk: CVE-B (CGA-b, fixed in 3.6.0-r2) not proven fixed here (residual or unlinked)")
	})

	t.Run("first-party at r2 holds a proven r3", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil,
			apkRecord("CGA-a", []string{"CVE-A", "GO-A"}, "3.6.0-r3"),
			apkRecord("CGA-x", []string{"CVE-X", "GHSA-x"}, "3.6.0-r2"))
		assert.Equal(t, int64(1), gp.ApkEpochTarget)
		assert.Equal(t, int64(1), apkNewEpoch(gp), "no raise past 1")
		assert.Equal(t, []string{"CVE-X"}, gp.FirstPartyVulnIDs)
		notesContain(t, gp, "ALERT apk: CVE-X (CGA-x, fixed in 3.6.0-r2) matches no dependency or stdlib advisory - possible first-party vulnerability (affects github.com/example/pkg); needs a patch, not a dependency bump; epoch held at 1")
	})

	t.Run("first-party fixed in another version - alert only", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil, provenR2, apkRecord("CGA-x", []string{"CVE-X"}, "3.7.0-r0"))
		assert.Equal(t, int64(2), gp.ApkEpochTarget, "no effect on the epoch")
		assert.Equal(t, []string{"CVE-X"}, gp.FirstPartyVulnIDs)
		notesContain(t, gp, "ALERT apk: CVE-X (CGA-x, fixed in 3.7.0-r0) matches no dependency or stdlib advisory")
		assert.NotContains(t, strings.Join(gp.Notes, "\n"), "epoch held")
	})

	t.Run("ordinary bump reaching a first-party fix says so", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.StdlibBumps = []StdlibBump{{RebuildGoVersion: "1.24.5"}}
		run(t, gp, nil, apkRecord("CGA-x", []string{"CVE-X"}, "3.6.0-r2"))
		assert.Equal(t, int64(2), apkNewEpoch(gp))
		notesContain(t, gp, "epoch 2 reaches -r2, so scanners will now treat it as fixed")
	})

	t.Run("pristine advisory fixed by an earlier run, unvalidated - unproven, never first-party", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.Validated = false
		gp.Residuals = nil
		run(t, gp, nil, apkRecord("CGA-a", []string{"GO-A"}, "3.6.0-r2"))
		require.Len(t, gp.ApkAdvisories, 1)
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status)
		assert.Empty(t, gp.FirstPartyVulnIDs)
		assert.Zero(t, gp.ApkEpochTarget)
	})

	t.Run("stdlib proven at the rebuild version", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{"1.24.5": {stdlibVuln("CVE-other")}}}
		run(t, gp, scanner, stdlibR2)
		assert.Equal(t, apkProven, gp.ApkAdvisories[0].Status)
		assert.Equal(t, []string{"1.24.5"}, scanner.scanned)
		assert.Equal(t, int64(2), gp.ApkEpochTarget)
	})

	t.Run("stdlib still affected at the rebuild version", func(t *testing.T) {
		gp := newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		vuln := stdlibVuln("CVE-S")
		vuln.Aliases = []string{"GO-S"}
		run(t, gp, &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{"1.24.5": {vuln}}}, stdlibR2)
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status)
		assert.Zero(t, gp.ApkEpochTarget)
		messagesContain(t, gp, "not proven fixed here (stdlib)")
	})

	t.Run("stdlib with the stdlib stage skipped", func(t *testing.T) {
		gp := newApkTestProcessor()
		scanner := &fakeStdlibScanner{}
		run(t, gp, scanner, stdlibR2)
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status)
		assert.Empty(t, scanner.scanned)
		assert.Empty(t, gp.FirstPartyVulnIDs)
	})

	t.Run("stdlib+module record needs both sides", func(t *testing.T) {
		dualR2 := apkRecord("CGA-d", []string{"CVE-A", "GO-A2"}, "3.6.0-r2")
		clean := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{}}

		gp := newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		run(t, gp, clean, dualR2)
		assert.Equal(t, apkProven, gp.ApkAdvisories[0].Status, "x/net fixed and stdlib clean")
		assert.Equal(t, []string{"golang.org/x/net", "stdlib"}, gp.ApkAdvisories[0].Modules)

		gp = newApkTestProcessor()
		gp.StdlibRebuildGoVersions = []string{"1.24.5"}
		gp.AddResiduals([]simulate.Residual{{Module: "golang.org/x/net", VulnIDs: []string{"CVE-A"}, Reason: "blocked"}})
		run(t, gp, clean, dualR2)
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status, "stdlib clean cannot prove a residual module")

		gp = newApkTestProcessor()
		run(t, gp, clean, dualR2)
		assert.Equal(t, apkUnproven, gp.ApkAdvisories[0].Status, "x/net fixed but no stdlib proof")
	})

	t.Run("one note per CVE and fix across both ecosystems' records", func(t *testing.T) {
		gp := newApkTestProcessor()
		run(t, gp, nil,
			apkRecord("CGA-b1", []string{"CVE-B"}, "3.6.0-r2"), apkRecord("CGA-b2", []string{"CVE-B"}, "3.6.0-r2"),
			apkRecord("CGA-x1", []string{"CVE-X"}, "3.7.0-r0"), apkRecord("CGA-x2", []string{"CVE-X"}, "3.7.0-r0"),
			provenR2)
		assert.Len(t, gp.Notes, 2, "one will-hide note, one ALERT: %v", gp.Notes)
		assert.Equal(t, []string{"CVE-X"}, gp.FirstPartyVulnIDs)
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
		messagesContain(t, gp, "apk: advisory check unavailable (boom) - skipping")
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
		gp := NewProcessor("/t.yaml", "pkg", "3.6.0", 1)
		gp.Config = &melange.Configuration{}
		gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{{ByModroot: []ModrootAnalysis{{ScanResult: &scan.ScanResult{}}}}}}
		src := &fakeApkSource{byVersion: map[string][]*osvschema.Vulnerability{"3.6.0-r1": {apkRecord("CGA-x", []string{"CVE-X"}, "3.6.0-r2")}}}
		require.NoError(t, newApkTestStage(src, &fakeStdlibScanner{}).Apply(t.Context(), gp))
		assert.Equal(t, []string{"CVE-X"}, gp.FirstPartyVulnIDs)
	})

	t.Run("no source - skip", func(t *testing.T) {
		gp := newApkTestProcessor()
		require.NoError(t, NewApkAdvisoryStage(nil, Options{ApkAdvisoryCheck: true}).Apply(t.Context(), gp))
		messagesContain(t, gp, "apk: advisory source unavailable")
	})
}
