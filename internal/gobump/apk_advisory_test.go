package gobump

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/assert"

	"github.com/isometry/choam/internal/scan"
)

// apkRecord is a CGA- advisory for pkg with the given fixed events, listed
// under both APK ecosystems like the real records.
func apkRecord(id string, upstream []string, fixed ...string) *osvschema.Vulnerability {
	events := []*osvschema.Event{{Introduced: "0"}}
	for _, f := range fixed {
		events = append(events, &osvschema.Event{Fixed: f})
	}
	rec := &osvschema.Vulnerability{Id: id, Upstream: upstream}
	for _, ecosystem := range apkEcosystems {
		rec.Affected = append(rec.Affected, &osvschema.Affected{
			Package: &osvschema.Package{Ecosystem: ecosystem, Name: "pkg"},
			Ranges:  []*osvschema.Range{{Type: osvschema.Range_ECOSYSTEM, Events: events}},
		})
	}
	return rec
}

func TestApkFixedEpoch(t *testing.T) {
	tests := []struct {
		name      string
		rec       *osvschema.Vulnerability
		epoch     int64
		wantN     int64
		wantOK    bool
		wantFixed string
	}{
		{"exact version match", apkRecord("CGA-1", nil, "3.6.0-r2"), 1, 2, true, "3.6.0-r2"},
		{"smallest N above the epoch", apkRecord("CGA-1", nil, "3.6.0-r1", "3.6.0-r4", "3.6.0-r3"), 1, 3, true, "3.6.0-r3"},
		{"near-miss version", apkRecord("CGA-1", nil, "3.6.0.1-r0"), 0, 0, false, "3.6.0.1-r0"},
		{"-r0 at epoch 0 is not above it", apkRecord("CGA-1", nil, "3.6.0-r0"), 0, 0, false, "3.6.0-r0"},
		{"other upstream version", apkRecord("CGA-1", nil, "3.7.0-r0"), 1, 0, false, "3.7.0-r0"},
		{"no fix", apkRecord("CGA-1", nil), 1, 0, false, ""},
		{"other package ignored", &osvschema.Vulnerability{Affected: []*osvschema.Affected{{
			Package: &osvschema.Package{Ecosystem: "Wolfi", Name: "other"},
			Ranges:  []*osvschema.Range{{Events: []*osvschema.Event{{Fixed: "3.6.0-r2"}}}},
		}}}, 1, 0, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, ok, fixed := apkFixedEpoch(tt.rec, "pkg", "3.6.0", tt.epoch)
			assert.Equal(t, tt.wantN, n)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantFixed, fixed)
		})
	}
}

func TestAliasExpand(t *testing.T) {
	got := aliasExpand([]string{"CVE-1", "CVE-2"}, map[string][]string{"CVE-1": {"GO-1", "GHSA-1"}})
	assert.Equal(t, idSet("CVE-1", "GO-1", "GHSA-1", "CVE-2"), got)
}

func idSet(ids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

func TestClassifyApk(t *testing.T) {
	aliases := map[string][]string{"CVE-A": {"GO-A"}, "CVE-B": {"GO-B"}}
	ev := apkEvidence{
		pristine: aliasExpand([]string{"CVE-A", "CVE-B", "CVE-C"}, aliases),
		fixed:    aliasExpand([]string{"CVE-A", "CVE-C"}, aliases),
		unfixed:  aliasExpand([]string{"CVE-C"}, aliases), // fixed in one module, residual in another
		stdlib:   idSet("GO-S"),
	}
	// dual is the evidence for a stdlib+module record (GO-D) whose CVE the
	// pristine scan found: fixed in the deps, optionally also still unfixed.
	dual := func(fixed, unfixed bool, remaining map[string]struct{}) apkEvidence {
		d := apkEvidence{pristine: idSet("CVE-D", "GO-D"), fixed: idSet(), unfixed: idSet(),
			stdlib: idSet("GO-D"), modules: idSet("GO-D"), stdlibRemaining: remaining}
		if fixed {
			d.fixed = idSet("CVE-D", "GO-D")
		}
		if unfixed {
			d.unfixed = idSet("CVE-D", "GO-D")
		}
		return d
	}
	tests := []struct {
		name     string
		upstream []string
		ev       apkEvidence
		want     string
	}{
		{"first-party", []string{"CVE-X", "GHSA-x"}, ev, apkFirstParty},
		{"alias hit is proven", []string{"GO-A"}, ev, apkProven},
		{"alias conflict is unproven", []string{"CVE-C"}, ev, apkUnproven},
		{"pristine but not fixed is unproven", []string{"GO-B"}, ev, apkUnproven},
		{"stdlib without proof", []string{"CVE-S", "GO-S"}, ev, apkUnproven},
		{"stdlib proven", []string{"CVE-S", "GO-S"}, apkEvidence{stdlib: ev.stdlib, stdlibRemaining: idSet("CVE-other")}, apkProven},
		{"stdlib still affected", []string{"CVE-S", "GO-S"}, apkEvidence{stdlib: ev.stdlib, stdlibRemaining: idSet("CVE-S")}, apkUnproven},
		{"module-only fixed", []string{"CVE-A"}, apkEvidence{pristine: ev.pristine, fixed: ev.fixed, modules: idSet("CVE-A")}, apkProven},

		// GO-D affects both the stdlib and a module (e.g. x/net).
		{"dual: both sides proven", []string{"CVE-D", "GO-D"}, dual(true, false, idSet()), apkProven},
		{"dual: module fixed, stdlib remaining", []string{"CVE-D", "GO-D"}, dual(true, false, idSet("CVE-D")), apkUnproven},
		{"dual: stdlib proven, module unfixed", []string{"CVE-D", "GO-D"}, dual(true, true, idSet()), apkUnproven},
		{"dual: module fixed, no stdlib proof", []string{"CVE-D", "GO-D"}, dual(true, false, nil), apkUnproven},
		{"dual: not in our graph - stdlib side only", []string{"CVE-D", "GO-D"}, apkEvidence{stdlib: idSet("GO-D"), modules: idSet("GO-D"), stdlibRemaining: idSet()}, apkProven},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classifyApk(tt.upstream, tt.ev))
		})
	}
}

// An unlinked advisory a hygiene bump cleared is proven: it stays
// unreachable (never a security fix) but moves from unfixed to fixed.
func TestApkDependencyEvidence_HygieneFixedIsProven(t *testing.T) {
	gp := NewProcessor("/t.yaml", "pkg", "3.6.0", 1)
	gp.Validated = true
	gp.ActualChangesApplied = true
	gp.VulnerabilityAnalysis = &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{{ByModroot: []ModrootAnalysis{{
		ScanResult: &scan.ScanResult{Vulnerabilities: []scan.Vulnerability{
			{ID: "CVE-H", Aliases: []string{"GO-H"}},
			{ID: "CVE-U"},
		}},
	}}}}}
	gp.AddUnreachableVulnIDs([]string{"CVE-H", "CVE-U"})
	gp.AddHygieneBump(SecurityFix{Module: "m", Vulnerability: "CVE-H"})

	ev := apkDependencyEvidence(gp)
	assert.Equal(t, apkProven, classifyApk([]string{"GO-H"}, ev))
	assert.Equal(t, apkUnproven, classifyApk([]string{"CVE-U"}, ev), "unlinked without a hygiene bump")
}

func TestApkEpochTarget(t *testing.T) {
	adv := func(status string, n int64) ApkAdvisory { return ApkAdvisory{Status: status, FixedEpoch: n} }
	tests := []struct {
		name string
		advs []ApkAdvisory
		want int64
	}{
		{"no proven advisories", []ApkAdvisory{adv(apkUnproven, 3)}, 0},
		{"proven r2, unproven r3", []ApkAdvisory{adv(apkProven, 2), adv(apkUnproven, 3)}, 2},
		{"proven r3 capped by first-party r2", []ApkAdvisory{adv(apkProven, 3), adv(apkFirstParty, 2)}, 1},
		{"proven r3, first-party r4", []ApkAdvisory{adv(apkProven, 3), adv(apkFirstParty, 4)}, 3},
		{"non-addressable ignored", []ApkAdvisory{adv(apkProven, 0), adv(apkFirstParty, 0)}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, apkEpochTarget(tt.advs))
		})
	}
}

func TestApkNewEpoch(t *testing.T) {
	gp := NewProcessor("/t.yaml", "pkg", "3.6.0", 1)
	assert.Equal(t, int64(1), apkNewEpoch(gp), "nothing fired")
	gp.ApkEpochTarget = 3
	assert.Equal(t, int64(3), apkNewEpoch(gp), "apk raise alone")
	gp.StdlibBumps = []StdlibBump{{RebuildGoVersion: "1.24.5"}}
	gp.ApkEpochTarget = 1 // capped at E
	assert.Equal(t, int64(2), apkNewEpoch(gp), "the ordinary bump still happens")
}
