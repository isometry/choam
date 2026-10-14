package gobump

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/assert"

	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
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
		name   string
		rec    *osvschema.Vulnerability
		epoch  int64
		wantN  int64
		wantOK bool
	}{
		{"exact version match", apkRecord("CGA-1", nil, "3.6.0-r2"), 1, 2, true},
		{"smallest N above the epoch", apkRecord("CGA-1", nil, "3.6.0-r1", "3.6.0-r4", "3.6.0-r3"), 1, 3, true},
		{"near-miss version", apkRecord("CGA-1", nil, "3.6.0.1-r0"), 0, 0, false},
		{"-r0 at epoch 0 is not above it", apkRecord("CGA-1", nil, "3.6.0-r0"), 0, 0, false},
		{"other upstream version", apkRecord("CGA-1", nil, "3.7.0-r0"), 1, 0, false},
		{"no fix", apkRecord("CGA-1", nil), 1, 0, false},
		{"other package ignored", &osvschema.Vulnerability{Affected: []*osvschema.Affected{{
			Package: &osvschema.Package{Ecosystem: "Wolfi", Name: "other"},
			Ranges:  []*osvschema.Range{{Events: []*osvschema.Event{{Fixed: "3.6.0-r2"}}}},
		}}}, 1, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, ok := apkFixedEpoch(tt.rec, "pkg", "3.6.0", tt.epoch)
			assert.Equal(t, tt.wantN, n)
			assert.Equal(t, tt.wantOK, ok)
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
	ev := apkEvidence{open: idSet("CVE-OPEN", "GO-OPEN")}
	proof := apkEvidence{open: ev.open, stdlibRemaining: idSet("CVE-STILL")}
	module := func(ids ...string) apkComponent {
		return apkComponent{kind: apkModule, ids: ids, module: "golang.org/x/net"}
	}
	stdlib := func(ids ...string) apkComponent { return apkComponent{kind: apkStdlib, ids: ids, module: "stdlib"} }
	tests := []struct {
		name       string
		components []apkComponent
		ev         apkEvidence
		want       string
		cause      string
	}{
		{"no record", nil, ev, apkUnproven, "no upstream advisory record"},
		{"root module", []apkComponent{module("CVE-1"), {kind: apkRoot, module: "example.com/self"}}, ev, apkFirstParty, "affects example.com/self, this package's own module"},
		{"module not open", []apkComponent{module("CVE-1", "GO-1")}, ev, apkProven, ""},
		{"module open via alias", []apkComponent{module("CVE-1", "GO-OPEN")}, ev, apkUnproven, "module golang.org/x/net residual, unlinked or not proven fixed"},
		{"module outside the graph", []apkComponent{{kind: apkOutside, module: "example.com/other"}}, ev, apkUnproven, "module example.com/other not in the analysed graph"},
		{"stdlib without proof", []apkComponent{stdlib("CVE-1")}, ev, apkUnproven, "stdlib: no rebuild Go version recorded, rerun on a clean tree"},
		{"stdlib proven", []apkComponent{stdlib("CVE-1")}, proof, apkProven, ""},
		{"stdlib still affected", []apkComponent{stdlib("CVE-STILL")}, proof, apkUnproven, "stdlib: still affected at the rebuild Go version"},
		{"stdlib proven, empty remaining", []apkComponent{stdlib("CVE-1")}, apkEvidence{stdlibRemaining: idSet()}, apkProven, ""},

		// A stdlib+module record (e.g. stdlib and x/net) needs both sides.
		{"dual: both proven", []apkComponent{stdlib("CVE-1"), module("CVE-1")}, proof, apkProven, ""},
		{"dual: module open", []apkComponent{stdlib("CVE-OPEN"), module("CVE-OPEN")}, proof, apkUnproven, "module golang.org/x/net residual, unlinked or not proven fixed"},
		{"dual: stdlib remaining", []apkComponent{stdlib("CVE-STILL"), module("CVE-STILL")}, proof, apkUnproven, "stdlib: still affected at the rebuild Go version"},
		{"dual: no stdlib proof", []apkComponent{module("CVE-1"), stdlib("CVE-1")}, ev, apkUnproven, "stdlib: no rebuild Go version recorded, rerun on a clean tree"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, cause := classifyApk(tt.components, tt.ev)
			assert.Equal(t, tt.want, status)
			assert.Equal(t, tt.cause, cause)
		})
	}
}

// OPEN: residuals, unlinked advisories no hygiene bump cleared, and pristine
// advisories not proven fixed (alias-expanded); a hygiene-bumped one is not.
func TestApkDependencyEvidence(t *testing.T) {
	analysis := func() *VulnerabilityAnalysis {
		return &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{{ByModroot: []ModrootAnalysis{{
			ScanResult: &scan.ScanResult{Vulnerabilities: []scan.Vulnerability{
				{ID: "CVE-F", Aliases: []string{"GO-F"}, FixedVersion: "1.0.1"},
				{ID: "CVE-H", Aliases: []string{"GO-H"}, FixedVersion: "1.0.1"},
				{ID: "CVE-U", FixedVersion: "1.0.1"},
				{ID: "CVE-R", Aliases: []string{"GO-R"}, FixedVersion: "1.0.1"},
			}},
		}}}}}
	}

	gp := NewProcessor("/t.yaml", "pkg", "3.6.0", 1)
	gp.Validated = true
	gp.ActualChangesApplied = true
	gp.VulnerabilityAnalysis = analysis()
	gp.AddUnreachableVulnIDs([]string{"CVE-H", "CVE-U"})
	gp.AddHygieneBump(SecurityFix{Module: "m", Vulnerability: "CVE-H"})
	gp.AddResiduals([]simulate.Residual{{Module: "r", VulnIDs: []string{"CVE-R"}, Reason: "blocked"}})
	assert.Equal(t, idSet("CVE-U", "CVE-R", "GO-R"), apkDependencyEvidence(gp).open)

	// --no-validate: a pristine advisory no SecurityFix of this run names
	// (e.g. fixed by an earlier run) stays open - the safe direction.
	gp = NewProcessor("/t.yaml", "pkg", "3.6.0", 1)
	gp.VulnerabilityAnalysis = analysis()
	gp.ActualChangesApplied = true
	gp.AddSecurityFix(SecurityFix{Module: "m", Vulnerability: "CVE-F"})
	open := apkDependencyEvidence(gp).open
	assert.NotContains(t, open, "GO-F")
	assert.Contains(t, open, "GO-H")
}

func TestApkEpochTarget(t *testing.T) {
	adv := func(status string, n int64) ApkAdvisory { return ApkAdvisory{Status: status, FixedEpoch: n} }
	tests := []struct {
		name string
		advs []ApkAdvisory
		want int64
	}{
		{"none proven", []ApkAdvisory{adv(apkUnproven, 3)}, 0},
		{"r5 unproven blocks r7 proven", []ApkAdvisory{adv(apkUnproven, 5), adv(apkProven, 7)}, 0},
		{"r5 proven, r7 unproven", []ApkAdvisory{adv(apkProven, 5), adv(apkUnproven, 7)}, 5},
		{"r6 proven, r9 first-party", []ApkAdvisory{adv(apkProven, 6), adv(apkFirstParty, 9)}, 6},
		{"r6 and r7 proven, r9 unproven", []ApkAdvisory{adv(apkProven, 7), adv(apkUnproven, 9), adv(apkProven, 6)}, 7},
		{"same N proven and unproven", []ApkAdvisory{adv(apkProven, 2), adv(apkUnproven, 2)}, 0},
		{"all proven", []ApkAdvisory{adv(apkProven, 2), adv(apkProven, 4)}, 4},
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
