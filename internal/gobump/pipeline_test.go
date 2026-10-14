package gobump

import (
	"strings"
	"testing"

	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
	"github.com/stretchr/testify/assert"
)

// epochComment composes the inline intent comment on the epoch line: clause
// per trigger, advisories most-critical-first, truncated at epochCommentMaxIDs.
func TestEpochComment(t *testing.T) {
	analysisWith := func(vulns ...scan.Vulnerability) *VulnerabilityAnalysis {
		return &VulnerabilityAnalysis{
			ByLanguage: []LanguageAnalysis{{
				Language: "go",
				ByModroot: []ModrootAnalysis{{
					Modroot:    ".",
					ScanResult: &scan.ScanResult{Vulnerabilities: vulns},
				}},
			}},
		}
	}

	t.Run("deps only, severity ordered", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ActualChangesApplied = true
		gp.Validated = true
		gp.AddSecurityFix(SecurityFix{Module: "m", Vulnerability: "GHSA-crit, GO-2026-0002"})
		gp.VulnerabilityAnalysis = analysisWith(
			scan.Vulnerability{ID: "GO-2026-0002"},
			scan.Vulnerability{ID: "GHSA-high", Severity: "HIGH"},
			scan.Vulnerability{ID: "GHSA-crit", Severity: "CRITICAL"},
		)
		assert.Equal(t, "updated bumps; fixes: GHSA-crit, GHSA-high, GO-2026-0002", epochComment(gp))
	})

	t.Run("validated set excludes residual and unreachable IDs", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ActualChangesApplied = true
		gp.Validated = true
		gp.AddSecurityFix(SecurityFix{Module: "m", Vulnerability: "GHSA-fixed"})
		gp.VulnerabilityAnalysis = analysisWith(
			scan.Vulnerability{ID: "GHSA-fixed", Severity: "HIGH"},
			scan.Vulnerability{ID: "GHSA-residual", Severity: "CRITICAL"},
			scan.Vulnerability{ID: "GHSA-unlinked", Severity: "CRITICAL"},
		)
		gp.AddResiduals([]simulate.Residual{{Module: "m", VulnIDs: []string{"GHSA-residual"}, Reason: "no released fix"}})
		gp.AddUnreachableVulnIDs([]string{"GHSA-unlinked"})
		assert.Equal(t, "updated bumps; fixes: GHSA-fixed", epochComment(gp))
	})

	t.Run("stdlib only", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.StdlibBumps = []StdlibBump{{
			RebuildGoVersion: "1.26.5",
			VulnIDs:          []string{"GO-2026-4970", "GO-2026-5856"},
		}}
		assert.Equal(t, "rebuild with go1.26.5; fixes: GO-2026-4970, GO-2026-5856", epochComment(gp))
	})

	t.Run("combined merges into one deduped list", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ActualChangesApplied = true
		gp.Validated = true
		gp.AddSecurityFix(SecurityFix{Module: "m", Vulnerability: "CVE-2026-0001"})
		gp.VulnerabilityAnalysis = analysisWith(scan.Vulnerability{ID: "CVE-2026-0001", Severity: "CRITICAL", Aliases: []string{"GHSA-crit", "GO-2026-0001"}})
		gp.StdlibBumps = []StdlibBump{{RebuildGoVersion: "1.26.5", VulnIDs: []string{"GO-2026-4970"}}}
		assert.Equal(t, "updated bumps, rebuild with go1.26.5; fixes: CVE-2026-0001, GO-2026-4970", epochComment(gp))
	})

	apkProvenAt := func(n int64, upstream ...string) ApkAdvisory {
		return ApkAdvisory{ID: "CGA-" + upstream[0], Upstream: upstream, FixedEpoch: n, Status: apkProven}
	}

	t.Run("apk only, CVE first", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ApkEpochTarget = 2
		gp.ApkAdvisories = []ApkAdvisory{
			apkProvenAt(2, "GO-2026-0001", "CVE-2026-0002", "GHSA-xxxx"),
			apkProvenAt(3, "CVE-2026-0003"), // beyond the (capped) target
			{ID: "CGA-u", Upstream: []string{"CVE-2026-0004"}, FixedEpoch: 2, Status: apkUnproven},
		}
		assert.Equal(t, "align with chainguard apk -r2; apk: CVE-2026-0002", epochComment(gp))
	})

	t.Run("apk + deps", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ActualChangesApplied = true
		gp.Validated = true
		gp.AddSecurityFix(SecurityFix{Module: "m", Vulnerability: "CVE-2026-0001"})
		gp.VulnerabilityAnalysis = analysisWith(scan.Vulnerability{ID: "CVE-2026-0001", Severity: "HIGH"})
		gp.ApkEpochTarget = 3
		gp.ApkAdvisories = []ApkAdvisory{apkProvenAt(3, "CVE-2026-0001")}
		assert.Equal(t, "updated bumps, align with chainguard apk -r3; fixes: CVE-2026-0001; apk: CVE-2026-0001", epochComment(gp))
	})

	t.Run("apk truncates after five", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ApkEpochTarget = 2
		for _, id := range []string{"CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5", "CVE-6"} {
			gp.ApkAdvisories = append(gp.ApkAdvisories, apkProvenAt(2, id))
		}
		assert.Equal(t, "align with chainguard apk -r2; apk: CVE-1, CVE-2, CVE-3, CVE-4, CVE-5, +1 more", epochComment(gp))
	})

	t.Run("apk target at or below the epoch adds nothing", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 2)
		gp.ApkEpochTarget = 2
		gp.ApkAdvisories = []ApkAdvisory{apkProvenAt(2, "CVE-2026-0002")}
		assert.Empty(t, epochComment(gp))
	})

	t.Run("truncates after five with +N more", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.StdlibBumps = []StdlibBump{{
			RebuildGoVersion: "1.26.5",
			VulnIDs:          []string{"GO-1", "GO-2", "GO-3", "GO-4", "GO-5", "GO-6", "GO-7"},
		}}
		assert.Equal(t, "rebuild with go1.26.5; fixes: GO-1, GO-2, GO-3, GO-4, GO-5, +2 more", epochComment(gp))
	})

	t.Run("unvalidated falls back to SecurityFixes IDs, skipping placeholder", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ActualChangesApplied = true
		gp.AddSecurityFix(SecurityFix{Module: "m1", Vulnerability: "GHSA-aaaa, GHSA-bbbb"})
		gp.AddSecurityFix(SecurityFix{Module: "m2", Vulnerability: "security vulnerability"})
		assert.Equal(t, "updated bumps; fixes: GHSA-aaaa, GHSA-bbbb", epochComment(gp))
	})

	t.Run("build-input edit alone", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.OriginalYAML = []byte("pipeline:\n  - uses: go/build\n    with:\n      go-package: go-1.24\n")
		gp.CurrentYAML = []byte("pipeline:\n  - uses: go/build\n    with:\n      go-package: go-1.25\n")
		assert.Equal(t, "updated build inputs", epochComment(gp))

		gp.StdlibBumps = []StdlibBump{{RebuildGoVersion: "1.26.5", VulnIDs: []string{"GO-1"}}}
		assert.Equal(t, "rebuild with go1.26.5; fixes: GO-1", epochComment(gp), "an existing clause already explains the bump")
	})

	t.Run("no trigger yields empty comment", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		assert.Empty(t, epochComment(gp))
	})

	t.Run("security fixes plus hygiene bumps", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ActualChangesApplied = true
		gp.Validated = true
		gp.AddSecurityFix(SecurityFix{Module: "m", Vulnerability: "GHSA-fixed"})
		gp.AddHygieneBump(SecurityFix{Module: "golang.org/x/text", Vulnerability: "GO-2026-6629, GO-2026-5970"})
		gp.VulnerabilityAnalysis = analysisWith(
			scan.Vulnerability{ID: "GHSA-fixed", Severity: "HIGH"},
			scan.Vulnerability{ID: "GO-2026-5970", Severity: "MEDIUM"},
			scan.Vulnerability{ID: "GO-2026-6629", Severity: "MEDIUM"},
		)
		gp.AddUnreachableVulnIDs([]string{"GO-2026-5970", "GO-2026-6629"})
		assert.Equal(t, "updated bumps; fixes: GHSA-fixed; hygiene: GO-2026-5970, GO-2026-6629", epochComment(gp))
	})

	t.Run("hygiene bumps only", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.ActualChangesApplied = true
		gp.Validated = true
		gp.AddHygieneBump(SecurityFix{Module: "golang.org/x/text", Vulnerability: "GO-2026-5970"})
		gp.VulnerabilityAnalysis = analysisWith(scan.Vulnerability{ID: "GO-2026-5970", Severity: "MEDIUM"})
		gp.AddUnreachableVulnIDs([]string{"GO-2026-5970"})
		assert.Equal(t, "updated bumps (scanner hygiene); hygiene: GO-2026-5970", epochComment(gp))
	})

	t.Run("hygiene bumps not applied yield no clause", func(t *testing.T) {
		gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
		gp.HygieneBumps = []SecurityFix{{Module: "m", Vulnerability: "GO-1"}}
		assert.Empty(t, epochComment(gp))
	})
}

// TestEpochTriggers_Matrix audits what bumps the epoch. wasBumping records
// the rule before build-input diffs counted (security/hygiene fixes with
// changes applied, or a stdlib staleness finding); every real edit to the
// build inputs now bumps too, comment-only and epoch-only edits never do.
func TestEpochTriggers_Matrix(t *testing.T) {
	const base = `package:
  name: pkg
  version: 1.0.0
  epoch: 1
pipeline:
  - uses: go/bump
    with:
      deps: example.com/a@v1.0.0 example.com/redundant@v1.2.0
      go-version: "1.24"
  - uses: go/build
    with:
      packages: ./cmd
      go-package: go-1.24
`
	edit := func(old, new string) string { return strings.Replace(base, old, new, 1) }
	tests := []struct {
		name       string
		current    string
		state      func(gp *Processor)
		wasBumping bool
		want       bool
	}{
		{"security fix", edit("a@v1.0.0", "a@v1.0.1"), func(gp *Processor) {
			gp.ActualChangesApplied = true
			gp.SecurityFixes = []SecurityFix{{Module: "example.com/a", Vulnerability: "CVE-1"}}
		}, true, true},
		{"hygiene only", edit("a@v1.0.0", "a@v1.0.1"), func(gp *Processor) {
			gp.ActualChangesApplied = true
			gp.HygieneBumps = []SecurityFix{{Module: "example.com/a", Vulnerability: "CVE-1"}}
		}, true, true},
		{"stdlib stale only (clean file)", base, func(gp *Processor) { gp.StdlibBumps = []StdlibBump{{RebuildGoVersion: "1.24.5"}} }, true, true},
		{"stdlib stale on a dirty file (trigger skipped)", base, func(*Processor) {}, false, false},
		{"go-package pin raise only", edit("go-package: go-1.24", "go-package: go-1.25"), func(gp *Processor) { gp.ActualChangesApplied = true }, false, true},
		{"go/bump -> bump migration", edit("  - uses: go/bump\n    with:\n      deps: example.com/a@v1.0.0 example.com/redundant@v1.2.0\n      go-version: \"1.24\"",
			"  - uses: bump\n    with:\n      deps: example.com/a@v1.0.0 example.com/redundant@v1.2.0"), func(gp *Processor) { gp.ActualChangesApplied = true }, false, true},
		{"redundant pin removed", edit(" example.com/redundant@v1.2.0", ""), func(gp *Processor) { gp.ActualChangesApplied = true }, false, true},
		{"go-version fallback (--no-validate)", edit(`go-version: "1.24"`, `go-version: "1.25"`), func(gp *Processor) { gp.ActualChangesApplied = true }, false, true},
		{"bump-step entry without a CVE", edit("redundant@v1.2.0", "redundant@v1.2.0 example.com/coherence@v0.3.0"), func(gp *Processor) { gp.ActualChangesApplied = true }, false, true},
		{"comment-only rewrite", edit("  - uses: go/build", "  # build it\n  - uses: go/build"), func(gp *Processor) { gp.ActualChangesApplied = true }, false, false},
		{"epoch line only", edit("epoch: 1", "epoch: 2 # bumped"), func(*Processor) {}, false, false},
		{"nothing", base, func(*Processor) {}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
			gp.OriginalYAML, gp.CurrentYAML = []byte(base), []byte(tt.current)
			tt.state(gp)
			was := (gp.ActualChangesApplied && (len(gp.SecurityFixes) > 0 || len(gp.HygieneBumps) > 0)) || len(gp.StdlibBumps) > 0
			assert.Equal(t, tt.wasBumping, was, "audit: the previous rule")
			assert.Equal(t, tt.want, epochTriggers(gp))
			wantEpoch := int64(1)
			if tt.want {
				wantEpoch = 2
			}
			assert.Equal(t, wantEpoch, apkNewEpoch(gp))
			gp.ApkEpochTarget = 4
			assert.Equal(t, int64(4), apkNewEpoch(gp), "the apk target still wins when higher")
		})
	}
}

// TestEpochReasons: the reasons are exactly the epoch comment's clauses (the
// same conditions, so the why: line and the YAML comment agree), each with
// its advisory IDs; none exactly when nothing triggers a bump.
func TestEpochReasons(t *testing.T) {
	analysis := &VulnerabilityAnalysis{ByLanguage: []LanguageAnalysis{{ByModroot: []ModrootAnalysis{{
		ScanResult: &scan.ScanResult{Vulnerabilities: []scan.Vulnerability{{ID: "CVE-D"}, {ID: "GO-H"}}},
	}}}}}
	cases := map[string]struct {
		setup func(*Processor)
		want  []EpochReason
	}{
		"nothing": {setup: func(*Processor) {}},
		"deps, stdlib and apk": {
			setup: func(gp *Processor) {
				gp.ActualChangesApplied, gp.Validated = true, true
				gp.VulnerabilityAnalysis = analysis
				gp.AddSecurityFix(SecurityFix{Module: "m", Vulnerability: "CVE-D"})
				gp.AddHygieneBump(SecurityFix{Module: "h", Vulnerability: "GO-H"})
				gp.AddUnreachableVulnIDs([]string{"GO-H"})
				gp.StdlibBumps = []StdlibBump{{RebuildGoVersion: "1.26.5", VulnIDs: []string{"GO-S2", "GO-S1"}}, {RebuildGoVersion: "1.26.5", VulnIDs: []string{"GO-S1"}}}
				gp.ApkEpochTarget = 3
				gp.ApkAdvisories = []ApkAdvisory{{ID: "CGA-a", Upstream: []string{"CVE-A"}, FixedEpoch: 3, Status: apkProven}}
			},
			want: []EpochReason{
				{Kind: "deps", Text: "updated bumps", VulnIDs: []string{"CVE-D"}},
				{Kind: "stdlib", Text: "rebuild with go1.26.5", VulnIDs: []string{"GO-S1", "GO-S2"}},
				{Kind: "apk", Text: "align with chainguard apk -r3", VulnIDs: []string{"CVE-A"}},
			},
		},
		"hygiene only": {
			setup: func(gp *Processor) {
				gp.ActualChangesApplied = true
				gp.AddHygieneBump(SecurityFix{Module: "h", Vulnerability: "GO-H"})
			},
			want: []EpochReason{{Kind: "hygiene", Text: "updated bumps (scanner hygiene)", VulnIDs: []string{"GO-H"}}},
		},
		"build inputs only": {
			setup: func(gp *Processor) {
				gp.OriginalYAML = []byte("pipeline:\n  - uses: go/build\n    with:\n      go-package: go-1.24\n")
				gp.CurrentYAML = []byte("pipeline:\n  - uses: go/build\n    with:\n      go-package: go-1.25\n")
			},
			want: []EpochReason{{Kind: "build", Text: "updated build inputs"}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gp := NewProcessor("/t.yaml", "pkg", "1.0.0", 1)
			tc.setup(gp)
			reasons := epochReasons(gp)
			assert.Equal(t, tc.want, reasons)
			texts := make([]string, len(reasons))
			for i, r := range reasons {
				texts[i] = r.Text
			}
			clauses, _, _ := strings.Cut(epochComment(gp), ";")
			assert.Equal(t, strings.Join(texts, ", "), clauses, "the reasons are the comment's clauses")
			assert.Equal(t, len(reasons) > 0, epochTriggers(gp) || gp.ApkEpochTarget > gp.GetCurrentEpoch(), "a reason exactly when the epoch bumps")
		})
	}
}
