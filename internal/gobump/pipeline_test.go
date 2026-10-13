package gobump

import (
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
