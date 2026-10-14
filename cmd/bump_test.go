package cmd

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/isometry/choam/internal/gobump"
	"github.com/isometry/choam/internal/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it. outputBumpStructured/outputBumpTable write
// directly to os.Stdout (matching the rest of the cmd package), so this is
// the seam available for exercising them end-to-end in tests.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// TestNewBumpCmd_NoStdlibFlag verifies the --no-stdlib flag is registered
// with the documented default/help text and parses correctly.
func TestNewBumpCmd_NoStdlibFlag(t *testing.T) {
	t.Cleanup(func() { noStdlib = false })

	cmd := NewBumpCmd()

	flag := cmd.Flags().Lookup("no-stdlib")
	require.NotNil(t, flag, "--no-stdlib should be registered")
	assert.Equal(t, "false", flag.DefValue)
	assert.Contains(t, flag.Usage, "Skip the Go stdlib staleness check")
	assert.Contains(t, flag.Usage, "uncommitted changes")

	require.NoError(t, cmd.Flags().Set("no-stdlib", "true"))
	val, err := cmd.Flags().GetBool("no-stdlib")
	require.NoError(t, err)
	assert.True(t, val)
}

// TestBuildBumpProcessorOptions_StdlibCheck verifies --no-stdlib plumbs
// through to ProcessorOptions.StdlibCheck (inverted), matching the
// established --no-validate -> Validate wiring.
func TestBuildBumpProcessorOptions_StdlibCheck(t *testing.T) {
	orig := noStdlib
	t.Cleanup(func() { noStdlib = orig })

	noStdlib = false
	assert.True(t, buildBumpProcessorOptions().StdlibCheck, "StdlibCheck defaults on")

	noStdlib = true
	assert.False(t, buildBumpProcessorOptions().StdlibCheck, "--no-stdlib disables StdlibCheck")
}

// TestBuildBumpProcessorOptions_ApkAdvisoryCheck verifies --no-apk-advisories
// is registered and plumbs through (inverted) to Options.ApkAdvisoryCheck.
func TestBuildBumpProcessorOptions_ApkAdvisoryCheck(t *testing.T) {
	orig := noApkAdvisories
	t.Cleanup(func() { noApkAdvisories = orig })

	flag := NewBumpCmd().Flags().Lookup("no-apk-advisories")
	require.NotNil(t, flag, "--no-apk-advisories should be registered")
	assert.Equal(t, "false", flag.DefValue)

	noApkAdvisories = false
	assert.True(t, buildBumpProcessorOptions().ApkAdvisoryCheck, "ApkAdvisoryCheck defaults on")

	noApkAdvisories = true
	assert.False(t, buildBumpProcessorOptions().ApkAdvisoryCheck, "--no-apk-advisories disables it")
}

// TestBuildBumpProcessorOptions_Compile verifies --no-compile (and
// --no-validate, which skips simulation entirely) disable the compile gate.
func TestBuildBumpProcessorOptions_Compile(t *testing.T) {
	origCompile, origValidate := noCompile, noValidate
	t.Cleanup(func() { noCompile, noValidate = origCompile, origValidate })

	noCompile, noValidate = false, false
	assert.True(t, buildBumpProcessorOptions().Compile, "compile gate defaults on")

	noCompile = true
	assert.False(t, buildBumpProcessorOptions().Compile, "--no-compile disables the gate")

	noCompile, noValidate = false, true
	assert.False(t, buildBumpProcessorOptions().Compile, "--no-validate implies no compile gate")
}

func TestBumpRowStatus(t *testing.T) {
	tests := []struct {
		name        string
		result      *gobump.Result
		stdlibVulns int
		want        string
	}{
		{
			name:   "error takes precedence over everything",
			result: &gobump.Result{Error: "boom", VulnerabilitiesFound: 1, EpochChanged: true},
			want:   "ERROR",
		},
		{
			name:   "no vulnerabilities, no stdlib bump",
			result: &gobump.Result{},
			want:   "NO VULNS",
		},
		{
			name:        "stdlib-only epoch bump (zero dependency vulnerabilities found)",
			result:      &gobump.Result{EpochChanged: true},
			stdlibVulns: 2,
			want:        "STDLIB-REBUILD",
		},
		{
			name:        "stdlib bump found but epoch not changed - not a rebuild status",
			result:      &gobump.Result{EpochChanged: false},
			stdlibVulns: 2,
			want:        "NO VULNS",
		},
		{
			name:        "dependency fix and stdlib bump together keep dependency-driven status",
			result:      &gobump.Result{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, EpochChanged: true, Validated: true},
			stdlibVulns: 3,
			want:        "FIXED",
		},
		{
			name:   "dependency fixed and validated, no residual",
			result: &gobump.Result{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, EpochChanged: true, Validated: true},
			want:   "FIXED",
		},
		{
			name:   "dependency fixed but unvalidated",
			result: &gobump.Result{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, EpochChanged: true, Validated: false},
			want:   "UNVALIDATED",
		},
		{
			name:   "dependency fixed, validated, with residual",
			result: &gobump.Result{VulnerabilitiesFound: 2, VulnerabilitiesFixed: 1, VulnerabilitiesResidual: 1, EpochChanged: true, Validated: true},
			want:   "PARTIAL",
		},
		{
			name:   "vulnerabilities found, file written but nothing fixed",
			result: &gobump.Result{VulnerabilitiesFound: 1, FileWasWritten: true},
			want:   "UPDATED",
		},
		{
			name:   "vulnerabilities found, pipeline already correct",
			result: &gobump.Result{VulnerabilitiesFound: 1, Validated: true},
			want:   "UP-TO-DATE",
		},
		{
			name:   "vulnerabilities found, validated, residual but nothing fixed",
			result: &gobump.Result{VulnerabilitiesFound: 1, VulnerabilitiesResidual: 1, Validated: true},
			want:   "NO-FIX",
		},
		{
			name:   "no simulation, unfixable advisories remain: never UP-TO-DATE",
			result: &gobump.Result{VulnerabilitiesFound: 2, VulnerabilitiesResidual: 2},
			want:   "NO-FIX",
		},
		{
			name:   "skipped and nothing analyzed",
			result: &gobump.Result{SkipReasons: []string{"cannot fetch dependency manifests"}},
			want:   "SKIPPED",
		},
		{
			name:   "partly skipped but advisories found: normal status",
			result: &gobump.Result{SkipReasons: []string{"gradle: unsupported"}, VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, ModulesBumped: 1, Validated: true},
			want:   "FIXED",
		},
		{
			name:   "validated, fixed by an earlier run, nothing changed now => UP-TO-DATE, was FIXED",
			result: &gobump.Result{VulnerabilitiesFound: 12, VulnerabilitiesFixed: 5, VulnerabilitiesUnreachable: 7, Validated: true, OldEpoch: 2, NewEpoch: 2},
			want:   "UP-TO-DATE",
		},
		{
			name:   "validated, hygiene bump only this run keeps FIXED",
			result: &gobump.Result{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, HygieneModulesBumped: 1, Validated: true},
			want:   "FIXED",
		},
		{
			name:   "error keeps precedence over skip",
			result: &gobump.Result{Error: "boom", SkipReasons: []string{"x"}},
			want:   "ERROR",
		},
		{
			name:   "regression: dep vulns found, zero fixed, stdlib-only epoch => UP-TO-DATE, was FIXED",
			result: &gobump.Result{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 0, ModulesBumped: 0, EpochChanged: true, Validated: true},
			want:   "UP-TO-DATE",
		},
		{
			name:        "stdlib+residual: dependency fixed with residuals and stdlib bump",
			result:      &gobump.Result{VulnerabilitiesFound: 2, VulnerabilitiesFixed: 1, VulnerabilitiesResidual: 1, ModulesBumped: 1, EpochChanged: true, Validated: true},
			stdlibVulns: 2,
			want:        "PARTIAL",
		},
		{
			name:   "ModulesBumped-only: modules moved but nothing fixed, residuals remain",
			result: &gobump.Result{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 0, VulnerabilitiesResidual: 1, ModulesBumped: 1, Validated: true},
			want:   "NO-FIX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bumpRowStatus(tt.result, tt.stdlibVulns))
		})
	}
}

func TestStdlibColumnValue(t *testing.T) {
	tests := []struct {
		name        string
		stdlibVulns int
		checked     bool
		want        string
	}{
		{"unchecked", 0, false, "skip"},
		{"checked but zero vulns", 0, true, "-"},
		{"checked, some vulns", 3, true, "3"},
		// Defensive: a nonzero count paired with checked=false shouldn't occur
		// in practice (StdlibChecked=false implies no StdlibBumps), but the
		// column must still say the check did not run.
		{"nonzero vulns but not checked", 2, false, "skip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, stdlibColumnValue(tt.stdlibVulns, tt.checked))
		})
	}
}

// TestOutputBumpTable_FooterWithStdlibStale: stdlib-stale files show their
// distinct stdlib counts in the STDLIB column; the short footer counts files.
func TestOutputBumpTable_FooterWithStdlibStale(t *testing.T) {
	results := []*gobump.Result{
		{
			PackageName:   "pkg-a",
			FilePath:      "pkg-a.yaml",
			StdlibChecked: true,
			StdlibBumps: []gobump.StdlibBump{
				{GoPackagePin: "1.22", VulnIDs: []string{"GO-STD-1", "GO-STD-2"}},
			},
		},
		{
			PackageName:   "pkg-b",
			FilePath:      "pkg-b.yaml",
			StdlibChecked: true,
			StdlibBumps: []gobump.StdlibBump{
				{GoPackagePin: "1.22", VulnIDs: []string{"GO-STD-3"}},
			},
		},
		{
			PackageName:   "pkg-c",
			FilePath:      "pkg-c.yaml",
			StdlibChecked: true,
			// No stdlib vulnerabilities
		},
	}

	stdout := captureStdout(t, func() {
		require.NoError(t, outputBumpTable(results))
	})

	assert.Regexp(t, `pkg-a\s.*│ 2\s+│ 0\s+│ NO VULNS`, stdout)
	assert.Regexp(t, `pkg-c\s.*│ -\s+│ 0\s+│ NO VULNS`, stdout)
	assert.Contains(t, stdout, "\nSummary: 3 files, 0 changed, 0 errors, 0 skipped, 0 need action\n")
}

// TestOutputBumpTable_FooterWithoutStdlibStale: a clean run prints the table
// and the footer alone - no actions, no info line.
func TestOutputBumpTable_FooterWithoutStdlibStale(t *testing.T) {
	results := []*gobump.Result{
		{
			PackageName:   "pkg-a",
			FilePath:      "pkg-a.yaml",
			StdlibChecked: true,
			// No stdlib vulnerabilities
		},
		{
			PackageName:   "pkg-b",
			FilePath:      "pkg-b.yaml",
			StdlibChecked: true,
			// No stdlib vulnerabilities
		},
	}

	stdout := captureStdout(t, func() {
		require.NoError(t, outputBumpTable(results))
	})

	assert.NotContains(t, stdout, "Action needed")
	assert.NotContains(t, stdout, "Info")
	assert.Contains(t, stdout, "\nSummary: 2 files, 0 changed, 0 errors, 0 skipped, 0 need action\n")
}

// TestOutputBumpStructured_StdlibSummary exercises the real
// outputBumpStructured code path (not a reimplementation) to confirm
// PackagesStdlibStale/TotalStdlibVulns dedupe the same vulnerability ID
// recurring across a file's go-package pin constraints, and that a
// dependency-only file and a checked-but-clean file don't inflate the count.
func TestOutputBumpStructured_StdlibSummary(t *testing.T) {
	results := []*gobump.Result{
		{
			FilePath:      "pkg-a.yaml",
			StdlibChecked: true,
			StdlibBumps: []gobump.StdlibBump{
				{GoPackagePin: "1.22", VulnIDs: []string{"GO-STD-1", "GO-STD-2"}},
				{GoPackagePin: "1.23", VulnIDs: []string{"GO-STD-1"}}, // GO-STD-1 recurs across pin constraints
			},
		},
		{
			FilePath:             "pkg-b.yaml",
			VulnerabilitiesFound: 1,
			VulnerabilitiesFixed: 1,
			Validated:            true,
			EpochChanged:         true,
			StdlibChecked:        true,
			StdlibBumps: []gobump.StdlibBump{
				{VulnIDs: []string{"GO-STD-9"}},
			},
		},
		{
			FilePath:      "pkg-c.yaml",
			StdlibChecked: true, // check ran, nothing to fix
		},
	}

	stdout := captureStdout(t, func() {
		require.NoError(t, outputBumpStructured(results, "json"))
	})

	var resp output.BumpResponse
	require.NoError(t, json.Unmarshal([]byte(stdout), &resp))

	assert.Equal(t, 2, resp.Summary.PackagesStdlibStale, "pkg-a and pkg-b each have >=1 distinct stdlib vuln ID")
	assert.Equal(t, 3, resp.Summary.TotalStdlibVulns, "pkg-a: GO-STD-1+GO-STD-2 (deduped), pkg-b: GO-STD-9")

	// The per-file structured result carries StdlibBumps/StdlibChecked through
	// verbatim (Result's own json tags), including in the response map.
	require.Contains(t, resp.Results, "pkg-a.yaml")
	assert.True(t, resp.Results["pkg-a.yaml"].StdlibChecked)
	assert.Len(t, resp.Results["pkg-a.yaml"].StdlibBumps, 2)
}

// TestSummarizeBumpResults pins the one summary definition shared by the
// table footer and the structured output: errored files count only as
// errors, "fixed" means VulnerabilitiesFixed > 0 (a file that only moved
// modules is not fixed), skips are counted, changed means the epoch moved or
// the file was rewritten, and action-needed covers errors and actions.
func TestSummarizeBumpResults(t *testing.T) {
	results := []*gobump.Result{
		{FilePath: "a.yaml", VulnerabilitiesFound: 3, VulnerabilitiesFixed: 2, VulnerabilitiesResidual: 1, ModulesBumped: 2, Validated: true},
		{FilePath: "b.yaml", VulnerabilitiesFound: 1, ModulesBumped: 1, Validated: true, VulnerabilitiesResidual: 1},
		{FilePath: "c.yaml", PackageName: "c", VulnerabilitiesFound: 5, VulnerabilitiesFixed: 5, Error: "fetch failed"},
		{FilePath: "d.yaml", PackageName: "d", SkipReasons: []string{"unsupported repository"},
			ActionsNeeded: []gobump.NeededAction{{Kind: gobump.ActionReview, Subject: "not analyzed", Detail: "unsupported repository"}}},
		{FilePath: "e.yaml", VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, ModulesBumped: 1, EpochChanged: true, OldEpoch: 1, NewEpoch: 2},
	}
	s := summarizeBumpResults(results)
	assert.Equal(t, output.BumpSummary{
		TotalPackages:        5,
		PackagesWithVulns:    3,
		PackagesFixed:        2,
		PackagesPartial:      2,
		PackagesUnvalidated:  1,
		TotalVulnsFound:      5,
		TotalVulnsFixed:      3,
		TotalVulnsResidual:   2,
		TotalModulesBumped:   4,
		Errors:               1,
		PackagesSkipped:      1,
		PackagesChanged:      1,
		PackagesActionNeeded: 2,
	}, s)

	table := captureStdout(t, func() { require.NoError(t, outputBumpTable(results)) })
	assert.Contains(t, table, "\nSummary: 5 files, 1 changed, 1 errors, 1 skipped, 2 need action\n")
	assert.Contains(t, table, "\n  ERROR   fetch failed - c\n", "errors are shown at default verbosity")
	assert.Contains(t, table, "\n  REVIEW  not analyzed: unsupported repository - d\n", "skip reasons are shown at default verbosity")
	assert.Regexp(t, `│ 1->2\s+│ UNVALIDATED`, table, "merged EPOCH cell")
}

// TestBumpOutput_HygieneColumn: hygiene bumps get their own table column
// (after UNLINKED; BUMPED stays security-only), info count and summary key,
// all absent when there are none.
func TestBumpOutput_HygieneColumn(t *testing.T) {
	results := []*gobump.Result{
		{FilePath: "k.yaml", PackageName: "kubeconform", VulnerabilitiesFound: 2, VulnerabilitiesUnreachable: 2, Validated: true,
			HygieneModulesBumped: 1, HygieneBumps: []gobump.SecurityFix{{Module: "golang.org/x/text", Vulnerability: "GO-2026-5970"}}},
	}
	table := captureStdout(t, func() { require.NoError(t, outputBumpTable(results)) })
	header := strings.Fields(strings.ReplaceAll(strings.SplitN(table, "\n", 2)[0], "│", " "))
	assert.Equal(t, []string{"PACKAGE", "FOUND", "FIXED", "RESIDUAL", "UNLINKED", "HYGIENE", "BUMPED"}, header[:7])
	assert.Contains(t, table, "\nInfo (-v for detail): 2 advisories in unlinked modules, 1 hygiene bump, 1 stdlib check skipped\n")

	stdout := captureStdout(t, func() { require.NoError(t, outputBumpStructured(results, "json")) })
	assert.Contains(t, stdout, `"total_hygiene_modules_bumped": 1`)

	plain := captureStdout(t, func() {
		require.NoError(t, outputBumpStructured([]*gobump.Result{{FilePath: "p.yaml"}}, "json"))
	})
	assert.NotContains(t, plain, "hygiene")
}

// TestBumpOutput_Notes: notes are printed at default verbosity (table
// layout unchanged) and published under the new "notes" key, absent when
// there are none.
func TestBumpOutput_Notes(t *testing.T) {
	note := "artifact linkage unavailable (GOARCH=amd64: go list -deps: package example.com/gen: build constraints exclude all Go files) - unlinked/hygiene classification and stdlib filtering skipped"
	results := []*gobump.Result{{FilePath: "f.yaml", PackageName: "flux", VulnerabilitiesFound: 1, Validated: true, Notes: []string{note}}}

	saved := verbosity
	verbosity = 0 // default verbosity: Messages are not printed, notes are
	t.Cleanup(func() { verbosity = saved })
	table := captureStdout(t, func() { require.NoError(t, outputBumpTable(results)) })
	assert.Contains(t, table, "\nNote flux: "+note+"\n")
	header := strings.Fields(strings.ReplaceAll(strings.SplitN(table, "\n", 2)[0], "│", " "))
	assert.Equal(t, []string{"PACKAGE", "FOUND", "FIXED", "RESIDUAL", "UNLINKED", "HYGIENE", "BUMPED", "STDLIB", "EPOCH", "STATUS"}, header)

	stdout := captureStdout(t, func() { require.NoError(t, outputBumpStructured(results, "json")) })
	var resp struct {
		Results map[string]map[string]any `json:"results"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &resp))
	assert.Equal(t, []any{note}, resp.Results["f.yaml"]["notes"])
	yamlOut := captureStdout(t, func() { require.NoError(t, outputBumpStructured(results, "yaml")) })
	assert.Contains(t, yamlOut, "notes:")

	plain := []*gobump.Result{{FilePath: "p.yaml", PackageName: "plain"}}
	assert.NotContains(t, captureStdout(t, func() { require.NoError(t, outputBumpTable(plain)) }), "Note ")
	assert.NotContains(t, captureStdout(t, func() { require.NoError(t, outputBumpStructured(plain, "json")) }), `"notes"`)
}

// TestOutputBumpStructured_KeyedByFullPath: two files sharing a basename in
// different directories must both appear.
func TestOutputBumpStructured_KeyedByFullPath(t *testing.T) {
	results := []*gobump.Result{
		{FilePath: "x/pkg.yaml", PackageName: "pkg"},
		{FilePath: "y/pkg.yaml", PackageName: "pkg"},
	}
	stdout := captureStdout(t, func() { require.NoError(t, outputBumpStructured(results, "json")) })
	var resp output.BumpResponse
	require.NoError(t, json.Unmarshal([]byte(stdout), &resp))
	assert.Len(t, resp.Results, 2)
	assert.Contains(t, resp.Results, "x/pkg.yaml")
	assert.Contains(t, resp.Results, "y/pkg.yaml")
}

// TestOutputBumpTable_NotValidatedRerun: an unvalidated write is a RERUN
// action carrying the simulation error (derived in gobump's ToResult).
func TestOutputBumpTable_NotValidatedRerun(t *testing.T) {
	untouched := []*gobump.Result{{PackageName: "quiet", VulnerabilitiesFound: 1}}
	assert.NotContains(t, captureStdout(t, func() { require.NoError(t, outputBumpTable(untouched)) }), "RERUN")

	written := []*gobump.Result{{PackageName: "loud", VulnerabilitiesFound: 1, ModulesBumped: 1, FileWasWritten: true, SimulationError: "clone failed",
		ActionsNeeded: []gobump.NeededAction{{Kind: gobump.ActionRerun, Subject: "deps list not validated (resolvability and completeness unproven)", Detail: "clone failed"}}}}
	out := captureStdout(t, func() { require.NoError(t, outputBumpTable(written)) })
	assert.Contains(t, out, "\n  RERUN   deps list not validated (resolvability and completeness unproven): clone failed - loud\n")
	assert.Contains(t, out, "1 needs action")
}

// TestRenderActions_GroupsAndOrders: actions group across files on (kind,
// subject, detail), list most severe first (error, patch, rerun, review,
// accept) then by subject, and cut the package list after three names.
func TestRenderActions_GroupsAndOrders(t *testing.T) {
	accept := gobump.NeededAction{Kind: gobump.ActionAccept, Subject: "no released fix", Detail: "golang.org/x/crypto@v0.1.0 GO-2026-5932"}
	review := gobump.NeededAction{Kind: gobump.ActionReview, Subject: "not analyzed", Detail: "no git-checkout step"}
	results := []*gobump.Result{
		{PackageName: "a", ActionsNeeded: []gobump.NeededAction{accept, review}},
		{PackageName: "b", ActionsNeeded: []gobump.NeededAction{accept, {Kind: gobump.ActionPatch, Subject: "CVE-2026-1 (CGA-1, fixed in 1.0-r2)", Detail: "own module"}}},
		{PackageName: "c", ActionsNeeded: []gobump.NeededAction{review}},
		{PackageName: "d", ActionsNeeded: []gobump.NeededAction{review}},
		{PackageName: "e", ActionsNeeded: []gobump.NeededAction{review}},
		{PackageName: "f", Error: "boom", ActionsNeeded: []gobump.NeededAction{accept}},
	}
	out := captureStdout(t, func() { renderActions(results) })
	assert.Equal(t, `
Action needed:
  ERROR   boom - f
  PATCH   CVE-2026-1 (CGA-1, fixed in 1.0-r2): own module - b
  REVIEW  not analyzed: no git-checkout step - a, c, d, +1 more
  ACCEPT  no released fix: golang.org/x/crypto@v0.1.0 GO-2026-5932 - a, b
`, out, "an errored file shows only its error")

	assert.Empty(t, captureStdout(t, func() { renderActions([]*gobump.Result{{PackageName: "clean"}}) }))
}

// TestRenderWhy: changed rows get a why line (reason clauses with advisory
// counts, then the apk outcome); unchanged, ERROR and SKIPPED rows get none.
func TestRenderWhy(t *testing.T) {
	reasons := []gobump.EpochReason{
		{Kind: "deps", Text: "updated bumps", VulnIDs: []string{"CVE-1", "CVE-2"}},
		{Kind: "apk", Text: "align with chainguard apk -r9", VulnIDs: []string{"CVE-3"}},
	}
	results := []*gobump.Result{
		{PackageName: "tofu", EpochChanged: true, OldEpoch: 1, NewEpoch: 9, EpochReasons: reasons,
			ApkAlignment: &gobump.ApkAlignment{Version: "0.16.5-r1", TargetEpoch: 9, HighestFixedEpoch: 9}},
		{PackageName: "held", EpochChanged: true, OldEpoch: 1, NewEpoch: 7, EpochReasons: reasons[1:],
			ApkAlignment: &gobump.ApkAlignment{Version: "2.0-r1", TargetEpoch: 7, HighestFixedEpoch: 11, BlockedAt: 9}},
		{PackageName: "build", EpochChanged: true, OldEpoch: 1, NewEpoch: 2, EpochReasons: []gobump.EpochReason{{Kind: "build", Text: "updated build inputs"}}},
		{PackageName: "same", EpochReasons: reasons},
		{PackageName: "broken", Error: "boom", EpochChanged: true, EpochReasons: reasons},
	}
	out := captureStdout(t, func() { renderWhy(results) })
	assert.Equal(t, `
Why:
  tofu: updated bumps (2), align with chainguard apk -r9 (1); apk: -r9 is the highest Wolfi advisory fix epoch for 0.16.5
  held: align with chainguard apk -r9 (1); apk: held at -r7, -r9 advisory not proven (see actions)
  build: updated build inputs
`, out)
}

// TestRunBump_StructuredOutputStaysParseable: with --format json|yaml the
// stdout must be the document alone - no "No melange files found." line, no
// dry-run banner - for an empty directory and for a file that cannot be
// parsed.
func TestRunBump_StructuredOutputStaysParseable(t *testing.T) {
	run := func(t *testing.T, args ...string) (string, error) {
		t.Helper()
		t.Cleanup(func() { dryRun, outputFormat = false, "table" })
		cmd := NewBumpCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs(append([]string{"--dry-run", "--no-validate", "--no-stdlib"}, args...))
		var err error
		stdout := captureStdout(t, func() { err = cmd.ExecuteContext(t.Context()) })
		return stdout, err
	}

	t.Run("empty directory", func(t *testing.T) {
		for _, format := range []string{"json", "yaml"} {
			stdout, err := run(t, "--format", format, t.TempDir())
			require.NoError(t, err)
			var resp output.BumpResponse
			if format == "json" {
				require.NoError(t, json.Unmarshal([]byte(stdout), &resp), stdout)
			} else {
				require.NoError(t, yaml.Unmarshal([]byte(stdout), &resp), stdout)
			}
			assert.Empty(t, resp.Results)
			assert.Zero(t, resp.Summary.TotalPackages)
		}
	})

	t.Run("empty directory keeps the text line for table", func(t *testing.T) {
		stdout, err := run(t, t.TempDir())
		require.NoError(t, err)
		assert.Contains(t, stdout, "No melange files found.")
	})

	t.Run("broken file", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "broken.yaml")
		require.NoError(t, os.WriteFile(bad, []byte("package: [not valid\n"), 0o644))
		stdout, err := run(t, "--format", "json", bad)
		require.ErrorIs(t, err, ErrBumpFailed)
		var resp output.BumpResponse
		require.NoError(t, json.Unmarshal([]byte(stdout), &resp), stdout)
		require.Contains(t, resp.Results, bad)
		assert.NotEmpty(t, resp.Results[bad].Error)
		assert.Equal(t, 1, resp.Summary.Errors)
	})
}

// TestRunBump_ErroredFileExitsNonZero: a file that cannot be processed is
// still reported, and the command returns ErrBumpFailed (exit 1).
func TestRunBump_ErroredFileExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "broken.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("package: [not valid\n"), 0o644))

	cmd := NewBumpCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--no-validate", "--no-stdlib", bad})
	var err error
	stdout := captureStdout(t, func() { err = cmd.ExecuteContext(t.Context()) })

	require.ErrorIs(t, err, ErrBumpFailed)
	assert.Contains(t, stdout, "broken")
	assert.Contains(t, stdout, "ERROR")
}

// TestRunBump_CancelledPrintsPartialResults: a cancelled run still prints
// what it has, then returns the cancellation.
func TestRunBump_CancelledPrintsPartialResults(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("package: [not valid\n"), 0o644))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	cmd := NewBumpCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--no-validate", "--no-stdlib", dir})
	var err error
	stdout := captureStdout(t, func() { err = cmd.ExecuteContext(ctx) })

	require.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, stdout, "Summary: 0 files,")
}

func TestNewBumpCmd_FailOnResidualFlag(t *testing.T) {
	flag := NewBumpCmd().Flags().Lookup("fail-on-residual")
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
	assert.Contains(t, flag.Usage, "first-party")
}

// TestBumpOutput_FirstPartyAlerts: first-party apk advisories are counted in
// the summary and shown as default-verbosity PATCH actions.
func TestBumpOutput_FirstPartyAlerts(t *testing.T) {
	results := []*gobump.Result{
		{FilePath: "a.yaml", PackageName: "a", FirstPartyVulnIDs: []string{"CVE-2026-1", "CVE-2026-2"},
			ActionsNeeded: []gobump.NeededAction{{Kind: gobump.ActionPatch, Subject: "CVE-2026-1 (CGA-1, fixed in 1.0-r2)", Detail: "needs a patch"}}},
		{FilePath: "b.yaml", PackageName: "b"},
	}
	s := summarizeBumpResults(results)
	assert.Equal(t, 1, s.PackagesPatchNeeded)
	assert.Equal(t, 2, s.TotalFirstPartyVulns)

	saved := verbosity
	verbosity = 0
	t.Cleanup(func() { verbosity = saved })
	table := captureStdout(t, func() { require.NoError(t, outputBumpTable(results)) })
	assert.Contains(t, table, "PATCH-NEEDED")
	assert.Contains(t, table, "\n  PATCH   CVE-2026-1 (CGA-1, fixed in 1.0-r2): needs a patch - a\n")
	assert.Contains(t, table, ", 1 needs action\n")

	js := captureStdout(t, func() { require.NoError(t, outputBumpStructured(results, "json")) })
	assert.Contains(t, js, `"packages_patch_needed": 1`)
	assert.Contains(t, js, `"total_first_party_vulns": 2`)
}

// TestRunBump_FailOnResidualFirstPartyExitsNonZero: with --fail-on-residual a
// first-party apk advisory fails the run; without it the run succeeds.
func TestRunBump_FailOnResidualFirstPartyExitsNonZero(t *testing.T) {
	summary := summarizeBumpResults([]*gobump.Result{{FilePath: "a.yaml", FirstPartyVulnIDs: []string{"CVE-2026-1"}}})
	orig := failOnResidual
	t.Cleanup(func() { failOnResidual = orig })

	failOnResidual = false
	assert.NoError(t, bumpExitError(summary))

	failOnResidual = true
	err := bumpExitError(summary)
	require.ErrorIs(t, err, ErrBumpFailed)
	assert.Contains(t, err.Error(), "first-party")
}

// TestRenderDetails: the -v details group by section in a fixed order,
// lead Changes with the structured fixes (CVE IDs first), render apk from
// the structured alignment, and hide epoch/validation/file-writer messages -
// which the JSON messages still carry.
func TestRenderDetails(t *testing.T) {
	result := &gobump.Result{
		FilePath:    "tofu.yaml",
		PackageName: "tofu",
		NewEpoch:    7,
		SecurityFixes: []gobump.SecurityFix{
			{Module: "golang.org/x/net", OldVersion: "v0.1.0", NewVersion: "v0.2.0", Vulnerability: "GO-2026-1, CVE-2026-1"},
		},
		HygieneBumps: []gobump.SecurityFix{{Module: "golang.org/x/text", OldVersion: "v0.1.0", NewVersion: "v0.3.0", Vulnerability: "GO-2026-9"}},
		ApkAlignment: &gobump.ApkAlignment{Version: "0.16.5-r1", TargetEpoch: 7, HighestFixedEpoch: 9, BlockedAt: 9, Proven: 2, Unproven: 1, Ignored: 2, Uncorrelated: 1},
		ApkAdvisories: []gobump.ApkAdvisory{
			{ID: "CGA-g7", Upstream: []string{"GHSA-g7", "CVE-G7"}, FixedVersion: "0.16.5-r7", FixedEpoch: 7, Status: "proven"},
			{ID: "CGA-g7b", Upstream: []string{"CVE-G7"}, FixedVersion: "0.16.5-r7", FixedEpoch: 7, Status: "proven"}, // same issue, other ecosystem
			{ID: "CGA-g6", Upstream: []string{"GO-G6"}, FixedVersion: "0.16.5-r6", FixedEpoch: 6, Status: "proven"},
			{ID: "CGA-m9", Upstream: []string{"CVE-M9"}, FixedVersion: "0.16.5-r9", FixedEpoch: 9, Status: "first-party", Reason: "affects example.com/self, this package's own module"},
			{ID: "CGA-x9", Upstream: []string{"CVE-X9"}, FixedVersion: "0.16.5-r9", FixedEpoch: 9, Status: "unproven", Reason: "module example.com/x not in the analysed graph"},
			{ID: "CGA-n9b", Upstream: []string{"CVE-N9b"}, FixedVersion: "0.16.5-r9", FixedEpoch: 9, Status: "unproven", Reason: "stdlib: the rebuild Go toolchain could not be resolved"},
			{ID: "CGA-n9", Upstream: []string{"CVE-N9"}, FixedVersion: "0.16.5-r9", FixedEpoch: 9, Status: "unproven", Reason: "stdlib: the rebuild Go toolchain could not be resolved"},
		},
		Messages:        []string{"stdlib: trigger skipped", "golang.org/x/crypto (GO-2) vulnerable but not linked", "Updated deps", "epoch: 1 -> 7", "YAML validation passed", "wrote file", "trailing"},
		MessageSections: []string{gobump.SectionStdlib, gobump.SectionAdvisories, gobump.SectionChanges, gobump.SectionHidden, gobump.SectionHidden, gobump.SectionHidden},
	}
	out := captureStdout(t, func() { renderDetails(result) })
	assert.Equal(t, `
Details for tofu:
  Changes:
    - golang.org/x/net v0.1.0 -> v0.2.0 [CVE-2026-1, GO-2026-1]
    - hygiene: golang.org/x/text v0.1.0 -> v0.3.0 [GO-2026-9]
    - Updated deps
  Advisories:
    - golang.org/x/crypto (GO-2) vulnerable but not linked
  apk:
    - 0.16.5-r1: 2 proven, 1 unproven, 0 first-party, 2 ignored (1 without an upstream ID); reached -r7 of highest -r9
    - proven: CVE-G7, GO-G6
    - first-party CVE-M9 (CGA-m9, fixed in 0.16.5-r9): affects example.com/self, this package's own module
    - unproven in -r9 (1): CVE-X9 (CGA-x9): module example.com/x not in the analysed graph
    - unproven in -r9 (2): CVE-N9 (CGA-n9), CVE-N9b (CGA-n9b): stdlib: the rebuild Go toolchain could not be resolved
  stdlib:
    - stdlib: trigger skipped
  Other:
    - trailing
`, out)

	js := captureStdout(t, func() { require.NoError(t, outputBumpStructured([]*gobump.Result{result}, "json")) })
	assert.Contains(t, js, `"YAML validation passed"`, "hidden messages stay in the JSON")
	assert.NotContains(t, js, "message_sections")

	assert.Empty(t, captureStdout(t, func() { renderDetails(&gobump.Result{PackageName: "quiet"}) }))
	assert.Contains(t, captureStdout(t, func() {
		renderDetails(&gobump.Result{PackageName: "none", ApkAlignment: &gobump.ApkAlignment{Version: "1.0-r2"}})
	}), "    - 1.0-r2: no apk advisories\n")
}
