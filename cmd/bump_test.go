package cmd

import (
	"encoding/json"
	"io"
	"os"
	"testing"

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

func TestBumpRowStatus(t *testing.T) {
	tests := []struct {
		name        string
		result      *gobump.GoBumpResult
		stdlibVulns int
		want        string
	}{
		{
			name:   "error takes precedence over everything",
			result: &gobump.GoBumpResult{Error: "boom", VulnerabilitiesFound: 1, EpochChanged: true},
			want:   "ERROR",
		},
		{
			name:   "no vulnerabilities, no stdlib bump",
			result: &gobump.GoBumpResult{},
			want:   "NO VULNS",
		},
		{
			name:        "stdlib-only epoch bump (zero dependency vulnerabilities found)",
			result:      &gobump.GoBumpResult{EpochChanged: true},
			stdlibVulns: 2,
			want:        "STDLIB-REBUILD",
		},
		{
			name:        "stdlib bump found but epoch not changed - not a rebuild status",
			result:      &gobump.GoBumpResult{EpochChanged: false},
			stdlibVulns: 2,
			want:        "NO VULNS",
		},
		{
			name:        "dependency fix and stdlib bump together keep dependency-driven status",
			result:      &gobump.GoBumpResult{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, EpochChanged: true, Validated: true},
			stdlibVulns: 3,
			want:        "FIXED",
		},
		{
			name:   "dependency fixed and validated, no residual",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, EpochChanged: true, Validated: true},
			want:   "FIXED",
		},
		{
			name:   "dependency fixed but unvalidated",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, EpochChanged: true, Validated: false},
			want:   "UNVALIDATED",
		},
		{
			name:   "dependency fixed, validated, with residual",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 2, VulnerabilitiesFixed: 1, VulnerabilitiesResidual: 1, EpochChanged: true, Validated: true},
			want:   "PARTIAL",
		},
		{
			name:   "vulnerabilities found, file written but nothing fixed",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 1, FileWasWritten: true},
			want:   "UPDATED",
		},
		{
			name:   "vulnerabilities found, pipeline already correct",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 1, Validated: true},
			want:   "UP-TO-DATE",
		},
		{
			name:   "vulnerabilities found, validated, residual but nothing 'fixed'/no epoch change",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 1, VulnerabilitiesResidual: 1, Validated: true},
			want:   "PARTIAL",
		},
		{
			name:   "regression: dep vulns found, zero fixed, stdlib-only epoch => UP-TO-DATE, was FIXED",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 0, ModulesBumped: 0, EpochChanged: true, Validated: true},
			want:   "UP-TO-DATE",
		},
		{
			name:        "stdlib+residual: dependency fixed with residuals and stdlib bump",
			result:      &gobump.GoBumpResult{VulnerabilitiesFound: 2, VulnerabilitiesFixed: 1, VulnerabilitiesResidual: 1, ModulesBumped: 1, EpochChanged: true, Validated: true},
			stdlibVulns: 2,
			want:        "PARTIAL",
		},
		{
			name:   "ModulesBumped-only: attempted fix with residuals remain",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 0, VulnerabilitiesResidual: 1, ModulesBumped: 1, Validated: true},
			want:   "PARTIAL",
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
		{"unchecked", 0, false, "-"},
		{"checked but zero vulns", 0, true, "-"},
		{"checked, some vulns", 3, true, "3"},
		// Defensive: a nonzero count paired with checked=false shouldn't occur
		// in practice (StdlibChecked=false implies no StdlibBumps), but the
		// column must still degrade to "-" rather than show a misleading count.
		{"nonzero vulns but not checked", 2, false, "-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, stdlibColumnValue(tt.stdlibVulns, tt.checked))
		})
	}
}

// TestOutputBumpTable_FooterWithStdlibStale verifies the summary footer
// appends a stdlib-stale clause when files with stdlib vulnerabilities exist,
// matching the format "; N stdlib-stale".
func TestOutputBumpTable_FooterWithStdlibStale(t *testing.T) {
	results := []*gobump.GoBumpResult{
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

	// Should show 2 stdlib-stale files in footer
	assert.Contains(t, stdout, "; 2 stdlib-stale", "Footer should report 2 stdlib-stale files")
}

// TestOutputBumpTable_FooterWithoutStdlibStale verifies the summary footer
// does not include a stdlib-stale clause when no files have stdlib vulnerabilities.
func TestOutputBumpTable_FooterWithoutStdlibStale(t *testing.T) {
	results := []*gobump.GoBumpResult{
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

	// Footer should not contain stdlib-stale clause
	assert.NotContains(t, stdout, "stdlib-stale", "Footer should not mention stdlib-stale when no files are stdlib-stale")
}

// TestOutputBumpStructured_StdlibSummary exercises the real
// outputBumpStructured code path (not a reimplementation) to confirm
// PackagesStdlibStale/TotalStdlibVulns dedupe the same vulnerability ID
// recurring across a file's go-package pin constraints, and that a
// dependency-only file and a checked-but-clean file don't inflate the count.
func TestOutputBumpStructured_StdlibSummary(t *testing.T) {
	results := []*gobump.GoBumpResult{
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

	var resp output.GoBumpResponse
	require.NoError(t, json.Unmarshal([]byte(stdout), &resp))

	assert.Equal(t, 2, resp.Summary.PackagesStdlibStale, "pkg-a and pkg-b each have >=1 distinct stdlib vuln ID")
	assert.Equal(t, 3, resp.Summary.TotalStdlibVulns, "pkg-a: GO-STD-1+GO-STD-2 (deduped), pkg-b: GO-STD-9")

	// The per-file structured result carries StdlibBumps/StdlibChecked through
	// verbatim (GoBumpResult's own json tags), including in the response map.
	require.Contains(t, resp.Results, "pkg-a.yaml")
	assert.True(t, resp.Results["pkg-a.yaml"].StdlibChecked)
	assert.Len(t, resp.Results["pkg-a.yaml"].StdlibBumps, 2)
}

// TestDependencyFixApplied verifies the dependencyFixApplied helper correctly
// identifies when a dependency-level fix was attempted (regardless of epoch
// changes from stdlib alone).
func TestDependencyFixApplied(t *testing.T) {
	tests := []struct {
		name        string
		result      *gobump.GoBumpResult
		want        bool
	}{
		{
			name:   "no vulnerabilities, no modules bumped",
			result: &gobump.GoBumpResult{},
			want:   false,
		},
		{
			name:   "vulnerabilities fixed",
			result: &gobump.GoBumpResult{VulnerabilitiesFixed: 1},
			want:   true,
		},
		{
			name:   "modules bumped",
			result: &gobump.GoBumpResult{ModulesBumped: 1},
			want:   true,
		},
		{
			name:   "both vulnerabilities fixed and modules bumped",
			result: &gobump.GoBumpResult{VulnerabilitiesFixed: 1, ModulesBumped: 1},
			want:   true,
		},
		{
			name:   "epoch changed from stdlib but no dependency fix applied",
			result: &gobump.GoBumpResult{EpochChanged: true, VulnerabilitiesFixed: 0, ModulesBumped: 0},
			want:   false,
		},
		{
			name:   "vulnerabilities found and fixed despite stdlib-only epoch",
			result: &gobump.GoBumpResult{VulnerabilitiesFound: 1, VulnerabilitiesFixed: 1, EpochChanged: true, ModulesBumped: 0},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dependencyFixApplied(tt.result))
		})
	}
}
