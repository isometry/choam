package gobump

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeReleaseIndex answers per-constraint release queries from fixed maps; a
// missing constraint key is an error (mirroring gorelease.ErrNoReleases).
type fakeReleaseIndex struct {
	asOf      map[string]string // constraint -> release as of the commit time
	available map[string]string // constraint -> latest available release

	asOfErr      error
	availableErr error

	asOfCalls      int
	availableCalls int
}

func (f *fakeReleaseIndex) LatestAsOf(_ context.Context, _ time.Time, constraint string) (string, error) {
	f.asOfCalls++
	if f.asOfErr != nil {
		return "", f.asOfErr
	}
	release, ok := f.asOf[constraint]
	if !ok {
		return "", fmt.Errorf("no matching stable Go releases for constraint %q", constraint)
	}
	return release, nil
}

func (f *fakeReleaseIndex) LatestAvailable(_ context.Context, constraint string) (string, error) {
	f.availableCalls++
	if f.availableErr != nil {
		return "", f.availableErr
	}
	release, ok := f.available[constraint]
	if !ok {
		return "", fmt.Errorf("no matching stable Go releases for constraint %q", constraint)
	}
	return release, nil
}

// fakeStdlibScanner returns canned per-version stdlib findings, recording
// every scanned version.
type fakeStdlibScanner struct {
	vulnsByVersion map[string][]scan.Vulnerability
	err            error
	scanErr        string // ScanResult.Error channel
	scanned        []string
}

func (f *fakeStdlibScanner) ScanPackages(_ context.Context, pkgs []scan.Package) (*scan.ScanResult, error) {
	if len(pkgs) != 1 || pkgs[0].Name != "stdlib" || pkgs[0].Ecosystem != "Go" {
		return nil, fmt.Errorf("unexpected scan request: %+v", pkgs)
	}
	f.scanned = append(f.scanned, pkgs[0].Version)
	if f.err != nil {
		return nil, f.err
	}
	if f.scanErr != "" {
		return &scan.ScanResult{Error: f.scanErr}, nil
	}
	return &scan.ScanResult{Vulnerabilities: f.vulnsByVersion[pkgs[0].Version]}, nil
}

func stdlibVuln(id string, imports ...scan.VulnerableImport) scan.Vulnerability {
	return scan.Vulnerability{ID: id, Module: "stdlib", Ecosystem: "Go", VulnerableImports: imports}
}

var stdlibCommitTime = time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC)

func TestEvaluateStdlibStaleness_FixableDiff(t *testing.T) {
	index := &fakeReleaseIndex{
		asOf:      map[string]string{"": "1.21.0"},
		available: map[string]string{"": "1.24.5"},
	}
	scanner := &fakeStdlibScanner{
		vulnsByVersion: map[string][]scan.Vulnerability{
			"1.21.0": {stdlibVuln("GO-2024-0001"), stdlibVuln("GO-2024-0002")},
			"1.24.5": {stdlibVuln("GO-2024-0002")}, // still present at rebuild - not fixable
		},
	}

	bumps, messages, err := evaluateStdlibStaleness(t.Context(), index, scanner, stdlibInput{
		CommitTime:  stdlibCommitTime,
		Constraints: []string{""},
	})
	require.NoError(t, err)

	require.Len(t, bumps, 1)
	assert.Equal(t, StdlibBump{
		AssumedGoVersion: "1.21.0",
		AssumedFromDate:  "2024-03-15T12:00:00Z",
		GoPackagePin:     "",
		RebuildGoVersion: "1.24.5",
		VulnIDs:          []string{"GO-2024-0001"},
		Validated:        false,
	}, bumps[0])

	require.Len(t, messages, 1)
	assert.Contains(t, messages[0], "assumed go1.21.0")
	assert.Contains(t, messages[0], "pin unpinned")
	assert.Contains(t, messages[0], "rebuilding with go1.24.5 fixes GO-2024-0001")

	assert.Equal(t, []string{"1.21.0", "1.24.5"}, scanner.scanned)
}

func TestEvaluateStdlibStaleness_AssumedEqualsRebuildNoScan(t *testing.T) {
	index := &fakeReleaseIndex{
		asOf:      map[string]string{"": "1.24.5"},
		available: map[string]string{"": "1.24.5"},
	}
	scanner := &fakeStdlibScanner{}

	bumps, messages, err := evaluateStdlibStaleness(t.Context(), index, scanner, stdlibInput{
		CommitTime:  stdlibCommitTime,
		Constraints: []string{""},
	})
	require.NoError(t, err)
	assert.Empty(t, bumps)
	assert.Empty(t, messages)
	assert.Empty(t, scanner.scanned, "no scans when a rebuild changes nothing")
}

func TestEvaluateStdlibStaleness_NoVulnsAtAssumedSkipsRebuildScan(t *testing.T) {
	index := &fakeReleaseIndex{
		asOf:      map[string]string{"": "1.24.0"},
		available: map[string]string{"": "1.24.5"},
	}
	scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{}}

	bumps, messages, err := evaluateStdlibStaleness(t.Context(), index, scanner, stdlibInput{
		CommitTime:  stdlibCommitTime,
		Constraints: []string{""},
	})
	require.NoError(t, err)
	assert.Empty(t, bumps)
	assert.Empty(t, messages)
	assert.Equal(t, []string{"1.24.0"}, scanner.scanned)
}

func TestEvaluateStdlibStaleness_PinConstrained(t *testing.T) {
	// Pinned to 1.21: the rebuild target is the newest 1.21 patch release,
	// NOT the newest Go overall.
	index := &fakeReleaseIndex{
		asOf:      map[string]string{"1.21": "1.21.0"},
		available: map[string]string{"1.21": "1.21.13"},
	}
	scanner := &fakeStdlibScanner{
		vulnsByVersion: map[string][]scan.Vulnerability{
			"1.21.0":  {stdlibVuln("GO-2024-0001")},
			"1.21.13": nil,
		},
	}

	bumps, _, err := evaluateStdlibStaleness(t.Context(), index, scanner, stdlibInput{
		CommitTime:  stdlibCommitTime,
		Constraints: []string{"1.21"},
	})
	require.NoError(t, err)
	require.Len(t, bumps, 1)
	assert.Equal(t, "1.21", bumps[0].GoPackagePin)
	assert.Equal(t, "1.21.13", bumps[0].RebuildGoVersion)
	assert.Equal(t, []string{"GO-2024-0001"}, bumps[0].VulnIDs)
}

func TestEvaluateStdlibStaleness_LinkedFiltering(t *testing.T) {
	linked := map[string]struct{}{"net/http": {}, "crypto/tls": {}}

	newIndex := func() *fakeReleaseIndex {
		return &fakeReleaseIndex{
			asOf:      map[string]string{"": "1.22.0"},
			available: map[string]string{"": "1.24.5"},
		}
	}

	t.Run("linked import kept", func(t *testing.T) {
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
			"1.22.0": {stdlibVuln("GO-LINKED", scan.VulnerableImport{Path: "net/http"})},
		}}
		bumps, _, err := evaluateStdlibStaleness(t.Context(), newIndex(), scanner, stdlibInput{
			CommitTime: stdlibCommitTime, Constraints: []string{""}, Linked: linked, Validated: true,
		})
		require.NoError(t, err)
		require.Len(t, bumps, 1)
		assert.Equal(t, []string{"GO-LINKED"}, bumps[0].VulnIDs)
		assert.Empty(t, bumps[0].UnlinkedVulnIDs)
		assert.True(t, bumps[0].Validated)
	})

	t.Run("unlinked import demoted to informational", func(t *testing.T) {
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
			"1.22.0": {stdlibVuln("GO-UNLINKED", scan.VulnerableImport{Path: "archive/zip"})},
		}}
		bumps, messages, err := evaluateStdlibStaleness(t.Context(), newIndex(), scanner, stdlibInput{
			CommitTime: stdlibCommitTime, Constraints: []string{""}, Linked: linked, Validated: true,
		})
		require.NoError(t, err)
		assert.Empty(t, bumps, "unlinked-only findings must not bump")
		require.Len(t, messages, 1)
		assert.Contains(t, messages[0], "GO-UNLINKED")
		assert.Contains(t, messages[0], "not linked into build artifacts")
	})

	t.Run("no import metadata fails open", func(t *testing.T) {
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
			"1.22.0": {stdlibVuln("GO-NOMETA")},
		}}
		bumps, _, err := evaluateStdlibStaleness(t.Context(), newIndex(), scanner, stdlibInput{
			CommitTime: stdlibCommitTime, Constraints: []string{""}, Linked: linked, Validated: true,
		})
		require.NoError(t, err)
		require.Len(t, bumps, 1)
		assert.Equal(t, []string{"GO-NOMETA"}, bumps[0].VulnIDs)
	})

	t.Run("pathless import entry fails open", func(t *testing.T) {
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
			"1.22.0": {stdlibVuln("GO-PATHLESS", scan.VulnerableImport{GOOS: []string{"linux"}})},
		}}
		bumps, _, err := evaluateStdlibStaleness(t.Context(), newIndex(), scanner, stdlibInput{
			CommitTime: stdlibCommitTime, Constraints: []string{""}, Linked: linked, Validated: true,
		})
		require.NoError(t, err)
		require.Len(t, bumps, 1)
	})

	t.Run("non-linux import entry ignored for linkage", func(t *testing.T) {
		// The vulnerable windows-only package can never be in a linux
		// artifact; with no other applicable entry the finding is unlinked.
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
			"1.22.0": {stdlibVuln("GO-WINDOWS", scan.VulnerableImport{Path: "net/http", GOOS: []string{"windows"}})},
		}}
		bumps, messages, err := evaluateStdlibStaleness(t.Context(), newIndex(), scanner, stdlibInput{
			CommitTime: stdlibCommitTime, Constraints: []string{""}, Linked: linked, Validated: true,
		})
		require.NoError(t, err)
		assert.Empty(t, bumps)
		require.Len(t, messages, 1)
		assert.Contains(t, messages[0], "GO-WINDOWS")
	})

	t.Run("mixed linked and unlinked recorded on one bump", func(t *testing.T) {
		scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
			"1.22.0": {
				stdlibVuln("GO-LINKED", scan.VulnerableImport{Path: "crypto/tls"}),
				stdlibVuln("GO-UNLINKED", scan.VulnerableImport{Path: "archive/zip"}),
			},
		}}
		bumps, _, err := evaluateStdlibStaleness(t.Context(), newIndex(), scanner, stdlibInput{
			CommitTime: stdlibCommitTime, Constraints: []string{""}, Linked: linked, Validated: true,
		})
		require.NoError(t, err)
		require.Len(t, bumps, 1)
		assert.Equal(t, []string{"GO-LINKED"}, bumps[0].VulnIDs)
		assert.Equal(t, []string{"GO-UNLINKED"}, bumps[0].UnlinkedVulnIDs)
	})
}

func TestEvaluateStdlibStaleness_UnfilteredWhenLinkedUnknown(t *testing.T) {
	index := &fakeReleaseIndex{
		asOf:      map[string]string{"": "1.22.0"},
		available: map[string]string{"": "1.24.5"},
	}
	scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
		"1.22.0": {stdlibVuln("GO-ANY", scan.VulnerableImport{Path: "archive/zip"})},
	}}

	bumps, _, err := evaluateStdlibStaleness(t.Context(), index, scanner, stdlibInput{
		CommitTime: stdlibCommitTime, Constraints: []string{""}, Linked: nil, Validated: false,
	})
	require.NoError(t, err)
	require.Len(t, bumps, 1)
	assert.Equal(t, []string{"GO-ANY"}, bumps[0].VulnIDs, "no linked set - keep everything")
	assert.False(t, bumps[0].Validated)
}

func TestEvaluateStdlibStaleness_ErrorPropagation(t *testing.T) {
	scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
		"1.22.0": {stdlibVuln("GO-X")},
	}}
	in := stdlibInput{CommitTime: stdlibCommitTime, Constraints: []string{""}}

	t.Run("LatestAsOf error", func(t *testing.T) {
		index := &fakeReleaseIndex{asOfErr: errors.New("proxy unreachable")}
		_, _, err := evaluateStdlibStaleness(t.Context(), index, scanner, in)
		require.ErrorContains(t, err, "proxy unreachable")
	})

	t.Run("LatestAvailable error", func(t *testing.T) {
		index := &fakeReleaseIndex{
			asOf:         map[string]string{"": "1.22.0"},
			availableErr: errors.New("proxy unreachable"),
		}
		_, _, err := evaluateStdlibStaleness(t.Context(), index, scanner, in)
		require.ErrorContains(t, err, "proxy unreachable")
	})

	t.Run("scanner transport error", func(t *testing.T) {
		index := &fakeReleaseIndex{
			asOf:      map[string]string{"": "1.22.0"},
			available: map[string]string{"": "1.24.5"},
		}
		failing := &fakeStdlibScanner{err: errors.New("OSV down")}
		_, _, err := evaluateStdlibStaleness(t.Context(), index, failing, in)
		require.ErrorContains(t, err, "OSV down")
	})

	t.Run("scanner result error", func(t *testing.T) {
		index := &fakeReleaseIndex{
			asOf:      map[string]string{"": "1.22.0"},
			available: map[string]string{"": "1.24.5"},
		}
		failing := &fakeStdlibScanner{scanErr: "OSV API error"}
		_, _, err := evaluateStdlibStaleness(t.Context(), index, failing, in)
		require.ErrorContains(t, err, "OSV API error")
	})
}

func TestEvaluateStdlibStaleness_MultipleConstraints(t *testing.T) {
	// Unpinned steps see the newest Go overall; a 1.21-pinned step only its
	// own patch series - each constraint yields its own bump.
	index := &fakeReleaseIndex{
		asOf:      map[string]string{"": "1.21.0", "1.21": "1.21.0", "1.24": "1.24.5"},
		available: map[string]string{"": "1.24.5", "1.21": "1.21.13", "1.24": "1.24.5"},
	}
	scanner := &fakeStdlibScanner{
		vulnsByVersion: map[string][]scan.Vulnerability{
			"1.21.0":  {stdlibVuln("GO-OLD-1"), stdlibVuln("GO-OLD-2")},
			"1.21.13": {stdlibVuln("GO-OLD-2")}, // 1.21 series never got this fix
			"1.24.5":  nil,
		},
	}

	bumps, _, err := evaluateStdlibStaleness(t.Context(), index, scanner, stdlibInput{
		CommitTime:  stdlibCommitTime,
		Constraints: []string{"", "1.21", "1.24"},
	})
	require.NoError(t, err)

	require.Len(t, bumps, 2, "1.24 is already latest in its series - no third bump")
	assert.Equal(t, "", bumps[0].GoPackagePin)
	assert.Equal(t, []string{"GO-OLD-1", "GO-OLD-2"}, bumps[0].VulnIDs)
	assert.Equal(t, "1.21", bumps[1].GoPackagePin)
	assert.Equal(t, []string{"GO-OLD-1"}, bumps[1].VulnIDs)
}

func TestPinWord(t *testing.T) {
	assert.Equal(t, "unpinned", pinWord(""))
	assert.Equal(t, "1.24", pinWord("1.24"))
}

// Guard against message drift: the bump message must mention the commit date
// the estimate came from.
func TestEvaluateStdlibStaleness_MessageCarriesCommitDate(t *testing.T) {
	index := &fakeReleaseIndex{
		asOf:      map[string]string{"": "1.22.0"},
		available: map[string]string{"": "1.24.5"},
	}
	scanner := &fakeStdlibScanner{vulnsByVersion: map[string][]scan.Vulnerability{
		"1.22.0": {stdlibVuln("GO-X")},
	}}

	_, messages, err := evaluateStdlibStaleness(t.Context(), index, scanner, stdlibInput{
		CommitTime: stdlibCommitTime, Constraints: []string{""},
	})
	require.NoError(t, err)
	require.Len(t, messages, 1)
	assert.True(t, strings.Contains(messages[0], "2024-03-15"), "message %q must carry the commit date", messages[0])
}
