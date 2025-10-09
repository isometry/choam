package gobump

import (
	"testing"

	"github.com/isometry/choam/internal/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGoBumpProcessor(t *testing.T) {
	tests := []struct {
		name           string
		filePath       string
		packageName    string
		currentVersion string
		currentEpoch   int64
	}{
		{
			name:           "basic initialization",
			filePath:       "/path/to/package.yaml",
			packageName:    "test-package",
			currentVersion: "1.2.3",
			currentEpoch:   5,
		},
		{
			name:           "zero epoch",
			filePath:       "/path/to/new-package.yaml",
			packageName:    "new-package",
			currentVersion: "0.1.0",
			currentEpoch:   0,
		},
		{
			name:           "empty version",
			filePath:       "/path/to/package.yaml",
			packageName:    "test",
			currentVersion: "",
			currentEpoch:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewGoBumpProcessor(tt.filePath, tt.packageName, tt.currentVersion, tt.currentEpoch)

			require.NotNil(t, proc)
			require.NotNil(t, proc.BaseProcessor)
			assert.Equal(t, tt.filePath, proc.GetFilePath())
			assert.Equal(t, tt.packageName, proc.GetPackageName())
			assert.Equal(t, tt.currentVersion, proc.GetCurrentVersion())
			assert.Equal(t, tt.currentEpoch, proc.GetCurrentEpoch())
			assert.NotNil(t, proc.SecurityFixes)
			assert.Empty(t, proc.SecurityFixes)
			assert.False(t, proc.ActualChangesApplied)
			assert.Nil(t, proc.VulnerabilityAnalysis)
		})
	}
}

func TestGoBumpProcessor_AddSecurityFix(t *testing.T) {
	tests := []struct {
		name          string
		fixes         []SecurityFix
		wantCount     int
		wantChanges   int
		validateFirst *SecurityFix
	}{
		{
			name: "single fix",
			fixes: []SecurityFix{
				{
					Module:        "golang.org/x/crypto",
					Vulnerability: "CVE-2023-1234",
					OldVersion:    "v0.13.0",
					NewVersion:    "v0.14.0",
					Severity:      "high",
				},
			},
			wantCount:   1,
			wantChanges: 1,
			validateFirst: &SecurityFix{
				Module:        "golang.org/x/crypto",
				Vulnerability: "CVE-2023-1234",
				OldVersion:    "v0.13.0",
				NewVersion:    "v0.14.0",
				Severity:      "high",
			},
		},
		{
			name: "multiple fixes",
			fixes: []SecurityFix{
				{
					Module:        "golang.org/x/crypto",
					Vulnerability: "CVE-2023-1234",
					OldVersion:    "v0.13.0",
					NewVersion:    "v0.14.0",
					Severity:      "critical",
				},
				{
					Module:        "github.com/gin-gonic/gin",
					Vulnerability: "GHSA-xxxx-yyyy",
					OldVersion:    "v1.9.0",
					NewVersion:    "v1.9.1",
					Severity:      "medium",
				},
				{
					Module:        "github.com/gorilla/websocket",
					Vulnerability: "CVE-2023-5678",
					OldVersion:    "v1.5.0",
					NewVersion:    "v1.5.1",
					Severity:      "low",
				},
			},
			wantCount:   3,
			wantChanges: 3,
		},
		{
			name:          "no fixes",
			fixes:         []SecurityFix{},
			wantCount:     0,
			wantChanges:   0,
			validateFirst: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewGoBumpProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

			for _, fix := range tt.fixes {
				proc.AddSecurityFix(fix)
			}

			assert.Equal(t, tt.wantCount, len(proc.SecurityFixes))
			assert.Equal(t, tt.wantChanges, len(proc.GetChanges()))

			// Validate first fix if provided
			if tt.validateFirst != nil {
				require.GreaterOrEqual(t, len(proc.SecurityFixes), 1)
				assert.Equal(t, tt.validateFirst.Module, proc.SecurityFixes[0].Module)
				assert.Equal(t, tt.validateFirst.Vulnerability, proc.SecurityFixes[0].Vulnerability)
				assert.Equal(t, tt.validateFirst.OldVersion, proc.SecurityFixes[0].OldVersion)
				assert.Equal(t, tt.validateFirst.NewVersion, proc.SecurityFixes[0].NewVersion)
				assert.Equal(t, tt.validateFirst.Severity, proc.SecurityFixes[0].Severity)
			}

			// Verify changes have correct type
			for _, change := range proc.GetChanges() {
				assert.Equal(t, "security", change.Type)
			}
		})
	}
}

func TestGoBumpProcessor_AddSecurityFix_Changes(t *testing.T) {
	proc := NewGoBumpProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

	fix := SecurityFix{
		Module:        "golang.org/x/crypto",
		Vulnerability: "CVE-2023-1234",
		OldVersion:    "v0.13.0",
		NewVersion:    "v0.14.0",
		Severity:      "high",
	}

	proc.AddSecurityFix(fix)

	require.Equal(t, 1, len(proc.GetChanges()))
	change := proc.GetChanges()[0]

	assert.Equal(t, "security", change.Type)
	assert.Equal(t, "golang.org/x/crypto", change.Field)
	assert.Equal(t, "v0.13.0", change.OldValue)
	assert.Equal(t, "v0.14.0", change.NewValue)
	assert.Contains(t, change.Description, "security fix")
	assert.Contains(t, change.Description, "golang.org/x/crypto")
	assert.Contains(t, change.Description, "v0.13.0")
	assert.Contains(t, change.Description, "v0.14.0")
	assert.Contains(t, change.Reason, "vulnerability")
	assert.Contains(t, change.Reason, "CVE-2023-1234")
	assert.Contains(t, change.Reason, "high")
}

func TestGoBumpProcessor_MarkActualChangesApplied(t *testing.T) {
	proc := NewGoBumpProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

	// Initially false
	assert.False(t, proc.ActualChangesApplied)

	// Mark as applied
	proc.MarkActualChangesApplied()

	// Should be true
	assert.True(t, proc.ActualChangesApplied)

	// Calling multiple times should remain true
	proc.MarkActualChangesApplied()
	assert.True(t, proc.ActualChangesApplied)
}

func TestGoBumpProcessor_HasActualChanges(t *testing.T) {
	tests := []struct {
		name                 string
		setupProc            func(*GoBumpProcessor)
		wantHasActualChanges bool
	}{
		{
			name: "no changes - neither flag nor YAML",
			setupProc: func(proc *GoBumpProcessor) {
				proc.OriginalYAML = []byte("original yaml content")
				proc.CurrentYAML = []byte("original yaml content")
				proc.ActualChangesApplied = false
			},
			wantHasActualChanges: false,
		},
		{
			name: "flag set - has actual changes",
			setupProc: func(proc *GoBumpProcessor) {
				proc.OriginalYAML = []byte("original yaml content")
				proc.CurrentYAML = []byte("original yaml content")
				proc.ActualChangesApplied = true
			},
			wantHasActualChanges: true,
		},
		{
			name: "YAML changed - has actual changes",
			setupProc: func(proc *GoBumpProcessor) {
				proc.OriginalYAML = []byte("original yaml content")
				proc.CurrentYAML = []byte("modified yaml content")
				proc.ActualChangesApplied = false
			},
			wantHasActualChanges: true,
		},
		{
			name: "both flag and YAML changed",
			setupProc: func(proc *GoBumpProcessor) {
				proc.OriginalYAML = []byte("original yaml content")
				proc.CurrentYAML = []byte("modified yaml content")
				proc.ActualChangesApplied = true
			},
			wantHasActualChanges: true,
		},
		{
			name: "nil YAML - considered different",
			setupProc: func(proc *GoBumpProcessor) {
				proc.OriginalYAML = nil
				proc.CurrentYAML = []byte("some content")
				proc.ActualChangesApplied = false
			},
			wantHasActualChanges: true,
		},
		{
			name: "empty YAML vs nil - considered same by bytes.Equal",
			setupProc: func(proc *GoBumpProcessor) {
				proc.OriginalYAML = []byte("")
				proc.CurrentYAML = nil
				proc.ActualChangesApplied = false
			},
			wantHasActualChanges: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewGoBumpProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)
			tt.setupProc(proc)

			result := proc.HasActualChanges()
			assert.Equal(t, tt.wantHasActualChanges, result)
		})
	}
}

func TestGoBumpProcessor_ToResult(t *testing.T) {
	tests := []struct {
		name                string
		setupProc           func(*GoBumpProcessor)
		wantVulnsFound      int
		wantVulnsFixed      int
		wantSecurityFixes   int
		wantActionsApplied  int
		wantOldEpoch        int64
		wantNewEpoch        int64
		wantEpochChanged    bool
		wantFileWasWritten  bool
		wantMessages        int
		wantError           string
		validatePackageName string
		validateFilePath    string
	}{
		{
			name: "no vulnerabilities - clean state",
			setupProc: func(proc *GoBumpProcessor) {
				// Default state - no vulnerabilities
			},
			wantVulnsFound:      0,
			wantVulnsFixed:      0,
			wantSecurityFixes:   0,
			wantActionsApplied:  0,
			wantOldEpoch:        0,
			wantNewEpoch:        0,
			wantEpochChanged:    false,
			wantFileWasWritten:  false,
			wantMessages:        0,
			wantError:           "",
			validatePackageName: "test-pkg",
			validateFilePath:    "/test/path.yaml",
		},
		{
			name: "vulnerabilities found and fixed",
			setupProc: func(proc *GoBumpProcessor) {
				proc.VulnerabilityAnalysis = &VulnerabilityAnalysis{
					VulnerabilitiesFound: 3,
					BumpActions: []BumpAction{
						{Action: "update", PipelineIdx: 0, Dependencies: []string{"dep1@v1.0.0"}},
						{Action: "insert", PipelineIdx: -1, Dependencies: []string{"dep2@v2.0.0"}},
					},
				}
				proc.AddSecurityFix(SecurityFix{
					Module:        "golang.org/x/crypto",
					Vulnerability: "CVE-2023-1234",
					OldVersion:    "v0.13.0",
					NewVersion:    "v0.14.0",
					Severity:      "high",
				})
				proc.AddSecurityFix(SecurityFix{
					Module:        "github.com/gin-gonic/gin",
					Vulnerability: "GHSA-xxxx-yyyy",
					OldVersion:    "v1.9.0",
					NewVersion:    "v1.9.1",
					Severity:      "medium",
				})
				proc.OriginalYAML = []byte("original")
				proc.CurrentYAML = []byte("modified")
				proc.AddMessage("Fixed 2 vulnerabilities")
			},
			wantVulnsFound:      3,
			wantVulnsFixed:      2,
			wantSecurityFixes:   2,
			wantActionsApplied:  2,
			wantOldEpoch:        0,
			wantNewEpoch:        0,
			wantEpochChanged:    false,
			wantFileWasWritten:  true,
			wantMessages:        1,
			wantError:           "",
			validatePackageName: "test-pkg",
			validateFilePath:    "/test/path.yaml",
		},
		{
			name: "epoch changed with fixes",
			setupProc: func(proc *GoBumpProcessor) {
				proc.VulnerabilityAnalysis = &VulnerabilityAnalysis{
					VulnerabilitiesFound: 1,
					BumpActions: []BumpAction{
						{Action: "update", PipelineIdx: 0},
					},
				}
				proc.AddSecurityFix(SecurityFix{
					Module:        "test/module",
					Vulnerability: "CVE-2024-1111",
					OldVersion:    "v1.0.0",
					NewVersion:    "v1.1.0",
					Severity:      "critical",
				})
				proc.SetEpochUpdate(5, 6)
				proc.OriginalYAML = []byte("original")
				proc.CurrentYAML = []byte("modified")
			},
			wantVulnsFound:      1,
			wantVulnsFixed:      1,
			wantSecurityFixes:   1,
			wantActionsApplied:  1,
			wantOldEpoch:        5,
			wantNewEpoch:        6,
			wantEpochChanged:    true,
			wantFileWasWritten:  true,
			wantMessages:        0,
			wantError:           "",
			validatePackageName: "test-pkg",
			validateFilePath:    "/test/path.yaml",
		},
		{
			name: "error during processing",
			setupProc: func(proc *GoBumpProcessor) {
				proc.VulnerabilityAnalysis = &VulnerabilityAnalysis{
					VulnerabilitiesFound: 2,
				}
				proc.AddError(assert.AnError)
				proc.AddMessage("Processing failed")
			},
			wantVulnsFound:      2,
			wantVulnsFixed:      0,
			wantSecurityFixes:   0,
			wantActionsApplied:  0,
			wantOldEpoch:        0,
			wantNewEpoch:        0,
			wantEpochChanged:    false,
			wantFileWasWritten:  false,
			wantMessages:        1,
			wantError:           assert.AnError.Error(),
			validatePackageName: "test-pkg",
			validateFilePath:    "/test/path.yaml",
		},
		{
			name: "vulnerabilities found but no actual changes",
			setupProc: func(proc *GoBumpProcessor) {
				proc.VulnerabilityAnalysis = &VulnerabilityAnalysis{
					VulnerabilitiesFound: 2,
					BumpActions: []BumpAction{
						{Action: "keep", PipelineIdx: 0},
						{Action: "keep", PipelineIdx: 1},
					},
				}
				// No changes to YAML, no ActualChangesApplied flag
				proc.OriginalYAML = []byte("original")
				proc.CurrentYAML = []byte("original")
			},
			wantVulnsFound:      2,
			wantVulnsFixed:      0,
			wantSecurityFixes:   0,
			wantActionsApplied:  0, // No actions applied because HasActualChanges is false
			wantOldEpoch:        0,
			wantNewEpoch:        0,
			wantEpochChanged:    false,
			wantFileWasWritten:  false,
			wantMessages:        0,
			wantError:           "",
			validatePackageName: "test-pkg",
			validateFilePath:    "/test/path.yaml",
		},
		{
			name: "multiple messages and fixes",
			setupProc: func(proc *GoBumpProcessor) {
				proc.VulnerabilityAnalysis = &VulnerabilityAnalysis{
					VulnerabilitiesFound: 5,
					BumpActions: []BumpAction{
						{Action: "update"},
						{Action: "insert"},
					},
				}
				for i := 0; i < 3; i++ {
					proc.AddSecurityFix(SecurityFix{
						Module:        "test/module",
						Vulnerability: "CVE-2024-1111",
						OldVersion:    "v1.0.0",
						NewVersion:    "v1.1.0",
						Severity:      "high",
					})
				}
				proc.AddMessage("Message 1")
				proc.AddMessage("Message 2")
				proc.AddMessage("Message 3")
				proc.OriginalYAML = []byte("original")
				proc.CurrentYAML = []byte("modified")
			},
			wantVulnsFound:      5,
			wantVulnsFixed:      3,
			wantSecurityFixes:   3,
			wantActionsApplied:  2,
			wantOldEpoch:        0,
			wantNewEpoch:        0,
			wantEpochChanged:    false,
			wantFileWasWritten:  true,
			wantMessages:        3,
			wantError:           "",
			validatePackageName: "test-pkg",
			validateFilePath:    "/test/path.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewGoBumpProcessor(tt.validateFilePath, tt.validatePackageName, "1.0.0", tt.wantOldEpoch)
			tt.setupProc(proc)

			result := proc.ToResult()

			require.NotNil(t, result)
			assert.Equal(t, tt.validatePackageName, result.PackageName)
			assert.Equal(t, tt.validateFilePath, result.FilePath)
			assert.Equal(t, tt.wantVulnsFound, result.VulnerabilitiesFound)
			assert.Equal(t, tt.wantVulnsFixed, result.VulnerabilitiesFixed)
			assert.Equal(t, tt.wantSecurityFixes, len(result.SecurityFixes))
			assert.Equal(t, tt.wantActionsApplied, len(result.ActionsApplied))
			assert.Equal(t, tt.wantOldEpoch, result.OldEpoch)
			assert.Equal(t, tt.wantNewEpoch, result.NewEpoch)
			assert.Equal(t, tt.wantEpochChanged, result.EpochChanged)
			assert.Equal(t, tt.wantFileWasWritten, result.FileWasWritten)
			assert.Equal(t, tt.wantMessages, len(result.Messages))
			assert.Equal(t, tt.wantError, result.Error)
		})
	}
}

func TestGoBumpProcessor_Integration(t *testing.T) {
	tests := []struct {
		name           string
		scenario       func(*GoBumpProcessor)
		validateResult func(*testing.T, *GoBumpResult)
	}{
		{
			name: "complete vulnerability fix workflow",
			scenario: func(proc *GoBumpProcessor) {
				// Set up vulnerability analysis
				proc.VulnerabilityAnalysis = &VulnerabilityAnalysis{
					VulnerabilitiesFound: 3,
					CriticalCount:        1,
					HighCount:            2,
					BumpActions: []BumpAction{
						{
							Action:       "update",
							PipelineIdx:  0,
							Dependencies: []string{"golang.org/x/crypto@v0.14.0"},
							Reason:       "security fix for CVE-2023-1234",
						},
						{
							Action:       "insert",
							PipelineIdx:  -1,
							Dependencies: []string{"github.com/gin-gonic/gin@v1.9.1"},
							Reason:       "security fix for GHSA-xxxx-yyyy",
						},
					},
				}

				// Add security fixes
				proc.AddSecurityFix(SecurityFix{
					Module:        "golang.org/x/crypto",
					Vulnerability: "CVE-2023-1234",
					OldVersion:    "v0.13.0",
					NewVersion:    "v0.14.0",
					Severity:      "critical",
				})
				proc.AddSecurityFix(SecurityFix{
					Module:        "github.com/gin-gonic/gin",
					Vulnerability: "GHSA-xxxx-yyyy",
					OldVersion:    "v1.9.0",
					NewVersion:    "v1.9.1",
					Severity:      "high",
				})

				// Simulate YAML changes
				proc.OriginalYAML = []byte("original yaml content")
				proc.CurrentYAML = []byte("modified yaml content with fixes")
				proc.MarkActualChangesApplied()

				// Bump epoch
				proc.SetEpochUpdate(5, 6)

				// Add messages
				proc.AddMessage("Fixed 2 critical/high vulnerabilities")
				proc.AddMessage("Updated go/bump pipelines")
			},
			validateResult: func(t *testing.T, result *GoBumpResult) {
				assert.Equal(t, 3, result.VulnerabilitiesFound)
				assert.Equal(t, 2, result.VulnerabilitiesFixed)
				assert.Equal(t, 2, len(result.SecurityFixes))
				assert.Equal(t, 2, len(result.ActionsApplied))
				assert.Equal(t, int64(5), result.OldEpoch)
				assert.Equal(t, int64(6), result.NewEpoch)
				assert.True(t, result.EpochChanged)
				assert.True(t, result.FileWasWritten)
				assert.Equal(t, 2, len(result.Messages))
				assert.Empty(t, result.Error)

				// Validate security fixes
				assert.Equal(t, "golang.org/x/crypto", result.SecurityFixes[0].Module)
				assert.Equal(t, "critical", result.SecurityFixes[0].Severity)
				assert.Equal(t, "github.com/gin-gonic/gin", result.SecurityFixes[1].Module)
				assert.Equal(t, "high", result.SecurityFixes[1].Severity)
			},
		},
		{
			name: "vulnerabilities found but already fixed",
			scenario: func(proc *GoBumpProcessor) {
				proc.VulnerabilityAnalysis = &VulnerabilityAnalysis{
					VulnerabilitiesFound: 2,
					BumpActions: []BumpAction{
						{Action: "keep", Reason: "already at required version"},
						{Action: "keep", Reason: "already at required version"},
					},
				}

				// No actual changes
				proc.OriginalYAML = []byte("yaml content")
				proc.CurrentYAML = []byte("yaml content")

				proc.AddMessage("No updates needed - all dependencies at secure versions")
			},
			validateResult: func(t *testing.T, result *GoBumpResult) {
				assert.Equal(t, 2, result.VulnerabilitiesFound)
				assert.Equal(t, 0, result.VulnerabilitiesFixed)
				assert.Equal(t, 0, len(result.SecurityFixes))
				assert.Equal(t, 0, len(result.ActionsApplied))
				assert.False(t, result.EpochChanged)
				assert.False(t, result.FileWasWritten)
				assert.Equal(t, 1, len(result.Messages))
			},
		},
		{
			name: "error during vulnerability scan",
			scenario: func(proc *GoBumpProcessor) {
				proc.VulnerabilityAnalysis = &VulnerabilityAnalysis{
					VulnerabilitiesFound: 0,
				}

				proc.AddError(assert.AnError)
				proc.AddMessage("Vulnerability scan failed")
			},
			validateResult: func(t *testing.T, result *GoBumpResult) {
				assert.Equal(t, 0, result.VulnerabilitiesFound)
				assert.Equal(t, 0, result.VulnerabilitiesFixed)
				assert.NotEmpty(t, result.Error)
				assert.Equal(t, 1, len(result.Messages))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewGoBumpProcessor("/test/package.yaml", "test-package", "1.2.3", 5)
			tt.scenario(proc)

			result := proc.ToResult()
			require.NotNil(t, result)

			tt.validateResult(t, result)

			// Common validations
			assert.Equal(t, "test-package", result.PackageName)
			assert.Equal(t, "/test/package.yaml", result.FilePath)
		})
	}
}

func TestGoBumpProcessor_BaseProcessorIntegration(t *testing.T) {
	proc := NewGoBumpProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

	// Test that BaseProcessor methods work
	proc.AddMessage("Test message 1")
	proc.AddMessage("Test message 2")
	assert.Equal(t, 2, len(proc.GetMessages()))

	proc.AddError(assert.AnError)
	assert.Equal(t, 1, len(proc.GetErrors()))

	proc.SetVersionUpdate("1.0.0", "1.1.0")
	assert.True(t, proc.IsVersionChanged())
	assert.Equal(t, "1.1.0", proc.GetLatestVersion())

	proc.SetEpochUpdate(0, 1)
	assert.True(t, proc.IsEpochChanged())
	assert.Equal(t, int64(1), proc.GetNewEpoch())

	// Add security fix creates a change
	proc.AddSecurityFix(SecurityFix{
		Module:        "test/module",
		Vulnerability: "CVE-2024-1111",
		OldVersion:    "v1.0.0",
		NewVersion:    "v1.1.0",
		Severity:      "high",
	})

	// Should have changes from version update, epoch update, and security fix
	assert.True(t, proc.HasChanges())
	assert.GreaterOrEqual(t, len(proc.GetChanges()), 3)

	// Test context
	proc.SetContext("test_key", "test_value")
	assert.Equal(t, "test_value", proc.GetContext("test_key"))

	// Test options
	opts := processor.ProcessorOptions{
		DryRun: true,
		Force:  true,
	}
	proc.SetOptions(opts)
	assert.Equal(t, opts, proc.GetOptions())
	assert.True(t, proc.GetOptions().DryRun)
}

func TestGoBumpProcessor_ChangeTracking(t *testing.T) {
	proc := NewGoBumpProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

	// Add multiple security fixes
	fixes := []SecurityFix{
		{Module: "mod1", Vulnerability: "CVE-1", OldVersion: "v1.0", NewVersion: "v1.1", Severity: "high"},
		{Module: "mod2", Vulnerability: "CVE-2", OldVersion: "v2.0", NewVersion: "v2.1", Severity: "critical"},
		{Module: "mod3", Vulnerability: "CVE-3", OldVersion: "v3.0", NewVersion: "v3.1", Severity: "medium"},
	}

	for _, fix := range fixes {
		proc.AddSecurityFix(fix)
	}

	changes := proc.GetChanges()
	assert.Equal(t, 3, len(changes))

	// All changes should be security type
	for _, change := range changes {
		assert.Equal(t, "security", change.Type)
		assert.NotEmpty(t, change.Field)
		assert.NotEmpty(t, change.OldValue)
		assert.NotEmpty(t, change.NewValue)
		assert.NotEmpty(t, change.Description)
		assert.NotEmpty(t, change.Reason)
	}

	// Verify change details for first fix
	firstChange := changes[0]
	assert.Equal(t, "mod1", firstChange.Field)
	assert.Equal(t, "v1.0", firstChange.OldValue)
	assert.Equal(t, "v1.1", firstChange.NewValue)
	assert.Contains(t, firstChange.Description, "security fix")
	assert.Contains(t, firstChange.Reason, "CVE-1")
}
