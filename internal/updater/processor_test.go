package updater

import (
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/isometry/choam/internal/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUpdaterProcessor(t *testing.T) {
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
			currentVersion: "1.0.0",
			currentEpoch:   1,
		},
		{
			name:           "zero epoch",
			filePath:       "/path/to/package.yaml",
			packageName:    "test-package",
			currentVersion: "2.3.4",
			currentEpoch:   0,
		},
		{
			name:           "empty version",
			filePath:       "/path/to/package.yaml",
			packageName:    "test-package",
			currentVersion: "",
			currentEpoch:   5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor(tt.filePath, tt.packageName, tt.currentVersion, tt.currentEpoch)

			require.NotNil(t, proc)
			assert.Equal(t, tt.filePath, proc.GetFilePath())
			assert.Equal(t, tt.packageName, proc.GetPackageName())
			assert.Equal(t, tt.currentVersion, proc.GetCurrentVersion())
			assert.Equal(t, tt.currentEpoch, proc.GetCurrentEpoch())
			assert.False(t, proc.UpdateAvailable)
			assert.False(t, proc.VersionChanged)
			assert.False(t, proc.IsManual)
			assert.Empty(t, proc.LatestVersion)
			assert.Empty(t, proc.UpdateSource)
			assert.NotNil(t, proc.PipelineChanges)
			assert.Len(t, proc.PipelineChanges, 0)
			assert.NotNil(t, proc.GetLogger())
		})
	}
}

func TestUpdaterProcessor_GetCurrentVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{
			name:    "standard version",
			version: "1.2.3",
		},
		{
			name:    "semantic version with v prefix",
			version: "v2.3.4",
		},
		{
			name:    "empty version",
			version: "",
		},
		{
			name:    "complex version",
			version: "11.0.27.6.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", tt.version, 0)
			assert.Equal(t, tt.version, proc.GetCurrentVersion())
		})
	}
}

func TestUpdaterProcessor_SetUpdateResult(t *testing.T) {
	tests := []struct {
		name          string
		hasUpdate     bool
		latestVersion string
		source        string
		isManual      bool
	}{
		{
			name:          "update available from github",
			hasUpdate:     true,
			latestVersion: "2.0.0",
			source:        "github",
			isManual:      false,
		},
		{
			name:          "update available from git",
			hasUpdate:     true,
			latestVersion: "1.5.0",
			source:        "git",
			isManual:      false,
		},
		{
			name:          "manual update from anitya",
			hasUpdate:     true,
			latestVersion: "3.0.0",
			source:        "anitya",
			isManual:      true,
		},
		{
			name:          "no update available",
			hasUpdate:     false,
			latestVersion: "1.0.0",
			source:        "github",
			isManual:      false,
		},
		{
			name:          "empty source",
			hasUpdate:     true,
			latestVersion: "1.1.0",
			source:        "",
			isManual:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

			proc.SetUpdateResult(tt.hasUpdate, tt.latestVersion, tt.source, tt.isManual)

			assert.Equal(t, tt.hasUpdate, proc.UpdateAvailable)
			assert.Equal(t, tt.latestVersion, proc.LatestVersion)
			assert.Equal(t, tt.source, proc.UpdateSource)
			assert.Equal(t, tt.isManual, proc.IsManual)
		})
	}
}

func TestUpdaterProcessor_SetVersionUpdate(t *testing.T) {
	tests := []struct {
		name         string
		oldVersion   string
		newVersion   string
		wantMessages int
		checkMessage bool
		expectedMsg  string
	}{
		{
			name:         "version update",
			oldVersion:   "1.0.0",
			newVersion:   "1.1.0",
			wantMessages: 1,
			checkMessage: true,
			expectedMsg:  "version updated: 1.0.0 -> 1.1.0",
		},
		{
			name:         "major version update",
			oldVersion:   "1.9.9",
			newVersion:   "2.0.0",
			wantMessages: 1,
			checkMessage: true,
			expectedMsg:  "version updated: 1.9.9 -> 2.0.0",
		},
		{
			name:         "same version",
			oldVersion:   "1.0.0",
			newVersion:   "1.0.0",
			wantMessages: 1,
			checkMessage: true,
			expectedMsg:  "version updated: 1.0.0 -> 1.0.0",
		},
		{
			name:         "empty versions",
			oldVersion:   "",
			newVersion:   "",
			wantMessages: 1,
			checkMessage: true,
			expectedMsg:  "version updated:  -> ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Suppress log output during tests
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			slog.SetDefault(logger)

			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", tt.oldVersion, 0)

			proc.SetVersionUpdate(tt.oldVersion, tt.newVersion)

			assert.True(t, proc.VersionChanged)
			assert.Equal(t, tt.newVersion, proc.LatestVersion)
			assert.Len(t, proc.GetMessages(), tt.wantMessages)

			if tt.checkMessage {
				assert.Contains(t, proc.GetMessages()[0], tt.expectedMsg)
			}
		})
	}
}

func TestUpdaterProcessor_GetLatestVersion(t *testing.T) {
	tests := []struct {
		name          string
		setVersion    string
		expectedEmpty bool
	}{
		{
			name:          "with latest version set",
			setVersion:    "2.0.0",
			expectedEmpty: false,
		},
		{
			name:          "empty latest version",
			setVersion:    "",
			expectedEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)
			proc.LatestVersion = tt.setVersion

			result := proc.GetLatestVersion()
			assert.Equal(t, tt.setVersion, result)

			if tt.expectedEmpty {
				assert.Empty(t, result)
			} else {
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestUpdaterProcessor_IsVersionChanged(t *testing.T) {
	tests := []struct {
		name           string
		versionChanged bool
	}{
		{
			name:           "version changed",
			versionChanged: true,
		},
		{
			name:           "version not changed",
			versionChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)
			proc.VersionChanged = tt.versionChanged

			assert.Equal(t, tt.versionChanged, proc.IsVersionChanged())
		})
	}
}

func TestUpdaterProcessor_GetNewEpoch(t *testing.T) {
	tests := []struct {
		name     string
		oldEpoch int64
		newEpoch int64
	}{
		{
			name:     "epoch unchanged",
			oldEpoch: 1,
			newEpoch: 1,
		},
		{
			name:     "epoch incremented",
			oldEpoch: 1,
			newEpoch: 2,
		},
		{
			name:     "zero to one",
			oldEpoch: 0,
			newEpoch: 1,
		},
		{
			name:     "large epoch",
			oldEpoch: 100,
			newEpoch: 101,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", tt.oldEpoch)
			proc.NewEpoch = tt.newEpoch

			assert.Equal(t, tt.newEpoch, proc.GetNewEpoch())
		})
	}
}

func TestUpdaterProcessor_GetOldEpoch(t *testing.T) {
	tests := []struct {
		name        string
		startEpoch  int64
		expectEpoch int64
	}{
		{
			name:        "epoch one",
			startEpoch:  1,
			expectEpoch: 1,
		},
		{
			name:        "epoch zero",
			startEpoch:  0,
			expectEpoch: 0,
		},
		{
			name:        "large epoch",
			startEpoch:  999,
			expectEpoch: 999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", tt.startEpoch)
			assert.Equal(t, tt.expectEpoch, proc.GetOldEpoch())
		})
	}
}

func TestUpdaterProcessor_AddPipelineChange(t *testing.T) {
	tests := []struct {
		name         string
		changes      []PipelineChange
		wantCount    int
		wantMessages int
	}{
		{
			name: "single pipeline change",
			changes: []PipelineChange{
				{
					Type:        "update",
					Index:       0,
					Field:       "with.version",
					OldValue:    "1.0.0",
					NewValue:    "1.1.0",
					Description: "Updated pipeline version",
					Reason:      "New version available",
				},
			},
			wantCount:    1,
			wantMessages: 1,
		},
		{
			name: "multiple pipeline changes",
			changes: []PipelineChange{
				{
					Type:        "insert",
					Index:       1,
					Field:       "uses",
					NewValue:    "go/build",
					Description: "Added build step",
				},
				{
					Type:        "remove",
					Index:       2,
					Field:       "runs",
					OldValue:    "old-command",
					Description: "Removed obsolete step",
				},
			},
			wantCount:    2,
			wantMessages: 2,
		},
		{
			name:         "no changes",
			changes:      []PipelineChange{},
			wantCount:    0,
			wantMessages: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Suppress log output during tests
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			slog.SetDefault(logger)

			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

			for _, change := range tt.changes {
				proc.AddPipelineChange(change)
			}

			assert.Len(t, proc.PipelineChanges, tt.wantCount)
			assert.Len(t, proc.GetMessages(), tt.wantMessages)

			// Verify messages match descriptions
			for i, change := range tt.changes {
				if i < len(proc.GetMessages()) {
					assert.Equal(t, change.Description, proc.GetMessages()[i])
				}
			}
		})
	}
}

func TestUpdaterProcessor_HasChanges(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(*UpdaterProcessor)
		expectChanges bool
	}{
		{
			name: "version changed",
			setup: func(p *UpdaterProcessor) {
				p.VersionChanged = true
			},
			expectChanges: true,
		},
		{
			name: "epoch changed",
			setup: func(p *UpdaterProcessor) {
				p.EpochChanged = true
			},
			expectChanges: true,
		},
		{
			name: "pipeline changes",
			setup: func(p *UpdaterProcessor) {
				p.PipelineChanges = []PipelineChange{
					{Type: "update", Description: "test"},
				}
			},
			expectChanges: true,
		},
		{
			name: "all changes",
			setup: func(p *UpdaterProcessor) {
				p.VersionChanged = true
				p.EpochChanged = true
				p.PipelineChanges = []PipelineChange{
					{Type: "update", Description: "test"},
				}
			},
			expectChanges: true,
		},
		{
			name: "no changes",
			setup: func(p *UpdaterProcessor) {
				// no changes
			},
			expectChanges: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)
			tt.setup(proc)

			assert.Equal(t, tt.expectChanges, proc.HasChanges())
		})
	}
}

func TestUpdaterProcessor_WithStage(t *testing.T) {
	proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

	stages := []string{"fetch", "parse", "validate", "update"}

	for _, stage := range stages {
		logger := proc.WithStage(stage)
		require.NotNil(t, logger)
		// Logger should be different instance with stage context
		assert.NotEqual(t, proc.GetLogger(), logger)
	}
}

func TestUpdaterProcessor_WithPipeline(t *testing.T) {
	proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)

	tests := []struct {
		stage string
		index int
	}{
		{stage: "go/build", index: 0},
		{stage: "go/bump", index: 1},
		{stage: "git-checkout", index: 2},
	}

	for _, tt := range tests {
		logger := proc.WithPipeline(tt.stage, tt.index)
		require.NotNil(t, logger)
		// Logger should be different instance with pipeline context
		assert.NotEqual(t, proc.GetLogger(), logger)
	}
}

func TestUpdaterProcessor_Summary(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(*UpdaterProcessor)
		wantContains string
	}{
		{
			name: "with errors",
			setup: func(p *UpdaterProcessor) {
				p.AddError(errors.New("test error"))
			},
			wantContains: "error",
		},
		{
			name: "up-to-date",
			setup: func(p *UpdaterProcessor) {
				p.UpdateAvailable = false
			},
			wantContains: "up-to-date",
		},
		{
			name: "manual update available",
			setup: func(p *UpdaterProcessor) {
				p.UpdateAvailable = true
				p.IsManual = true
				p.CurrentVersion = "1.0.0"
				p.LatestVersion = "2.0.0"
			},
			wantContains: "manual update available",
		},
		{
			name: "updated with changes",
			setup: func(p *UpdaterProcessor) {
				p.UpdateAvailable = true
				p.VersionChanged = true
				p.AddMessage("Version updated")
				p.AddMessage("Pipeline updated")
			},
			wantContains: "updated with",
		},
		{
			name: "update available not applied",
			setup: func(p *UpdaterProcessor) {
				p.UpdateAvailable = true
				p.CurrentVersion = "1.0.0"
				p.LatestVersion = "1.5.0"
			},
			wantContains: "update available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewUpdaterProcessor("/test/path.yaml", "test-pkg", "1.0.0", 0)
			tt.setup(proc)

			summary := proc.Summary()
			assert.Contains(t, summary, tt.wantContains)
			assert.Contains(t, summary, "test-pkg")
		})
	}
}

func TestUpdaterProcessor_Integration(t *testing.T) {
	t.Run("full update workflow", func(t *testing.T) {
		// Suppress log output during tests
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		slog.SetDefault(logger)

		proc := NewUpdaterProcessor("/test/package.yaml", "my-package", "1.0.0", 1)

		// Step 1: Check for updates
		proc.SetUpdateResult(true, "1.2.0", "github", false)
		assert.True(t, proc.UpdateAvailable)
		assert.Equal(t, "1.2.0", proc.LatestVersion)
		assert.Equal(t, "github", proc.UpdateSource)

		// Step 2: Apply version update
		proc.SetVersionUpdate("1.0.0", "1.2.0")
		assert.True(t, proc.IsVersionChanged())
		assert.Len(t, proc.GetMessages(), 1)

		// Step 3: Add pipeline changes
		proc.AddPipelineChange(PipelineChange{
			Type:        "update",
			Index:       0,
			Field:       "with.version",
			OldValue:    "1.0.0",
			NewValue:    "1.2.0",
			Description: "Updated pipeline version",
		})

		// Step 4: Add regular changes
		proc.AddChange(processor.Change{
			Type:        "version",
			Field:       "package.version",
			OldValue:    "1.0.0",
			NewValue:    "1.2.0",
			Description: "Version update",
		})

		// Verify final state
		assert.True(t, proc.HasChanges())
		assert.Len(t, proc.PipelineChanges, 1)
		assert.Len(t, proc.GetChanges(), 1)
		assert.Len(t, proc.GetMessages(), 2) // version update + pipeline change
		assert.Empty(t, proc.GetErrors())

		// Verify summary
		summary := proc.Summary()
		assert.Contains(t, summary, "my-package")
		assert.Contains(t, summary, "updated with")
	})

	t.Run("manual update workflow", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "my-package", "1.0.0", 0)

		// Manual update detected
		proc.SetUpdateResult(true, "2.0.0", "anitya", true)
		assert.True(t, proc.UpdateAvailable)
		assert.True(t, proc.IsManual)

		// No automatic changes applied
		assert.False(t, proc.HasChanges())

		// Summary should indicate manual update
		summary := proc.Summary()
		assert.Contains(t, summary, "manual update available")
		assert.Contains(t, summary, "1.0.0 -> 2.0.0")
	})

	t.Run("error handling workflow", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "my-package", "1.0.0", 0)

		// Start update
		proc.SetUpdateResult(true, "1.5.0", "github", false)

		// Encounter error
		proc.AddError(errors.New("network timeout"))
		proc.AddMessage("Failed to apply update")

		// Verify error state
		assert.Len(t, proc.GetErrors(), 1)
		assert.Contains(t, proc.GetErrors()[0].Error(), "network timeout")

		// Summary should indicate error
		summary := proc.Summary()
		assert.Contains(t, summary, "error")
	})

	t.Run("epoch and version changes", func(t *testing.T) {
		// Suppress log output during tests
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		slog.SetDefault(logger)

		proc := NewUpdaterProcessor("/test/package.yaml", "my-package", "1.0.0", 5)

		// Apply version update
		proc.SetVersionUpdate("1.0.0", "1.1.0")

		// Apply epoch update
		proc.SetEpochUpdate(5, 6)

		// Verify both changes tracked
		assert.True(t, proc.IsVersionChanged())
		assert.True(t, proc.IsEpochChanged())
		assert.True(t, proc.HasChanges())
		assert.Equal(t, int64(5), proc.GetOldEpoch())
		assert.Equal(t, int64(6), proc.GetNewEpoch())
	})
}

func TestUpdaterProcessor_ProcessorInterfaceCompliance(t *testing.T) {
	// Verify UpdaterProcessor implements processor.Processor interface
	var _ processor.Processor = (*UpdaterProcessor)(nil)

	// Test all interface methods
	t.Run("identity methods", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "test-pkg", "1.0.0", 0)
		assert.Equal(t, "/test/package.yaml", proc.GetFilePath())
		assert.Equal(t, "test-pkg", proc.GetPackageName())
		assert.NotNil(t, proc.GetLogger())
	})

	t.Run("configuration methods", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "test-pkg", "1.0.0", 0)
		// Config initially nil
		assert.Nil(t, proc.GetConfig())

		// YAML methods
		testYAML := []byte("test: yaml")
		proc.SetCurrentYAML(testYAML)
		assert.Equal(t, testYAML, proc.GetCurrentYAML())
	})

	t.Run("version tracking methods", func(t *testing.T) {
		// Suppress log output during tests
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		slog.SetDefault(logger)

		proc := NewUpdaterProcessor("/test/package.yaml", "test-pkg", "1.0.0", 0)
		assert.Equal(t, "1.0.0", proc.GetCurrentVersion())
		assert.Empty(t, proc.GetLatestVersion())
		assert.False(t, proc.IsVersionChanged())

		proc.SetVersionUpdate("1.0.0", "1.1.0")
		assert.True(t, proc.IsVersionChanged())
		assert.Equal(t, "1.1.0", proc.GetLatestVersion())
	})

	t.Run("epoch tracking methods", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "test-pkg", "1.0.0", 0)
		assert.Equal(t, int64(0), proc.GetCurrentEpoch())
		assert.Equal(t, int64(0), proc.GetNewEpoch())
		assert.False(t, proc.IsEpochChanged())

		proc.SetEpochUpdate(0, 1)
		assert.True(t, proc.IsEpochChanged())
		assert.Equal(t, int64(1), proc.GetNewEpoch())
	})

	t.Run("change tracking methods", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "test-pkg", "1.0.0", 0)
		assert.Empty(t, proc.GetChanges())
		assert.False(t, proc.HasFileChanges())

		change := processor.Change{
			Type:        "test",
			Description: "test change",
		}
		proc.AddChange(change)
		assert.Len(t, proc.GetChanges(), 1)
	})

	t.Run("messaging methods", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "test-pkg", "1.0.0", 0)
		assert.Empty(t, proc.GetMessages())
		assert.Empty(t, proc.GetErrors())

		proc.AddMessage("test message")
		assert.Len(t, proc.GetMessages(), 1)

		proc.AddError(errors.New("test error"))
		assert.Len(t, proc.GetErrors(), 1)
	})

	t.Run("options methods", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "test-pkg", "1.0.0", 0)
		opts := processor.ProcessorOptions{
			DryRun: true,
			Force:  true,
		}
		proc.SetOptions(opts)
		assert.Equal(t, opts, proc.GetOptions())
	})

	t.Run("context methods", func(t *testing.T) {
		proc := NewUpdaterProcessor("/test/package.yaml", "test-pkg", "1.0.0", 0)
		proc.SetContext("test-key", "test-value")
		assert.Equal(t, "test-value", proc.GetContext("test-key"))
	})
}
