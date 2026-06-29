package processor

import (
	"fmt"
	"log/slog"
	"os"
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewBaseProcessor tests the constructor
func TestNewBaseProcessor(t *testing.T) {
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
			filePath:       "/path/to/another.yaml",
			packageName:    "another-package",
			currentVersion: "0.1.0",
			currentEpoch:   0,
		},
		{
			name:           "empty version",
			filePath:       "/test.yaml",
			packageName:    "test",
			currentVersion: "",
			currentEpoch:   10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor(tt.filePath, tt.packageName, tt.currentVersion, tt.currentEpoch)

			require.NotNil(t, proc)
			assert.Equal(t, tt.filePath, proc.FilePath)
			assert.Equal(t, tt.packageName, proc.PackageName)
			assert.Equal(t, tt.currentVersion, proc.CurrentVersion)
			assert.Equal(t, tt.currentEpoch, proc.CurrentEpoch)
			assert.Equal(t, tt.currentEpoch, proc.OldEpoch)
			assert.Equal(t, tt.currentEpoch, proc.NewEpoch)
			assert.NotNil(t, proc.Logger)
			assert.NotNil(t, proc.Changes)
			assert.NotNil(t, proc.Messages)
			assert.NotNil(t, proc.Errors)
			assert.NotNil(t, proc.Context)
			assert.Empty(t, proc.Changes)
			assert.Empty(t, proc.Messages)
			assert.Empty(t, proc.Errors)
			assert.Empty(t, proc.Context)
			assert.False(t, proc.VersionChanged)
			assert.False(t, proc.EpochChanged)
		})
	}
}

// TestBaseProcessor_Identity tests identity getter methods
func TestBaseProcessor_Identity(t *testing.T) {
	filePath := "/path/to/test.yaml"
	packageName := "test-package"
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	proc := &BaseProcessor{
		FilePath:    filePath,
		PackageName: packageName,
		Logger:      logger,
	}

	assert.Equal(t, filePath, proc.GetFilePath())
	assert.Equal(t, packageName, proc.GetPackageName())
	assert.Equal(t, logger, proc.GetLogger())
}

// TestBaseProcessor_Configuration tests configuration getter/setter methods
func TestBaseProcessor_Configuration(t *testing.T) {
	config := &melange.Configuration{
		Package: melange.Package{
			Name:    "test-package",
			Version: "1.2.3",
			Epoch:   5,
		},
	}
	originalYAML := []byte("original yaml content")
	currentYAML := []byte("current yaml content")

	proc := &BaseProcessor{
		Config:       config,
		OriginalYAML: originalYAML,
		CurrentYAML:  currentYAML,
	}

	assert.Equal(t, config, proc.GetConfig())
	assert.Equal(t, originalYAML, proc.GetOriginalYAML())
	assert.Equal(t, currentYAML, proc.GetCurrentYAML())

	newYAML := []byte("new yaml content")
	proc.SetCurrentYAML(newYAML)
	assert.Equal(t, newYAML, proc.GetCurrentYAML())
}

// TestBaseProcessor_VersionTracking tests version tracking methods
func TestBaseProcessor_VersionTracking(t *testing.T) {
	tests := []struct {
		name           string
		initialVersion string
		latestVersion  string
		oldVersion     string
		newVersion     string
		wantChanged    bool
	}{
		{
			name:           "initial state - no change",
			initialVersion: "1.0.0",
			latestVersion:  "",
			oldVersion:     "",
			newVersion:     "",
			wantChanged:    false,
		},
		{
			name:           "version updated",
			initialVersion: "1.0.0",
			latestVersion:  "2.0.0",
			oldVersion:     "1.0.0",
			newVersion:     "2.0.0",
			wantChanged:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := &BaseProcessor{
				CurrentVersion: tt.initialVersion,
				LatestVersion:  tt.latestVersion,
				OldVersion:     tt.oldVersion,
				NewVersion:     tt.newVersion,
				VersionChanged: tt.wantChanged,
			}

			assert.Equal(t, tt.initialVersion, proc.GetCurrentVersion())
			assert.Equal(t, tt.latestVersion, proc.GetLatestVersion())
			assert.Equal(t, tt.wantChanged, proc.IsVersionChanged())
		})
	}
}

// TestBaseProcessor_SetVersionUpdate tests version update method
func TestBaseProcessor_SetVersionUpdate(t *testing.T) {
	tests := []struct {
		name       string
		oldVersion string
		newVersion string
	}{
		{
			name:       "major version bump",
			oldVersion: "1.0.0",
			newVersion: "2.0.0",
		},
		{
			name:       "minor version bump",
			oldVersion: "1.2.3",
			newVersion: "1.3.0",
		},
		{
			name:       "patch version bump",
			oldVersion: "1.2.3",
			newVersion: "1.2.4",
		},
		{
			name:       "empty to version",
			oldVersion: "",
			newVersion: "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor("/test.yaml", "test-pkg", tt.oldVersion, 0)

			proc.SetVersionUpdate(tt.oldVersion, tt.newVersion)

			assert.Equal(t, tt.oldVersion, proc.OldVersion)
			assert.Equal(t, tt.newVersion, proc.NewVersion)
			assert.Equal(t, tt.newVersion, proc.LatestVersion)
			assert.True(t, proc.IsVersionChanged())

			// Check that a change was added
			assert.True(t, proc.HasChanges())
			changes := proc.GetChanges()
			require.Len(t, changes, 1)
			assert.Equal(t, "version", changes[0].Type)
			assert.Equal(t, "package.version", changes[0].Field)
			assert.Equal(t, tt.oldVersion, changes[0].OldValue)
			assert.Equal(t, tt.newVersion, changes[0].NewValue)
			assert.Contains(t, changes[0].Description, tt.oldVersion)
			assert.Contains(t, changes[0].Description, tt.newVersion)
		})
	}
}

// TestBaseProcessor_EpochTracking tests epoch tracking methods
func TestBaseProcessor_EpochTracking(t *testing.T) {
	tests := []struct {
		name         string
		currentEpoch int64
		newEpoch     int64
		wantChanged  bool
	}{
		{
			name:         "initial state - no change",
			currentEpoch: 5,
			newEpoch:     5,
			wantChanged:  false,
		},
		{
			name:         "epoch incremented",
			currentEpoch: 5,
			newEpoch:     6,
			wantChanged:  true,
		},
		{
			name:         "epoch reset to zero",
			currentEpoch: 10,
			newEpoch:     0,
			wantChanged:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := &BaseProcessor{
				CurrentEpoch: tt.currentEpoch,
				NewEpoch:     tt.newEpoch,
				EpochChanged: tt.wantChanged,
			}

			assert.Equal(t, tt.currentEpoch, proc.GetCurrentEpoch())
			assert.Equal(t, tt.newEpoch, proc.GetNewEpoch())
			assert.Equal(t, tt.wantChanged, proc.IsEpochChanged())
		})
	}
}

// TestBaseProcessor_SetEpochUpdate tests epoch update method
func TestBaseProcessor_SetEpochUpdate(t *testing.T) {
	tests := []struct {
		name     string
		oldEpoch int64
		newEpoch int64
	}{
		{
			name:     "increment epoch",
			oldEpoch: 5,
			newEpoch: 6,
		},
		{
			name:     "reset to zero",
			oldEpoch: 10,
			newEpoch: 0,
		},
		{
			name:     "large increment",
			oldEpoch: 0,
			newEpoch: 100,
		},
		{
			name:     "same epoch (edge case)",
			oldEpoch: 5,
			newEpoch: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", tt.oldEpoch)

			proc.SetEpochUpdate(tt.oldEpoch, tt.newEpoch)

			assert.Equal(t, tt.oldEpoch, proc.OldEpoch)
			assert.Equal(t, tt.newEpoch, proc.NewEpoch)
			assert.True(t, proc.IsEpochChanged())

			// Check that a change was added
			assert.True(t, proc.HasChanges())
			changes := proc.GetChanges()
			require.Len(t, changes, 1)
			assert.Equal(t, "epoch", changes[0].Type)
			assert.Equal(t, "package.epoch", changes[0].Field)
			assert.Equal(t, fmt.Sprintf("%d", tt.oldEpoch), changes[0].OldValue)
			assert.Equal(t, fmt.Sprintf("%d", tt.newEpoch), changes[0].NewValue)
			assert.Contains(t, changes[0].Description, fmt.Sprintf("%d", tt.oldEpoch))
			assert.Contains(t, changes[0].Description, fmt.Sprintf("%d", tt.newEpoch))
		})
	}
}

// TestBaseProcessor_ChangeTracking tests change tracking methods
func TestBaseProcessor_ChangeTracking(t *testing.T) {
	tests := []struct {
		name            string
		changes         []Change
		wantHasChanges  bool
		wantChangeCount int
	}{
		{
			name:            "no changes",
			changes:         []Change{},
			wantHasChanges:  false,
			wantChangeCount: 0,
		},
		{
			name: "single version change",
			changes: []Change{
				{Type: "version", Field: "package.version", OldValue: "1.0.0", NewValue: "2.0.0"},
			},
			wantHasChanges:  true,
			wantChangeCount: 1,
		},
		{
			name: "multiple changes",
			changes: []Change{
				{Type: "version", Field: "package.version", OldValue: "1.0.0", NewValue: "2.0.0"},
				{Type: "epoch", Field: "package.epoch", OldValue: "5", NewValue: "0"},
				{Type: "security", Field: "pipeline", Description: "CVE-2024-1234 fixed"},
			},
			wantHasChanges:  true,
			wantChangeCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

			for _, change := range tt.changes {
				proc.AddChange(change)
			}

			assert.Equal(t, tt.wantHasChanges, proc.HasChanges())
			assert.Equal(t, tt.wantChangeCount, len(proc.GetChanges()))
			assert.Equal(t, tt.changes, proc.GetChanges())
		})
	}
}

// TestBaseProcessor_HasFileChanges tests file change detection
func TestBaseProcessor_HasFileChanges(t *testing.T) {
	tests := []struct {
		name            string
		originalYAML    []byte
		currentYAML     []byte
		wantFileChanges bool
	}{
		{
			name:            "no file changes - both nil",
			originalYAML:    nil,
			currentYAML:     nil,
			wantFileChanges: false,
		},
		{
			name:            "no file changes - identical content",
			originalYAML:    []byte("package:\n  version: 1.0.0"),
			currentYAML:     []byte("package:\n  version: 1.0.0"),
			wantFileChanges: false,
		},
		{
			name:            "file changed - different content",
			originalYAML:    []byte("package:\n  version: 1.0.0"),
			currentYAML:     []byte("package:\n  version: 2.0.0"),
			wantFileChanges: true,
		},
		{
			name:            "file changed - original nil",
			originalYAML:    nil,
			currentYAML:     []byte("package:\n  version: 1.0.0"),
			wantFileChanges: true,
		},
		{
			name:            "file changed - current nil",
			originalYAML:    []byte("package:\n  version: 1.0.0"),
			currentYAML:     nil,
			wantFileChanges: true,
		},
		{
			name:            "file changed - whitespace difference",
			originalYAML:    []byte("package:\n  version: 1.0.0"),
			currentYAML:     []byte("package:\n  version: 1.0.0\n"),
			wantFileChanges: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := &BaseProcessor{
				OriginalYAML: tt.originalYAML,
				CurrentYAML:  tt.currentYAML,
			}

			assert.Equal(t, tt.wantFileChanges, proc.HasFileChanges())
		})
	}
}

// TestBaseProcessor_MessageManagement tests message management methods
func TestBaseProcessor_MessageManagement(t *testing.T) {
	tests := []struct {
		name         string
		messages     []string
		wantMessages []string
	}{
		{
			name:         "no messages",
			messages:     []string{},
			wantMessages: []string{},
		},
		{
			name:         "single message",
			messages:     []string{"test message"},
			wantMessages: []string{"test message"},
		},
		{
			name: "multiple messages",
			messages: []string{
				"first message",
				"second message",
				"third message",
			},
			wantMessages: []string{
				"first message",
				"second message",
				"third message",
			},
		},
		{
			name:         "empty string message",
			messages:     []string{""},
			wantMessages: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

			for _, msg := range tt.messages {
				proc.AddMessage(msg)
			}

			assert.Equal(t, tt.wantMessages, proc.GetMessages())
		})
	}
}

// TestBaseProcessor_ErrorManagement tests error management methods
func TestBaseProcessor_ErrorManagement(t *testing.T) {
	tests := []struct {
		name       string
		errors     []error
		wantErrors []error
	}{
		{
			name:       "no errors",
			errors:     []error{},
			wantErrors: []error{},
		},
		{
			name:       "single error",
			errors:     []error{fmt.Errorf("test error")},
			wantErrors: []error{fmt.Errorf("test error")},
		},
		{
			name: "multiple errors",
			errors: []error{
				fmt.Errorf("first error"),
				fmt.Errorf("second error"),
				fmt.Errorf("third error"),
			},
			wantErrors: []error{
				fmt.Errorf("first error"),
				fmt.Errorf("second error"),
				fmt.Errorf("third error"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

			for _, err := range tt.errors {
				proc.AddError(err)
			}

			gotErrors := proc.GetErrors()
			require.Equal(t, len(tt.wantErrors), len(gotErrors))
			for i, wantErr := range tt.wantErrors {
				assert.Equal(t, wantErr.Error(), gotErrors[i].Error())
			}
		})
	}
}

// TestBaseProcessor_Options tests options methods
func TestBaseProcessor_Options(t *testing.T) {
	tests := []struct {
		name    string
		options ProcessorOptions
	}{
		{
			name: "default options",
			options: ProcessorOptions{
				DryRun:        false,
				Force:         false,
				SharedUpdates: false,
				BackupSuffix:  "",
				TempDir:       "",
			},
		},
		{
			name: "custom options",
			options: ProcessorOptions{
				DryRun:        true,
				Force:         true,
				SharedUpdates: true,
				BackupSuffix:  ".bak",
				TempDir:       "/tmp/choam",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

			proc.SetOptions(tt.options)
			assert.Equal(t, tt.options, proc.GetOptions())
		})
	}
}

// TestBaseProcessor_Context tests context storage methods
func TestBaseProcessor_Context(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value any
	}{
		{
			name:  "string value",
			key:   "test-key",
			value: "test-value",
		},
		{
			name:  "int value",
			key:   "count",
			value: 42,
		},
		{
			name:  "bool value",
			key:   "enabled",
			value: true,
		},
		{
			name:  "struct value",
			key:   "config",
			value: struct{ Name string }{Name: "test"},
		},
		{
			name:  "slice value",
			key:   "items",
			value: []string{"a", "b", "c"},
		},
		{
			name:  "map value",
			key:   "metadata",
			value: map[string]string{"key": "value"},
		},
		{
			name:  "nil value",
			key:   "nil-value",
			value: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

			proc.SetContext(tt.key, tt.value)
			assert.Equal(t, tt.value, proc.GetContext(tt.key))
		})
	}
}

// TestBaseProcessor_Context_NonExistentKey tests retrieving non-existent context keys
func TestBaseProcessor_Context_NonExistentKey(t *testing.T) {
	proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

	value := proc.GetContext("non-existent-key")
	assert.Nil(t, value)
}

// TestBaseProcessor_Context_Overwrite tests overwriting context values
func TestBaseProcessor_Context_Overwrite(t *testing.T) {
	proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

	key := "test-key"
	firstValue := "first-value"
	secondValue := "second-value"

	proc.SetContext(key, firstValue)
	assert.Equal(t, firstValue, proc.GetContext(key))

	proc.SetContext(key, secondValue)
	assert.Equal(t, secondValue, proc.GetContext(key))
}

// TestBaseProcessor_IntegrationScenario tests realistic usage scenario
func TestBaseProcessor_IntegrationScenario(t *testing.T) {
	// Simulate a complete processor workflow
	proc := NewBaseProcessor("/path/to/package.yaml", "test-package", "1.0.0", 5)

	// Set configuration
	proc.Config = &melange.Configuration{
		Package: melange.Package{
			Name:    "test-package",
			Version: "1.0.0",
			Epoch:   5,
		},
	}

	originalYAML := []byte(`package:
  name: test-package
  version: "1.0.0"
  epoch: 5
`)
	proc.OriginalYAML = originalYAML
	proc.CurrentYAML = originalYAML

	// Set options
	proc.SetOptions(ProcessorOptions{
		DryRun: false,
		Force:  false,
	})

	// Add some context
	proc.SetContext("github_url", "https://github.com/test/test-package")
	proc.SetContext("has_security_fix", true)

	// Version update
	proc.SetVersionUpdate("1.0.0", "2.0.0")
	assert.True(t, proc.IsVersionChanged())
	assert.Equal(t, "2.0.0", proc.GetLatestVersion())

	// Epoch update
	proc.SetEpochUpdate(5, 0)
	assert.True(t, proc.IsEpochChanged())
	assert.Equal(t, int64(0), proc.GetNewEpoch())

	// Add security change
	proc.AddChange(Change{
		Type:        "security",
		Field:       "pipeline",
		Description: "CVE-2024-1234 fixed",
		Reason:      "security vulnerability",
	})

	// Add messages
	proc.AddMessage("Version updated successfully")
	proc.AddMessage("Epoch reset due to version change")

	// Simulate YAML modification
	newYAML := []byte(`package:
  name: test-package
  version: "2.0.0"
  epoch: 0
`)
	proc.SetCurrentYAML(newYAML)

	// Verify final state
	assert.True(t, proc.HasChanges())
	assert.True(t, proc.HasFileChanges())
	assert.Equal(t, 3, len(proc.GetChanges())) // version + epoch + security
	assert.Equal(t, 2, len(proc.GetMessages()))
	assert.Equal(t, 0, len(proc.GetErrors()))

	// Verify context
	assert.Equal(t, "https://github.com/test/test-package", proc.GetContext("github_url"))
	assert.Equal(t, true, proc.GetContext("has_security_fix"))

	// Verify changes
	changes := proc.GetChanges()
	var versionChange, epochChange, securityChange bool
	for _, change := range changes {
		switch change.Type {
		case "version":
			versionChange = true
			assert.Equal(t, "package.version", change.Field)
			assert.Equal(t, "1.0.0", change.OldValue)
			assert.Equal(t, "2.0.0", change.NewValue)
		case "epoch":
			epochChange = true
			assert.Equal(t, "package.epoch", change.Field)
			assert.Equal(t, "5", change.OldValue)
			assert.Equal(t, "0", change.NewValue)
		case "security":
			securityChange = true
			assert.Equal(t, "pipeline", change.Field)
		}
	}
	assert.True(t, versionChange, "version change should be tracked")
	assert.True(t, epochChange, "epoch change should be tracked")
	assert.True(t, securityChange, "security change should be tracked")
}

// TestBaseProcessor_ErrorAccumulation tests error accumulation during processing
func TestBaseProcessor_ErrorAccumulation(t *testing.T) {
	proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

	// Simulate various errors during processing
	proc.AddError(fmt.Errorf("failed to fetch latest version"))
	proc.AddError(fmt.Errorf("network timeout"))
	proc.AddError(fmt.Errorf("invalid YAML format"))

	errors := proc.GetErrors()
	require.Len(t, errors, 3)
	assert.Contains(t, errors[0].Error(), "failed to fetch")
	assert.Contains(t, errors[1].Error(), "network timeout")
	assert.Contains(t, errors[2].Error(), "invalid YAML")
}

// TestBaseProcessor_ChangeTypes tests different change types
func TestBaseProcessor_ChangeTypes(t *testing.T) {
	tests := []struct {
		name       string
		changeType string
		field      string
	}{
		{
			name:       "version change",
			changeType: "version",
			field:      "package.version",
		},
		{
			name:       "epoch change",
			changeType: "epoch",
			field:      "package.epoch",
		},
		{
			name:       "pipeline change",
			changeType: "pipeline",
			field:      "pipeline[0]",
		},
		{
			name:       "security change",
			changeType: "security",
			field:      "pipeline",
		},
		{
			name:       "dependency change",
			changeType: "dependency",
			field:      "environment.contents.packages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

			change := Change{
				Type:        tt.changeType,
				Field:       tt.field,
				OldValue:    "old",
				NewValue:    "new",
				Description: fmt.Sprintf("%s updated", tt.changeType),
			}

			proc.AddChange(change)

			changes := proc.GetChanges()
			require.Len(t, changes, 1)
			assert.Equal(t, tt.changeType, changes[0].Type)
			assert.Equal(t, tt.field, changes[0].Field)
		})
	}
}

// TestBaseProcessor_NilLogger tests behavior with nil logger
func TestBaseProcessor_NilLogger(t *testing.T) {
	proc := &BaseProcessor{
		FilePath:    "/test.yaml",
		PackageName: "test-pkg",
		Logger:      nil,
	}

	logger := proc.GetLogger()
	assert.Nil(t, logger)

	// WithStage should handle nil logger gracefully (will panic in real code)
	// This is a known edge case
}

// TestBaseProcessor_EmptyYAML tests behavior with empty YAML
func TestBaseProcessor_EmptyYAML(t *testing.T) {
	proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

	proc.OriginalYAML = []byte{}
	proc.CurrentYAML = []byte{}

	assert.False(t, proc.HasFileChanges())

	proc.CurrentYAML = []byte("changed")
	assert.True(t, proc.HasFileChanges())
}

// TestBaseProcessor_LargeChangeSet tests behavior with many changes
func TestBaseProcessor_LargeChangeSet(t *testing.T) {
	proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

	// Add 100 changes
	for i := range 100 {
		proc.AddChange(Change{
			Type:        "test",
			Field:       fmt.Sprintf("field-%d", i),
			OldValue:    fmt.Sprintf("old-%d", i),
			NewValue:    fmt.Sprintf("new-%d", i),
			Description: fmt.Sprintf("change %d", i),
		})
	}

	assert.True(t, proc.HasChanges())
	assert.Equal(t, 100, len(proc.GetChanges()))
}

// TestBaseProcessor_ConcurrentSafety tests thread safety (basic check)
// Note: BaseProcessor is NOT thread-safe by design, but we can verify
// that basic operations don't panic
func TestBaseProcessor_ConcurrentSafety(t *testing.T) {
	proc := NewBaseProcessor("/test.yaml", "test-pkg", "1.0.0", 0)

	// This test just ensures basic operations work
	// Real concurrent usage would require synchronization
	proc.AddChange(Change{Type: "test"})
	proc.AddMessage("test message")
	proc.AddError(fmt.Errorf("test error"))
	proc.SetContext("key", "value")

	assert.True(t, proc.HasChanges())
	assert.Equal(t, 1, len(proc.GetMessages()))
	assert.Equal(t, 1, len(proc.GetErrors()))
	assert.Equal(t, "value", proc.GetContext("key"))
}
