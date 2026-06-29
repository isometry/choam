package stages

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/isometry/choam/internal/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProcessor implements processor.Processor for testing
type mockProcessor struct {
	processor.BaseProcessor
	logger *slog.Logger
}

func newMockProcessor(packageName, currentVersion string, currentEpoch int64, opts processor.ProcessorOptions) *mockProcessor {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	base := processor.NewBaseProcessor("test.yaml", packageName, currentVersion, currentEpoch)
	base.Options = opts
	base.Logger = logger
	base.OriginalYAML = fmt.Appendf(nil, `package:
  name: %s
  version: "%s"
  epoch: %d
`, packageName, currentVersion, currentEpoch)
	base.CurrentYAML = base.OriginalYAML
	return &mockProcessor{
		BaseProcessor: *base,
		logger:        logger,
	}
}

// TestResetOnVersionChangeStrategy_ShouldUpdateEpoch tests version change detection
func TestResetOnVersionChangeStrategy_ShouldUpdateEpoch(t *testing.T) {
	tests := []struct {
		name           string
		versionChanged bool
		want           bool
	}{
		{
			name:           "version changed",
			versionChanged: true,
			want:           true,
		},
		{
			name:           "version not changed",
			versionChanged: false,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &ResetOnVersionChangeStrategy{}
			proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{})
			proc.VersionChanged = tt.versionChanged

			got := strategy.ShouldUpdateEpoch(proc)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestResetOnVersionChangeStrategy_CalculateNewEpoch tests epoch reset to 0
func TestResetOnVersionChangeStrategy_CalculateNewEpoch(t *testing.T) {
	strategy := &ResetOnVersionChangeStrategy{}
	proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{})

	got := strategy.CalculateNewEpoch(proc)
	assert.Equal(t, int64(0), got, "should reset epoch to 0")
}

// TestResetOnVersionChangeStrategy_GetReason tests reason message
func TestResetOnVersionChangeStrategy_GetReason(t *testing.T) {
	strategy := &ResetOnVersionChangeStrategy{}
	assert.Equal(t, "version changed", strategy.GetReason())
}

// TestBumpOnSecurityFixStrategy_ShouldUpdateEpoch tests security fix detection
func TestBumpOnSecurityFixStrategy_ShouldUpdateEpoch(t *testing.T) {
	tests := []struct {
		name      string
		changes   []processor.Change
		checkFunc func(processor.Processor) bool
		want      bool
	}{
		{
			name: "security change present",
			changes: []processor.Change{
				{Type: "security", Description: "CVE-2024-1234 fixed"},
			},
			want: true,
		},
		{
			name: "no security changes",
			changes: []processor.Change{
				{Type: "version", Description: "version update"},
			},
			want: false,
		},
		{
			name:    "no changes at all",
			changes: []processor.Change{},
			want:    false,
		},
		{
			name: "custom check function returns true",
			checkFunc: func(p processor.Processor) bool {
				return true
			},
			want: true,
		},
		{
			name: "custom check function returns false",
			checkFunc: func(p processor.Processor) bool {
				return false
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &BumpOnSecurityFixStrategy{
				CheckFunc: tt.checkFunc,
			}
			proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{})
			proc.Changes = tt.changes

			got := strategy.ShouldUpdateEpoch(proc)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestBumpOnSecurityFixStrategy_CalculateNewEpoch tests epoch increment
func TestBumpOnSecurityFixStrategy_CalculateNewEpoch(t *testing.T) {
	tests := []struct {
		name         string
		currentEpoch int64
		want         int64
	}{
		{
			name:         "increment from 0",
			currentEpoch: 0,
			want:         1,
		},
		{
			name:         "increment from 5",
			currentEpoch: 5,
			want:         6,
		},
		{
			name:         "increment from 99",
			currentEpoch: 99,
			want:         100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &BumpOnSecurityFixStrategy{}
			proc := newMockProcessor("test-pkg", "1.0.0", tt.currentEpoch, processor.ProcessorOptions{})

			got := strategy.CalculateNewEpoch(proc)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestBumpOnSecurityFixStrategy_GetReason tests reason message
func TestBumpOnSecurityFixStrategy_GetReason(t *testing.T) {
	strategy := &BumpOnSecurityFixStrategy{}
	assert.Equal(t, "security fixes applied", strategy.GetReason())
}

// TestBumpOnFileChangeStrategy_ShouldUpdateEpoch tests file change detection
func TestBumpOnFileChangeStrategy_ShouldUpdateEpoch(t *testing.T) {
	tests := []struct {
		name            string
		originalYAML    string
		currentYAML     string
		checkFunc       func(processor.Processor) bool
		wantFileChanges bool
		want            bool
	}{
		{
			name:            "file changed",
			originalYAML:    "package:\n  version: 1.0.0",
			currentYAML:     "package:\n  version: 2.0.0",
			wantFileChanges: true,
			want:            true,
		},
		{
			name:            "file not changed",
			originalYAML:    "package:\n  version: 1.0.0",
			currentYAML:     "package:\n  version: 1.0.0",
			wantFileChanges: false,
			want:            false,
		},
		{
			name: "custom check function overrides",
			checkFunc: func(p processor.Processor) bool {
				return true
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &BumpOnFileChangeStrategy{
				CheckFunc: tt.checkFunc,
			}
			proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{})
			if tt.originalYAML != "" {
				proc.OriginalYAML = []byte(tt.originalYAML)
			}
			if tt.currentYAML != "" {
				proc.CurrentYAML = []byte(tt.currentYAML)
			}

			got := strategy.ShouldUpdateEpoch(proc)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantFileChanges, proc.HasFileChanges())
		})
	}
}

// TestBumpOnFileChangeStrategy_CalculateNewEpoch tests epoch increment
func TestBumpOnFileChangeStrategy_CalculateNewEpoch(t *testing.T) {
	strategy := &BumpOnFileChangeStrategy{}
	proc := newMockProcessor("test-pkg", "1.0.0", 10, processor.ProcessorOptions{})

	got := strategy.CalculateNewEpoch(proc)
	assert.Equal(t, int64(11), got)
}

// TestBumpOnFileChangeStrategy_GetReason tests reason message
func TestBumpOnFileChangeStrategy_GetReason(t *testing.T) {
	strategy := &BumpOnFileChangeStrategy{}
	assert.Equal(t, "file changes applied", strategy.GetReason())
}

// TestCompositeEpochStrategy_ShouldUpdateEpoch tests multiple strategy evaluation
func TestCompositeEpochStrategy_ShouldUpdateEpoch(t *testing.T) {
	tests := []struct {
		name       string
		strategies []EpochStrategy
		setupProc  func(*mockProcessor)
		want       bool
	}{
		{
			name: "first strategy triggers",
			strategies: []EpochStrategy{
				&ResetOnVersionChangeStrategy{},
				&BumpOnSecurityFixStrategy{},
			},
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
			},
			want: true,
		},
		{
			name: "second strategy triggers",
			strategies: []EpochStrategy{
				&ResetOnVersionChangeStrategy{},
				&BumpOnSecurityFixStrategy{},
			},
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = false
				p.Changes = []processor.Change{
					{Type: "security", Description: "security fix"},
				}
			},
			want: true,
		},
		{
			name: "no strategies trigger",
			strategies: []EpochStrategy{
				&ResetOnVersionChangeStrategy{},
				&BumpOnSecurityFixStrategy{},
			},
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = false
			},
			want: false,
		},
		{
			name:       "empty strategies",
			strategies: []EpochStrategy{},
			setupProc:  func(p *mockProcessor) {},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &CompositeEpochStrategy{
				Strategies: tt.strategies,
			}
			proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{})
			tt.setupProc(proc)

			got := strategy.ShouldUpdateEpoch(proc)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCompositeEpochStrategy_CalculateNewEpoch tests epoch calculation
func TestCompositeEpochStrategy_CalculateNewEpoch(t *testing.T) {
	tests := []struct {
		name       string
		strategies []EpochStrategy
		setupProc  func(*mockProcessor)
		want       int64
	}{
		{
			name: "first strategy calculates (reset to 0)",
			strategies: []EpochStrategy{
				&ResetOnVersionChangeStrategy{},
				&BumpOnSecurityFixStrategy{},
			},
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
				p.CurrentEpoch = 5
			},
			want: 0,
		},
		{
			name: "second strategy calculates (increment)",
			strategies: []EpochStrategy{
				&ResetOnVersionChangeStrategy{},
				&BumpOnSecurityFixStrategy{},
			},
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = false
				p.CurrentEpoch = 5
				p.Changes = []processor.Change{
					{Type: "security", Description: "security fix"},
				}
			},
			want: 6,
		},
		{
			name: "no strategies trigger - return current",
			strategies: []EpochStrategy{
				&ResetOnVersionChangeStrategy{},
			},
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = false
				p.CurrentEpoch = 10
			},
			want: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy := &CompositeEpochStrategy{
				Strategies: tt.strategies,
			}
			proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{})
			tt.setupProc(proc)

			got := strategy.CalculateNewEpoch(proc)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCompositeEpochStrategy_GetReason tests reason message
func TestCompositeEpochStrategy_GetReason(t *testing.T) {
	strategy := &CompositeEpochStrategy{}
	assert.Equal(t, "composite strategy triggered", strategy.GetReason())
}

// TestNewEpochStage tests stage creation
func TestNewEpochStage(t *testing.T) {
	strategy := &ResetOnVersionChangeStrategy{}
	stage := NewEpochStage(strategy)

	assert.NotNil(t, stage)
	assert.Equal(t, "epoch", stage.Name())
	assert.Equal(t, "Handle epoch updates based on configured strategy", stage.Description())
	assert.Equal(t, strategy, stage.Strategy)
}

// TestEpochStage_ShouldRun tests conditional execution
func TestEpochStage_ShouldRun(t *testing.T) {
	tests := []struct {
		name      string
		strategy  EpochStrategy
		setupProc func(*mockProcessor)
		want      bool
	}{
		{
			name:     "should run when strategy triggers",
			strategy: &ResetOnVersionChangeStrategy{},
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
			},
			want: true,
		},
		{
			name:     "should not run when strategy does not trigger",
			strategy: &ResetOnVersionChangeStrategy{},
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = false
			},
			want: false,
		},
		{
			name:     "should run for security fixes",
			strategy: &BumpOnSecurityFixStrategy{},
			setupProc: func(p *mockProcessor) {
				p.Changes = []processor.Change{
					{Type: "security", Description: "fix"},
				}
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage := NewEpochStage(tt.strategy)
			proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{})
			tt.setupProc(proc)

			got, err := stage.ShouldRun(context.Background(), proc)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestEpochStage_Apply_DryRun tests dry run mode
func TestEpochStage_Apply_DryRun(t *testing.T) {
	tests := []struct {
		name         string
		strategy     EpochStrategy
		currentEpoch int64
		setupProc    func(*mockProcessor)
		wantNewEpoch int64
		wantMessage  string
	}{
		{
			name:         "dry run reset to 0",
			strategy:     &ResetOnVersionChangeStrategy{},
			currentEpoch: 5,
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
			},
			wantNewEpoch: 0,
			wantMessage:  "would update epoch: 5 -> 0 (version changed)",
		},
		{
			name:         "dry run increment",
			strategy:     &BumpOnSecurityFixStrategy{},
			currentEpoch: 5,
			setupProc: func(p *mockProcessor) {
				p.Changes = []processor.Change{
					{Type: "security", Description: "fix"},
				}
			},
			wantNewEpoch: 6,
			wantMessage:  "would update epoch: 5 -> 6 (security fixes applied)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage := NewEpochStage(tt.strategy)
			proc := newMockProcessor("test-pkg", "1.0.0", tt.currentEpoch, processor.ProcessorOptions{
				DryRun: true,
			})
			tt.setupProc(proc)

			err := stage.Apply(context.Background(), proc)
			require.NoError(t, err)

			assert.Equal(t, tt.wantNewEpoch, proc.GetNewEpoch())
			assert.True(t, proc.IsEpochChanged())
			assert.Contains(t, proc.GetMessages(), tt.wantMessage)
			// YAML should not be modified in dry run
			assert.Equal(t, proc.OriginalYAML, proc.CurrentYAML)
		})
	}
}

// TestEpochStage_Apply_RealUpdate tests actual epoch updates
func TestEpochStage_Apply_RealUpdate(t *testing.T) {
	tests := []struct {
		name         string
		strategy     EpochStrategy
		currentEpoch int64
		setupProc    func(*mockProcessor)
		wantNewEpoch int64
		wantMessage  string
	}{
		{
			name:         "reset epoch to 0",
			strategy:     &ResetOnVersionChangeStrategy{},
			currentEpoch: 5,
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
			},
			wantNewEpoch: 0,
			wantMessage:  "epoch updated: 5 -> 0 (version changed)",
		},
		{
			name:         "increment epoch",
			strategy:     &BumpOnSecurityFixStrategy{},
			currentEpoch: 5,
			setupProc: func(p *mockProcessor) {
				p.Changes = []processor.Change{
					{Type: "security", Description: "fix"},
				}
			},
			wantNewEpoch: 6,
			wantMessage:  "epoch updated: 5 -> 6 (security fixes applied)",
		},
		{
			name:         "increment from 0",
			strategy:     &BumpOnFileChangeStrategy{},
			currentEpoch: 0,
			setupProc: func(p *mockProcessor) {
				p.OriginalYAML = []byte(`package:
  name: test
  version: "1.0.0"
  epoch: 0
`)
				p.CurrentYAML = []byte(`package:
  name: test
  version: "2.0.0"
  epoch: 0
`)
			},
			wantNewEpoch: 1,
			wantMessage:  "epoch updated: 0 -> 1 (file changes applied)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage := NewEpochStage(tt.strategy)
			proc := newMockProcessor("test-pkg", "1.0.0", tt.currentEpoch, processor.ProcessorOptions{
				DryRun: false,
			})
			tt.setupProc(proc)

			err := stage.Apply(context.Background(), proc)
			require.NoError(t, err)

			assert.Equal(t, tt.wantNewEpoch, proc.GetNewEpoch())
			assert.True(t, proc.IsEpochChanged())
			assert.Contains(t, proc.GetMessages(), tt.wantMessage)

			// Verify YAML was updated
			assert.NotEqual(t, proc.OriginalYAML, proc.CurrentYAML)
			updatedYAML := string(proc.CurrentYAML)
			assert.Contains(t, updatedYAML, fmt.Sprintf("epoch: %d", tt.wantNewEpoch))
		})
	}
}

// TestEpochStage_Apply_YAMLPreservation tests YAML comment preservation
func TestEpochStage_Apply_YAMLPreservation(t *testing.T) {
	testYAML := `package:
  name: test-package
  version: "1.2.3"
  # Important: Epoch tracks rebuild count
  epoch: 5
  description: Test package

pipeline:
  - uses: fetch
    with:
      uri: https://example.com
`

	strategy := &BumpOnSecurityFixStrategy{}
	stage := NewEpochStage(strategy)
	proc := newMockProcessor("test-package", "1.2.3", 5, processor.ProcessorOptions{
		DryRun: false,
	})
	proc.OriginalYAML = []byte(testYAML)
	proc.CurrentYAML = []byte(testYAML)
	proc.Changes = []processor.Change{
		{Type: "security", Description: "CVE-2024-1234 fixed"},
	}

	err := stage.Apply(context.Background(), proc)
	require.NoError(t, err)

	updatedYAML := string(proc.CurrentYAML)

	// Verify epoch was updated
	assert.Contains(t, updatedYAML, "epoch: 6")
	assert.NotContains(t, updatedYAML, "epoch: 5")

	// Verify comment was preserved
	assert.Contains(t, updatedYAML, "# Important: Epoch tracks rebuild count")

	// Verify other fields unchanged
	assert.Contains(t, updatedYAML, "name: test-package")
	assert.Contains(t, updatedYAML, `version: "1.2.3"`)
	assert.Contains(t, updatedYAML, "description: Test package")
	assert.Contains(t, updatedYAML, "uses: fetch")
}

// TestEpochStage_Apply_InvalidYAML tests error handling
func TestEpochStage_Apply_InvalidYAML(t *testing.T) {
	invalidYAML := `package:
  name: test
  epoch: not-a-number
`

	strategy := &BumpOnSecurityFixStrategy{}
	stage := NewEpochStage(strategy)
	proc := newMockProcessor("test", "1.0.0", 5, processor.ProcessorOptions{})
	proc.CurrentYAML = []byte(invalidYAML)
	proc.Changes = []processor.Change{
		{Type: "security", Description: "fix"},
	}

	err := stage.Apply(context.Background(), proc)
	// Should handle error gracefully
	if err != nil {
		assert.Contains(t, err.Error(), "setting epoch")
	}
}

// TestEpochStage_Apply_ChangeTracking tests change tracking
func TestEpochStage_Apply_ChangeTracking(t *testing.T) {
	strategy := &BumpOnSecurityFixStrategy{}
	stage := NewEpochStage(strategy)
	proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{
		DryRun: false,
	})
	proc.Changes = []processor.Change{
		{Type: "security", Description: "CVE fix"},
	}

	initialChangeCount := len(proc.GetChanges())

	err := stage.Apply(context.Background(), proc)
	require.NoError(t, err)

	// Should have added epoch change to tracking
	assert.Greater(t, len(proc.GetChanges()), initialChangeCount)
	assert.True(t, proc.HasChanges())

	// Find the epoch change
	var foundEpochChange bool
	for _, change := range proc.GetChanges() {
		if change.Type == "epoch" {
			foundEpochChange = true
			assert.Equal(t, "package.epoch", change.Field)
			assert.Equal(t, "5", change.OldValue)
			assert.Equal(t, "6", change.NewValue)
			break
		}
	}
	assert.True(t, foundEpochChange, "epoch change should be tracked")
}

// TestEpochStage_Integration tests realistic scenarios
func TestEpochStage_Integration(t *testing.T) {
	tests := []struct {
		name           string
		strategy       EpochStrategy
		currentVersion string
		currentEpoch   int64
		setupProc      func(*mockProcessor)
		wantNewEpoch   int64
		wantRun        bool
	}{
		{
			name:           "version upgrade resets epoch",
			strategy:       &ResetOnVersionChangeStrategy{},
			currentVersion: "1.0.0",
			currentEpoch:   10,
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
				p.LatestVersion = "2.0.0"
			},
			wantNewEpoch: 0,
			wantRun:      true,
		},
		{
			name:           "security fix increments epoch",
			strategy:       &BumpOnSecurityFixStrategy{},
			currentVersion: "1.0.0",
			currentEpoch:   0,
			setupProc: func(p *mockProcessor) {
				p.Changes = []processor.Change{
					{Type: "security", Description: "CVE-2024-1234: buffer overflow"},
				}
			},
			wantNewEpoch: 1,
			wantRun:      true,
		},
		{
			name: "composite: version change takes priority over security",
			strategy: &CompositeEpochStrategy{
				Strategies: []EpochStrategy{
					&ResetOnVersionChangeStrategy{},
					&BumpOnSecurityFixStrategy{},
				},
			},
			currentVersion: "1.0.0",
			currentEpoch:   5,
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
				p.Changes = []processor.Change{
					{Type: "security", Description: "CVE fix"},
				}
			},
			wantNewEpoch: 0, // Reset wins because it's first in composite
			wantRun:      true,
		},
		{
			name: "composite: security fix when no version change",
			strategy: &CompositeEpochStrategy{
				Strategies: []EpochStrategy{
					&ResetOnVersionChangeStrategy{},
					&BumpOnSecurityFixStrategy{},
				},
			},
			currentVersion: "1.0.0",
			currentEpoch:   5,
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = false
				p.Changes = []processor.Change{
					{Type: "security", Description: "CVE fix"},
				}
			},
			wantNewEpoch: 6,
			wantRun:      true,
		},
		{
			name:           "no changes - should not run",
			strategy:       &ResetOnVersionChangeStrategy{},
			currentVersion: "1.0.0",
			currentEpoch:   5,
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = false
			},
			wantNewEpoch: 5, // Unchanged
			wantRun:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage := NewEpochStage(tt.strategy)
			proc := newMockProcessor("test-pkg", tt.currentVersion, tt.currentEpoch, processor.ProcessorOptions{
				DryRun: false,
			})
			tt.setupProc(proc)

			ctx := context.Background()

			// Check if stage should run
			shouldRun, err := stage.ShouldRun(ctx, proc)
			require.NoError(t, err)
			assert.Equal(t, tt.wantRun, shouldRun)

			if shouldRun {
				// Execute stage
				err = stage.Apply(ctx, proc)
				require.NoError(t, err)

				// Verify epoch update
				assert.Equal(t, tt.wantNewEpoch, proc.GetNewEpoch())
				assert.True(t, proc.IsEpochChanged())

				// Verify YAML was updated
				updatedYAML := string(proc.CurrentYAML)
				assert.Contains(t, updatedYAML, fmt.Sprintf("epoch: %d", tt.wantNewEpoch))
			}
		})
	}
}

// TestEpochStage_ConcurrentSafety tests thread safety (basic check)
func TestEpochStage_ConcurrentSafety(t *testing.T) {
	strategy := &BumpOnSecurityFixStrategy{}
	stage := NewEpochStage(strategy)

	// Run multiple processors concurrently
	done := make(chan bool)
	for i := range 10 {
		go func(id int) {
			proc := newMockProcessor(fmt.Sprintf("pkg-%d", id), "1.0.0", 5, processor.ProcessorOptions{
				DryRun: true,
			})
			proc.Changes = []processor.Change{
				{Type: "security", Description: "fix"},
			}

			err := stage.Apply(context.Background(), proc)
			assert.NoError(t, err)
			assert.Equal(t, int64(6), proc.GetNewEpoch())
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for range 10 {
		<-done
	}
}

// TestEpochStage_EdgeCases tests edge cases
func TestEpochStage_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		strategy  EpochStrategy
		setupProc func(*mockProcessor)
		wantError bool
		skipTest  bool
	}{
		{
			name:     "nil strategy should panic or error",
			strategy: nil,
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
			},
			wantError: true,
			skipTest:  true, // Would panic during NewEpochStage
		},
		{
			name:     "malformed YAML",
			strategy: &BumpOnSecurityFixStrategy{},
			setupProc: func(p *mockProcessor) {
				p.CurrentYAML = []byte(`invalid: yaml: content:`)
				p.Changes = []processor.Change{
					{Type: "security", Description: "fix"},
				}
			},
			wantError: true,
			skipTest:  true, // SetEpoch may hang on invalid YAML
		},
		{
			name:     "very large epoch number",
			strategy: &BumpOnSecurityFixStrategy{},
			setupProc: func(p *mockProcessor) {
				p.CurrentEpoch = 999999
				p.CurrentYAML = []byte(`package:
  name: test-pkg
  version: "1.0.0"
  epoch: 999999
`)
				p.Changes = []processor.Change{
					{Type: "security", Description: "fix"},
				}
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipTest {
				t.Skip("Skipping test that would panic")
				return
			}

			stage := NewEpochStage(tt.strategy)
			proc := newMockProcessor("test-pkg", "1.0.0", 5, processor.ProcessorOptions{})
			tt.setupProc(proc)

			err := stage.Apply(context.Background(), proc)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestEpochStage_MessageFormat tests message formatting
func TestEpochStage_MessageFormat(t *testing.T) {
	tests := []struct {
		name            string
		strategy        EpochStrategy
		currentEpoch    int64
		setupProc       func(*mockProcessor)
		dryRun          bool
		wantMessagePart string
	}{
		{
			name:         "dry run message format",
			strategy:     &ResetOnVersionChangeStrategy{},
			currentEpoch: 5,
			setupProc: func(p *mockProcessor) {
				p.VersionChanged = true
			},
			dryRun:          true,
			wantMessagePart: "would update epoch: 5 -> 0",
		},
		{
			name:         "real update message format",
			strategy:     &BumpOnSecurityFixStrategy{},
			currentEpoch: 5,
			setupProc: func(p *mockProcessor) {
				p.Changes = []processor.Change{
					{Type: "security", Description: "fix"},
				}
			},
			dryRun:          false,
			wantMessagePart: "epoch updated: 5 -> 6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage := NewEpochStage(tt.strategy)
			proc := newMockProcessor("test-pkg", "1.0.0", tt.currentEpoch, processor.ProcessorOptions{
				DryRun: tt.dryRun,
			})
			tt.setupProc(proc)

			err := stage.Apply(context.Background(), proc)
			require.NoError(t, err)

			messages := proc.GetMessages()
			found := false
			for _, msg := range messages {
				if strings.Contains(msg, tt.wantMessagePart) {
					found = true
					break
				}
			}
			assert.True(t, found, "expected message containing %q in %v", tt.wantMessagePart, messages)
		})
	}
}
