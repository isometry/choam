package updater

import (
	"context"
	"fmt"
)

// EpochApplier implements ApplyStage to reset epoch when package version changes
// In the simplified update flow, epoch is always reset to 0 when version changes
type EpochApplier struct{}

func (ea *EpochApplier) Name() string {
	return "epoch_apply"
}

func (ea *EpochApplier) Description() string {
	return "Reset epoch to 0 when package version changes"
}

// Apply resets epoch to 0 when version changes
func (ea *EpochApplier) Apply(ctx context.Context, processor *PackageProcessor) error {
	logger := processor.WithStage(ea.Name())

	// Only handle version changes: reset epoch to 0
	if processor.VersionChanged {
		loader := newMelangeLoader()

		if processor.Options.DryRun {
			logger.Info("Dry run - would reset epoch to 0 due to version change")
			processor.AddMessage(fmt.Sprintf("would reset epoch: %d -> 0 (version changed)", processor.OldEpoch))
			processor.NewEpoch = 0
			processor.EpochChanged = true
			return nil
		}

		logger.Info("Resetting epoch to 0 due to version change")
		updatedContent, err := loader.SetEpoch(processor.CurrentYAML, 0)
		if err != nil {
			return fmt.Errorf("resetting epoch: %w", err)
		}

		// Update processor state
		processor.CurrentYAML = updatedContent
		processor.NewEpoch = 0
		processor.EpochChanged = true
		processor.AddMessage(fmt.Sprintf("epoch reset: %d -> 0 (version changed)", processor.OldEpoch))
		logger.Info("Epoch reset to 0", "old_epoch", processor.OldEpoch)
		return nil
	}

	// No epoch changes needed (version unchanged)
	logger.Debug("No version change - no epoch reset needed")
	return nil
}
