package updater

import (
	"context"
	"fmt"
)

// EpochApplier implements ApplyStage to apply epoch bumps when needed
// This stage handles epoch increments for cases where go/bump dependencies
// change but package version does not change.
type EpochApplier struct{}

func (ea *EpochApplier) Name() string {
	return "epoch_apply"
}

func (ea *EpochApplier) Description() string {
	return "Apply epoch bump for dependency updates without version changes"
}

// Apply handles all epoch changes: reset to 0 for version changes, increment for config changes
func (ea *EpochApplier) Apply(ctx context.Context, processor *PackageProcessor) error {
	logger := processor.WithStage(ea.Name())
	loader := newMelangeLoader()

	// Handle version changes: reset epoch to 0
	if processor.VersionChanged {
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

	// Handle config changes without version change: increment epoch
	if processor.RequiresEpochBump {
		newEpoch := processor.OldEpoch + 1
		
		if processor.Options.DryRun {
			logger.Info("Dry run - would increment epoch for config changes")
			processor.AddMessage(fmt.Sprintf("would increment epoch: %d -> %d (config changes without version change)", 
				processor.OldEpoch, newEpoch))
			processor.NewEpoch = newEpoch
			processor.EpochChanged = true
			return nil
		}

		logger.Info("Incrementing epoch for config changes", "old_epoch", processor.OldEpoch, "new_epoch", newEpoch)
		updatedContent, err := loader.SetEpoch(processor.CurrentYAML, newEpoch)
		if err != nil {
			return fmt.Errorf("incrementing epoch: %w", err)
		}

		// Update processor state
		processor.CurrentYAML = updatedContent
		processor.NewEpoch = newEpoch
		processor.EpochChanged = true
		processor.AddMessage(fmt.Sprintf("epoch bumped: %d -> %d (config changes without version change)", processor.OldEpoch, newEpoch))
		logger.Info("Epoch incremented", "old_epoch", processor.OldEpoch, "new_epoch", newEpoch)
		return nil
	}

	// No epoch changes needed
	logger.Debug("No epoch changes needed")
	return nil
}