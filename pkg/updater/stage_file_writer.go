package updater

import (
	"context"
	"fmt"
)

// FileWriter implements ApplyStage to persist updated YAML content to disk
// This stage should be the final stage in the apply pipeline to ensure all
// modifications are complete before writing to disk.
type FileWriter struct{}

func (fw *FileWriter) Name() string {
	return "file_writer"
}

func (fw *FileWriter) Description() string {
	return "Write updated YAML content to disk with backup support"
}

// Apply writes the updated YAML content to disk
func (fw *FileWriter) Apply(ctx context.Context, processor *PackageProcessor) error {
	logger := processor.WithStage(fw.Name())

	// Skip if dry run
	if processor.Options.DryRun {
		logger.Info("Dry run - would write updated file to disk",
			"file", processor.FilePath)
		if processor.HasChanges() {
			processor.AddMessage(fmt.Sprintf("would write updated file: %s", processor.FilePath))
		}
		return nil
	}

	// Skip if no changes were made
	if !processor.HasChanges() {
		logger.Debug("No changes made - skipping file write")
		return nil
	}

	// Check if current YAML is different from original
	if string(processor.CurrentYAML) == string(processor.OriginalYAML) {
		logger.Debug("YAML content unchanged - skipping file write")
		return nil
	}

	logger.Info("Writing updated content to disk",
		"file", processor.FilePath)

	// Use the loader's Save method which handles:
	// - Backup creation if suffix provided
	// - YAML validation before writing
	// - Atomic file operations
	// - Proper file permissions
	loader := newMelangeLoader()
	err := loader.Save(
		processor.FilePath,
		processor.CurrentYAML,
		processor.Options.BackupSuffix,
	)

	if err != nil {
		return fmt.Errorf("writing updated file to disk: %w", err)
	}

	// Log success with details
	logger.Info("File updated successfully")

	// Mark that file was actually written
	processor.FileWasWritten = true

	// Add final message about file write
	if processor.Options.BackupSuffix != "" {
		processor.AddMessage(fmt.Sprintf("file updated with backup: %s%s", processor.FilePath, processor.Options.BackupSuffix))
	} else {
		processor.AddMessage(fmt.Sprintf("file updated: %s", processor.FilePath))
	}

	return nil
}
