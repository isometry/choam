package stages

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/isometry/choam/internal/processor"
)

// FileWriterStage handles writing changes to disk
type FileWriterStage struct {
	processor.BaseStage
	CreateBackup bool
	BackupSuffix string
}

// NewFileWriterStage creates a new file writer stage
func NewFileWriterStage(createBackup bool, backupSuffix string) *FileWriterStage {
	if backupSuffix == "" {
		backupSuffix = ".bak"
	}

	return &FileWriterStage{
		BaseStage: processor.BaseStage{
			StageName:        "file_writer",
			StageDescription: "Write changes to file",
		},
		CreateBackup: createBackup,
		BackupSuffix: backupSuffix,
	}
}

func (f *FileWriterStage) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	// Only run if there are actual changes to write
	hasFileChanges := !bytes.Equal(p.GetOriginalYAML(), p.GetCurrentYAML())
	return hasFileChanges, nil
}

func (f *FileWriterStage) Validate(ctx context.Context, p processor.Processor) error {
	// Check if file is writable
	filePath := p.GetFilePath()
	if filePath == "" {
		return fmt.Errorf("file path is empty")
	}

	// Check if we can write to the file
	if _, err := os.Stat(filePath); err != nil {
		return fmt.Errorf("cannot access file %s: %w", filePath, err)
	}

	return nil
}

func (f *FileWriterStage) Apply(ctx context.Context, p processor.Processor) error {
	logger := p.GetLogger().With("stage", f.Name())
	filePath := p.GetFilePath()

	if p.GetOptions().DryRun {
		logger.Info("Dry run - would write file", "path", filePath)
		p.AddMessage("would write changes to file")
		return nil
	}

	// Create backup if requested
	if f.CreateBackup {
		backupPath := filePath + f.BackupSuffix
		if err := os.WriteFile(backupPath, p.GetOriginalYAML(), 0644); err != nil {
			return fmt.Errorf("creating backup: %w", err)
		}
		logger.Debug("Created backup", "path", backupPath)
		p.AddMessage(fmt.Sprintf("created backup: %s", backupPath))
	}

	// Write the file
	if err := os.WriteFile(filePath, p.GetCurrentYAML(), 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	p.AddMessage("file written successfully")
	logger.Info("File written", "path", filePath)
	return nil
}
