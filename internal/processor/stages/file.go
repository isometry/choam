package stages

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/isometry/choam/internal/logging"
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
	logger := logging.From(ctx)
	filePath := p.GetFilePath()

	if p.GetOptions().DryRun {
		logger.Info("Dry run - would write file", "path", filePath)
		p.AddMessage("would write changes to file")
		return nil
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	// Create backup if requested
	if f.CreateBackup {
		backupPath := filePath + f.BackupSuffix
		if err := WriteFileAtomic(backupPath, p.GetOriginalYAML(), info.Mode().Perm()); err != nil {
			return fmt.Errorf("creating backup: %w", err)
		}
		logger.Debug("Created backup", "path", backupPath)
		p.AddMessage(fmt.Sprintf("created backup: %s", backupPath))
	}

	if err := WriteFileAtomic(filePath, p.GetCurrentYAML(), info.Mode().Perm()); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	p.AddMessage("file written successfully")
	logger.Info("File written", "path", filePath)
	return nil
}

// WriteFileAtomic replaces path with data via a temp file in the same
// directory and a rename, so an interrupted write never leaves a truncated
// file behind; the result has mode perm.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
