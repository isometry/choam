package updater

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	melangeConfig "github.com/isometry/choam/pkg/config"
)

// ApplyResult represents the result of an update application
type ApplyResult struct {
	PackageName    string   `json:"package_name"`
	FilePath       string   `json:"file_path"`
	OldVersion     string   `json:"old_version"`
	NewVersion     string   `json:"new_version"`
	OldEpoch       int64    `json:"old_epoch"`
	NewEpoch       int64    `json:"new_epoch"`
	UpdatesApplied []string `json:"updates_applied"`
	SharedUpdates  []string `json:"shared_updates,omitempty"`
	BackupCreated  string   `json:"backup_created,omitempty"`
	IsManual       bool     `json:"is_manual"`
	Error          string   `json:"error,omitempty"`
}

// ApplyOptions configures how updates are applied
type ApplyOptions struct {
	DryRun        bool   // Don't actually modify files
	Force         bool   // Apply update even if no version change
	SharedUpdates bool   // Apply shared dependency updates
	BackupSuffix  string // Suffix for backup files (default: ".bak")
	TempDir       string // Directory for temporary files
}

// DefaultApplyOptions returns default apply options
func DefaultApplyOptions() *ApplyOptions {
	return &ApplyOptions{
		DryRun:        false,
		Force:         false,
		SharedUpdates: true,
		BackupSuffix:  ".bak",
		TempDir:       os.TempDir(),
	}
}

// ApplyUpdate applies an update to a melange configuration file
func (u *Updater) ApplyUpdate(ctx context.Context, filePath string, opts *ApplyOptions) (*ApplyResult, error) {
	if opts == nil {
		opts = DefaultApplyOptions()
	}

	result := &ApplyResult{
		FilePath:       filePath,
		UpdatesApplied: make([]string, 0),
		SharedUpdates:  make([]string, 0),
	}

	// Load configuration with preservation
	loader := melangeConfig.NewLoader()
	cfg, originalContent, err := loader.LoadWithPreservation(filePath)
	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("loading configuration: %w", err)
	}

	result.PackageName = cfg.Package.Name
	result.OldVersion = cfg.Package.Version
	result.OldEpoch = int64(cfg.Package.Epoch)

	// Check for updates
	updateResult, err := u.CheckUpdate(ctx, cfg)
	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("checking for updates: %w", err)
	}

	// Set manual flag
	result.IsManual = updateResult.IsManual

	// Skip manual updates - they should not be automatically applied
	if updateResult.IsManual {
		if updateResult.HasUpdate {
			result.Error = "Manual update required - automatic updates disabled"
		}
		return result, nil
	}

	// Skip if no updates unless forced
	if !updateResult.HasUpdate && !opts.Force {
		// No error - this is a normal state when no updates are available
		return result, nil
	}

	// Prepare for update
	updatedContent := originalContent
	result.NewVersion = updateResult.LatestVersion

	// Apply version update if version changed or forced
	if updateResult.HasUpdate || opts.Force {
		if updateResult.HasUpdate {
			// Version changed - update and reset epoch
			updatedContent, err = loader.UpdatePackageVersion(updatedContent, updateResult.LatestVersion)
			if err != nil {
				result.Error = err.Error()
				return result, fmt.Errorf("updating package version: %w", err)
			}
			result.NewEpoch = 0
			result.UpdatesApplied = append(result.UpdatesApplied, "package.version", "package.epoch")
		} else if opts.Force {
			// Force update - increment epoch only
			updatedContent, err = loader.IncrementEpoch(updatedContent)
			if err != nil {
				result.Error = err.Error()
				return result, fmt.Errorf("incrementing epoch: %w", err)
			}
			result.NewEpoch = result.OldEpoch + 1
			result.UpdatesApplied = append(result.UpdatesApplied, "package.epoch")
		}
	}

	// Apply pipeline updates
	pipelineUpdater := NewPipelineUpdater(u.githubClient, u.gitClient)
	pipelineUpdates, err := pipelineUpdater.UpdatePipelines(ctx, cfg, updatedContent, updateResult)
	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("updating pipelines: %w", err)
	}

	if len(pipelineUpdates.UpdatesApplied) > 0 {
		updatedContent = pipelineUpdates.Content
		result.UpdatesApplied = append(result.UpdatesApplied, pipelineUpdates.UpdatesApplied...)
	}

	// Validate updated configuration
	if !opts.DryRun {
		tempFile := filepath.Join(opts.TempDir, fmt.Sprintf("melange-validate-%s.yaml", result.PackageName))
		if err := loader.ValidateUpdatedConfig(updatedContent, tempFile); err != nil {
			result.Error = err.Error()
			return result, fmt.Errorf("validation failed: %w", err)
		}
	}

	// Apply shared updates if enabled and package has shared=true
	if opts.SharedUpdates && cfg.Update.Shared {
		sharedUpdater := NewSharedUpdater()
		sharedResults, err := sharedUpdater.UpdateSharedDependencies(ctx, filePath, result.PackageName, opts)
		if err != nil {
			// Don't fail the main update for shared update errors, just log them
			result.SharedUpdates = append(result.SharedUpdates, fmt.Sprintf("Error updating shared dependencies: %v", err))
		} else {
			result.SharedUpdates = sharedResults
		}
	}

	// Save changes if not dry run
	if !opts.DryRun {
		backupPath := filePath + opts.BackupSuffix
		if err := loader.SaveWithBackup(filePath, updatedContent); err != nil {
			result.Error = err.Error()
			return result, fmt.Errorf("saving updated file: %w", err)
		}
		result.BackupCreated = backupPath
	}

	return result, nil
}

// ApplyUpdates applies updates to multiple files
func (u *Updater) ApplyUpdates(ctx context.Context, filePaths []string, opts *ApplyOptions) ([]*ApplyResult, error) {
	results := make([]*ApplyResult, 0, len(filePaths))

	for _, path := range filePaths {
		result, err := u.ApplyUpdate(ctx, path, opts)
		if err != nil {
			// Create error result
			result = &ApplyResult{
				FilePath: path,
				Error:    err.Error(),
			}
		}
		results = append(results, result)
	}

	return results, nil
}

// ApplyUpdateToDirectory applies updates to all melange files in a directory
func (u *Updater) ApplyUpdateToDirectory(ctx context.Context, dirPath string, opts *ApplyOptions) ([]*ApplyResult, error) {
	// Find all YAML files in directory
	files, err := findMelangeFiles(dirPath)
	if err != nil {
		return nil, fmt.Errorf("finding melange files in %s: %w", dirPath, err)
	}

	if len(files) == 0 {
		return []*ApplyResult{}, nil
	}

	return u.ApplyUpdates(ctx, files, opts)
}
