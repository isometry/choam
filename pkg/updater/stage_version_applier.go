package updater

import (
	"context"
	"fmt"
)

// VersionApplier implements ApplyStage to apply version updates to packages
type VersionApplier struct{}

func (va *VersionApplier) Name() string {
	return "version_apply"
}

func (va *VersionApplier) Description() string {
	return "Apply version updates to package configuration"
}

// Apply updates the package version in the configuration
func (va *VersionApplier) Apply(ctx context.Context, processor *PackageProcessor) error {
	logger := processor.WithStage(va.Name())

	// Skip if no update available and not forced
	if !processor.UpdateAvailable && !processor.Options.Force {
		logger.Debug("No version update needed")
		return nil
	}

	// Skip manual updates unless forced
	if processor.IsManual && !processor.Options.Force {
		logger.Debug("Manual update - skipping automatic version application")
		return nil
	}

	// Skip if there's no actual version change (even with --force)
	// This prevents panic when --force is used without an available update
	if processor.LatestVersion == "" || processor.LatestVersion == processor.CurrentVersion {
		logger.Debug("No version change to apply", 
			"current", processor.CurrentVersion, 
			"latest", processor.LatestVersion)
		return nil
	}

	// Skip if dry run
	if processor.Options.DryRun {
		logger.Info("Dry run - would update version",
			"current", processor.CurrentVersion,
			"latest", processor.LatestVersion)
		processor.AddMessage(fmt.Sprintf("would update version: %s -> %s", processor.CurrentVersion, processor.LatestVersion))
		return nil
	}

	logger.Info("Applying version update",
		"current", processor.CurrentVersion,
		"latest", processor.LatestVersion)

	// Update the version in YAML content
	loader := newMelangeLoader()
	updatedContent, err := loader.UpdatePackageVersion(processor.CurrentYAML, processor.LatestVersion)
	if err != nil {
		return fmt.Errorf("updating package version: %w", err)
	}

	// Update processor state
	processor.CurrentYAML = updatedContent
	processor.SetVersionUpdate(processor.LatestVersion)

	logger.Info("Version update applied successfully")
	return nil
}
