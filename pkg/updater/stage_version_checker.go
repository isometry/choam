package updater

import (
	"context"
	"fmt"
	"log/slog"

	melange "chainguard.dev/melange/pkg/config"
	githubClient "github.com/isometry/choam/pkg/github"
)

// VersionChecker implements CheckStage to determine if package updates are available
type VersionChecker struct{}

func (vc *VersionChecker) Name() string {
	return "version_check"
}

func (vc *VersionChecker) Description() string {
	return "Check for available package updates"
}

// Check determines if updates are available for the package
func (vc *VersionChecker) Check(ctx context.Context, processor *PackageProcessor) error {
	logger := processor.WithStage(vc.Name())
	cfg := processor.Config

	logger.Debug("Starting version check")

	// Check if updates are enabled
	if !cfg.Update.Enabled {
		logger.Debug("Updates disabled in configuration")
		return nil
	}

	// Check if update is excluded
	if cfg.Update.ExcludeReason != "" {
		logger.Debug("Updates excluded", "reason", cfg.Update.ExcludeReason)
		processor.AddError(fmt.Errorf("updates excluded: %s", cfg.Update.ExcludeReason))
		return nil
	}

	// Get orchestrator components through global access pattern
	// Note: This creates a new orchestrator instance, which is not ideal but consistent with other stages
	// Future improvement: Refactor stage architecture to inject orchestrator dependencies through context
	orchestrator := NewOrchestrator()

	// Get the latest valid version
	latestValidVersion, source, err := vc.getLatestValidVersion(ctx, cfg, orchestrator, logger)
	if err != nil {
		processor.AddError(fmt.Errorf("getting latest version: %w", err))
		return nil // Don't fail the entire pipeline, just record the error
	}

	// Compare versions
	_, versionComparator := orchestrator.GetVersionComponents()
	hasUpdate, err := versionComparator.IsNewer(cfg.Package.Version, latestValidVersion)
	if err != nil {
		processor.AddError(fmt.Errorf("comparing versions: %w", err))
		return nil
	}

	// Update processor with results
	processor.SetUpdateResult(hasUpdate, latestValidVersion, source, cfg.Update.Manual)

	if hasUpdate {
		logger.Info("Update available",
			"current", cfg.Package.Version,
			"latest", latestValidVersion,
			"source", source)
	} else {
		logger.Debug("Package is up to date",
			"current", cfg.Package.Version,
			"latest", latestValidVersion)
	}

	return nil
}

// getLatestValidVersion gets the latest valid version from the appropriate source
func (vc *VersionChecker) getLatestValidVersion(ctx context.Context, cfg *melange.Configuration, orchestrator *UpdateOrchestrator, logger *slog.Logger) (string, string, error) {
	updateConfig := &cfg.Update

	// Check GitHub monitor first (most common)
	if updateConfig.GitHubMonitor != nil {
		return vc.getLatestValidGitHubVersion(ctx, cfg, updateConfig.GitHubMonitor, orchestrator, logger)
	}

	// Check release monitor
	if updateConfig.ReleaseMonitor != nil {
		return vc.getLatestValidReleaseMonitorVersion(ctx, cfg, updateConfig.ReleaseMonitor, orchestrator, logger)
	}

	// Check git monitor
	if updateConfig.GitMonitor != nil {
		return vc.getLatestValidGitVersion(ctx, cfg, updateConfig.GitMonitor, orchestrator, logger)
	}

	return "", "", fmt.Errorf("no supported update monitor configured")
}

// getLatestValidGitHubVersion gets the latest valid version from GitHub
func (vc *VersionChecker) getLatestValidGitHubVersion(ctx context.Context, cfg *melange.Configuration, monitor *melange.GitHubMonitor, orchestrator *UpdateOrchestrator, logger *slog.Logger) (string, string, error) {
	repo, err := githubClient.ParseRepository(monitor.Identifier)
	if err != nil {
		return "", "github", fmt.Errorf("parsing repository identifier: %w", err)
	}

	// Create version filter with package context
	versionFilter, _ := orchestrator.GetVersionComponents()
	filterFunc := vc.createVersionFilter(cfg, versionFilter, logger)

	// Get GitHub client
	_, githubClient, _, _ := orchestrator.GetServiceClients()

	// Determine source type
	source := "github-releases"
	if monitor.UseTags {
		source = "github-tags"
	}

	logger.Debug("Checking GitHub for updates",
		"repository", monitor.Identifier,
		"use_tags", monitor.UseTags)

	// Get the first valid version using the filter
	var validVersion string
	if monitor.UseTags {
		validVersion, err = githubClient.GetFirstValidTag(
			ctx,
			repo.Owner,
			repo.Name,
			monitor.TagFilterPrefix,
			filterFunc,
		)
	} else {
		validVersion, err = githubClient.GetFirstValidRelease(
			ctx,
			repo.Owner,
			repo.Name,
			monitor.TagFilterPrefix,
			filterFunc,
		)
	}

	if err != nil {
		return "", source, err
	}

	// Process the valid version to get the final processed form
	processed, _, _ := versionFilter.ProcessVersion(validVersion, &cfg.Update)

	return processed, source, nil
}

// getLatestValidReleaseMonitorVersion gets the latest valid version from release-monitoring.org
func (vc *VersionChecker) getLatestValidReleaseMonitorVersion(ctx context.Context, cfg *melange.Configuration, monitor *melange.ReleaseMonitor, orchestrator *UpdateOrchestrator, logger *slog.Logger) (string, string, error) {
	anityaClient, _, _, _ := orchestrator.GetServiceClients()

	logger.Debug("Checking release-monitoring.org for updates", "identifier", monitor.Identifier)

	// Get the single version from release monitor
	version, err := anityaClient.GetLatestVersion(ctx, monitor.Identifier)
	if err != nil {
		return "", "release-monitor", fmt.Errorf("getting version from release-monitoring.org: %w", err)
	}

	// Process it through validation pipeline
	versionFilter, _ := orchestrator.GetVersionComponents()
	processed, valid, err := versionFilter.ProcessVersion(version, &cfg.Update)
	if err != nil {
		return "", "release-monitor", fmt.Errorf("processing version: %w", err)
	}

	if !valid {
		return "", "release-monitor", fmt.Errorf("version %s filtered out by update rules", version)
	}

	return processed, "release-monitor", nil
}

// getLatestValidGitVersion gets the latest valid version from a Git repository
func (vc *VersionChecker) getLatestValidGitVersion(ctx context.Context, cfg *melange.Configuration, monitor *melange.GitMonitor, orchestrator *UpdateOrchestrator, logger *slog.Logger) (string, string, error) {
	// Extract repository URL from the pipeline
	repoURL, err := extractRepositoryFromConfig(cfg)
	if err != nil {
		return "", "git", fmt.Errorf("extracting repository from pipeline: %w", err)
	}

	logger.Debug("Checking Git repository for updates", "repository", repoURL)

	// Create version filter
	versionFilter, _ := orchestrator.GetVersionComponents()
	filterFunc := vc.createVersionFilter(cfg, versionFilter, logger)

	// Get Git client
	_, _, gitClient, _ := orchestrator.GetServiceClients()

	// Get the first valid version using the filter
	validVersion, err := gitClient.GetFirstValidTag(ctx, repoURL, filterFunc)
	if err != nil {
		return "", "git", err
	}

	// Process the valid version to get the final processed form
	processed, _, _ := versionFilter.ProcessVersion(validVersion, &cfg.Update)

	return processed, "git", nil
}

// createVersionFilter creates a unified filter function with logging context
func (vc *VersionChecker) createVersionFilter(cfg *melange.Configuration, filter *VersionFilter, logger *slog.Logger) func(string) bool {
	return func(rawVersion string) bool {
		// Create a version-specific logger for this filtering operation
		versionLogger := logger.With("checking_version", rawVersion)

		// Apply ALL filtering logic with logging context
		processed, valid, err := filter.ProcessVersionWithLogger(rawVersion, &cfg.Update, versionLogger)
		if err != nil {
			versionLogger.Debug("Error processing version", "error", err)
			return false
		}

		if valid {
			versionLogger.Debug("Version accepted", "original", rawVersion, "processed", processed)
		} else {
			versionLogger.Debug("Version rejected", "original", rawVersion)
		}

		return valid
	}
}
