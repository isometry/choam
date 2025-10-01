package updater

import (
	"context"
	"fmt"
	"log/slog"

	melange "chainguard.dev/melange/pkg/config"
	githubClient "github.com/isometry/choam/internal/github"
	"github.com/isometry/choam/internal/processor"
)

// VersionChecker implements CheckStage for the shared processor architecture
type VersionChecker struct {
	processor.BaseStage
	orchestrator *UpdateOrchestrator
}

func NewVersionChecker(orchestrator *UpdateOrchestrator) *VersionChecker {
	return &VersionChecker{
		BaseStage: processor.BaseStage{
			StageName:        "version_check",
			StageDescription: "Check for available package updates",
		},
		orchestrator: orchestrator,
	}
}

func (vc *VersionChecker) Check(ctx context.Context, p processor.Processor) error {
	up, ok := p.(*UpdaterProcessor)
	if !ok {
		return fmt.Errorf("expected UpdaterProcessor, got %T", p)
	}

	logger := up.WithStage(vc.Name())
	cfg := up.GetConfig()

	logger.Debug("Starting version check")

	// Check if updates are enabled
	if !cfg.Update.Enabled {
		logger.Debug("Updates disabled in configuration")
		return nil
	}

	// Check if update is excluded
	if cfg.Update.ExcludeReason != "" {
		logger.Debug("Updates excluded", "reason", cfg.Update.ExcludeReason)
		up.AddError(fmt.Errorf("updates excluded: %s", cfg.Update.ExcludeReason))
		return nil
	}

	// Get the latest valid version
	latestValidVersion, source, err := vc.getLatestValidVersion(ctx, cfg, vc.orchestrator, logger)
	if err != nil {
		up.AddError(fmt.Errorf("getting latest version: %w", err))
		return err
	}

	if latestValidVersion == "" {
		logger.Debug("No valid version found")
		return nil
	}

	// Compare versions using version comparator
	_, versionComparator := vc.orchestrator.GetVersionComponents()
	hasUpdate, err := versionComparator.IsNewer(cfg.Package.Version, latestValidVersion)
	if err != nil {
		up.AddError(fmt.Errorf("comparing versions: %w", err))
		return nil
	}

	// Update processor with results
	up.SetUpdateResult(hasUpdate, latestValidVersion, source, cfg.Update.Manual)

	if hasUpdate {
		if cfg.Update.Manual {
			up.AddMessage(fmt.Sprintf("manual update available: %s -> %s (%s)",
				up.GetCurrentVersion(), latestValidVersion, source))
		} else {
			up.AddMessage(fmt.Sprintf("update available: %s -> %s (%s)",
				up.GetCurrentVersion(), latestValidVersion, source))
		}
		logger.Info("Update available",
			"current_version", up.GetCurrentVersion(),
			"latest_version", latestValidVersion,
			"source", source,
			"manual", cfg.Update.Manual)
	} else {
		up.AddMessage("package is up-to-date")
		logger.Debug("Package is up-to-date")
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

// VersionApplier implements ApplyStage for version updates
type VersionApplier struct {
	processor.BaseStage
}

func NewVersionApplier() *VersionApplier {
	return &VersionApplier{
		BaseStage: processor.BaseStage{
			StageName:        "version_apply",
			StageDescription: "Apply version updates to melange configuration",
		},
	}
}

func (va *VersionApplier) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	up, ok := p.(*UpdaterProcessor)
	if !ok {
		return false, fmt.Errorf("expected UpdaterProcessor, got %T", p)
	}

	// Only run if update is available and not manual
	return up.UpdateAvailable && !up.IsManual, nil
}

func (va *VersionApplier) Apply(ctx context.Context, p processor.Processor) error {
	up, ok := p.(*UpdaterProcessor)
	if !ok {
		return fmt.Errorf("expected UpdaterProcessor, got %T", p)
	}

	logger := up.WithStage(va.Name())

	if up.GetOptions().DryRun {
		logger.Info("Dry run - would update version",
			"old_version", up.GetCurrentVersion(),
			"new_version", up.LatestVersion)
		up.SetVersionUpdate(up.GetCurrentVersion(), up.LatestVersion)
		up.AddMessage(fmt.Sprintf("would update version: %s -> %s",
			up.GetCurrentVersion(), up.LatestVersion))
		return nil
	}

	// Update the package version in the configuration
	loader := newMelangeLoader()
	updatedContent, err := loader.UpdatePackageVersion(up.GetCurrentYAML(), up.LatestVersion)
	if err != nil {
		return fmt.Errorf("updating version: %w", err)
	}

	// Update processor state
	up.SetCurrentYAML(updatedContent)
	up.SetVersionUpdate(up.GetCurrentVersion(), up.LatestVersion)

	logger.Info("Version updated",
		"old_version", up.GetCurrentVersion(),
		"new_version", up.LatestVersion)

	return nil
}
