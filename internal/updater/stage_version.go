package updater

import (
	"cmp"
	"context"
	"fmt"
	"strings"

	melange "chainguard.dev/melange/pkg/config"
	githubClient "github.com/isometry/choam/internal/github"
	"github.com/isometry/choam/internal/logging"
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

	// ctx already carries "stage"/"stage_index" - processor.Pipeline.Execute
	// seeds them before calling any stage method.
	cfg := up.GetConfig()

	logging.From(ctx).Debug("Starting version check")

	// Check if updates are enabled
	if !cfg.Update.Enabled {
		logging.From(ctx).Debug("Updates disabled in configuration")
		return nil
	}

	// Check if update is excluded
	if cfg.Update.ExcludeReason != "" {
		logging.From(ctx).Debug("Updates excluded", "reason", cfg.Update.ExcludeReason)
		up.AddError(fmt.Errorf("updates excluded: %s", cfg.Update.ExcludeReason))
		return nil
	}

	// Get the latest valid version
	latestValidVersion, source, err := vc.getLatestValidVersion(ctx, cfg, vc.orchestrator)
	if err != nil {
		up.AddError(fmt.Errorf("getting latest version: %w", err))
		return err
	}

	if latestValidVersion == "" {
		logging.From(ctx).Debug("No valid version found")
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
		logging.From(ctx).Info("Update available",
			"current_version", up.GetCurrentVersion(),
			"latest_version", latestValidVersion,
			"source", source,
			"manual", cfg.Update.Manual)
	} else {
		up.AddMessage("package is up-to-date")
		logging.From(ctx).Debug("Package is up-to-date")
	}

	return nil
}

// getLatestValidVersion gets the latest valid version from the appropriate source
func (vc *VersionChecker) getLatestValidVersion(ctx context.Context, cfg *melange.Configuration, orchestrator *UpdateOrchestrator) (string, string, error) {
	updateConfig := &cfg.Update

	// Check GitHub monitor first (most common)
	if updateConfig.GitHubMonitor != nil {
		return vc.getLatestValidGitHubVersion(ctx, cfg, updateConfig.GitHubMonitor, orchestrator)
	}

	// Check release monitor
	if updateConfig.ReleaseMonitor != nil {
		return vc.getLatestValidReleaseMonitorVersion(ctx, cfg, updateConfig.ReleaseMonitor, orchestrator)
	}

	// Check git monitor
	if updateConfig.GitMonitor != nil {
		return vc.getLatestValidGitVersion(ctx, cfg, updateConfig.GitMonitor, orchestrator)
	}

	return "", "", fmt.Errorf("no supported update monitor configured")
}

// getLatestValidGitHubVersion gets the latest valid version from GitHub
func (vc *VersionChecker) getLatestValidGitHubVersion(ctx context.Context, cfg *melange.Configuration, monitor *melange.GitHubMonitor, orchestrator *UpdateOrchestrator) (string, string, error) {
	repo, err := githubClient.ParseRepository(monitor.Identifier)
	if err != nil {
		return "", "github", fmt.Errorf("parsing repository identifier: %w", err)
	}

	// Create version filter with package context
	versionFilter, _ := orchestrator.GetVersionComponents()
	filterFunc := vc.createVersionFilter(ctx, cfg, versionFilter)

	// Get GitHub client
	_, githubClient, _, _ := orchestrator.GetServiceClients()

	// Determine source type
	source := "github-releases"
	if monitor.UseTags {
		source = "github-tags"
	}

	logging.From(ctx).Debug("Checking GitHub for updates",
		"repository", monitor.Identifier,
		"use_tags", monitor.UseTags)

	// The deprecated tag-filter key has prefix semantics; tag-filter-prefix wins when both are set.
	tagPrefix := cmp.Or(monitor.TagFilterPrefix, monitor.TagFilter) //nolint:staticcheck // deprecated tag-filter kept for compat

	// Get the first valid version using the filter
	var validVersion string
	if monitor.UseTags {
		validVersion, err = githubClient.GetFirstValidTag(
			ctx,
			repo.Owner,
			repo.Name,
			tagPrefix,
			monitor.TagFilterContains,
			filterFunc,
		)
	} else {
		validVersion, err = githubClient.GetFirstValidRelease(
			ctx,
			repo.Owner,
			repo.Name,
			tagPrefix,
			monitor.TagFilterContains,
			filterFunc,
		)
	}

	if err != nil {
		return "", source, err
	}

	// Process the valid version to get the final processed form
	processed, _, _ := versionFilter.ProcessVersion(ctx, validVersion, &cfg.Update)

	return processed, source, nil
}

// getLatestValidReleaseMonitorVersion gets the latest valid version from release-monitoring.org
func (vc *VersionChecker) getLatestValidReleaseMonitorVersion(ctx context.Context, cfg *melange.Configuration, monitor *melange.ReleaseMonitor, orchestrator *UpdateOrchestrator) (string, string, error) {
	anityaClient, _, _, _ := orchestrator.GetServiceClients()

	logging.From(ctx).Debug("Checking release-monitoring.org for updates", "identifier", monitor.Identifier)

	// Get the single version from release monitor
	version, err := anityaClient.GetLatestVersion(ctx, monitor.Identifier)
	if err != nil {
		return "", "release-monitor", fmt.Errorf("getting version from release-monitoring.org: %w", err)
	}

	if !matchesTagFilters(version, monitor.VersionFilterPrefix, monitor.VersionFilterContains) {
		return "", "release-monitor", fmt.Errorf("version %s filtered out by version-filter rules", version)
	}

	// Process it through validation pipeline
	versionFilter, _ := orchestrator.GetVersionComponents()
	processed, valid, err := versionFilter.ProcessVersion(ctx, version, &cfg.Update)
	if err != nil {
		return "", "release-monitor", fmt.Errorf("processing version: %w", err)
	}

	if !valid {
		return "", "release-monitor", fmt.Errorf("version %s filtered out by update rules", version)
	}

	return processed, "release-monitor", nil
}

// getLatestValidGitVersion gets the latest valid version from a Git repository
func (vc *VersionChecker) getLatestValidGitVersion(ctx context.Context, cfg *melange.Configuration, monitor *melange.GitMonitor, orchestrator *UpdateOrchestrator) (string, string, error) {
	// Extract repository URL from the pipeline
	repoURL, err := extractRepositoryFromConfig(cfg)
	if err != nil {
		return "", "git", fmt.Errorf("extracting repository from pipeline: %w", err)
	}

	logging.From(ctx).Debug("Checking Git repository for updates", "repository", repoURL)

	// Create version filter
	versionFilter, _ := orchestrator.GetVersionComponents()
	filterFunc := vc.createVersionFilter(ctx, cfg, versionFilter)

	// Get Git client
	_, _, gitClient, _ := orchestrator.GetServiceClients()

	// Apply the monitor's tag filters to raw tags before version processing
	inner := filterFunc
	filterFunc = func(tag string) bool {
		return matchesTagFilters(tag, monitor.TagFilterPrefix, monitor.TagFilterContains) && inner(tag)
	}

	// Get the first valid version using the filter
	validVersion, err := gitClient.GetFirstValidTag(ctx, repoURL, filterFunc)
	if err != nil {
		return "", "git", err
	}

	// Process the valid version to get the final processed form
	processed, _, _ := versionFilter.ProcessVersion(ctx, validVersion, &cfg.Update)

	return processed, "git", nil
}

// matchesTagFilters reports whether a raw tag/version passes the monitor's
// prefix and substring filters. Empty filters match everything; when both are
// set, both must match (mirroring upstream wolfictl behaviour).
func matchesTagFilters(value, prefix, contains string) bool {
	if prefix != "" && !strings.HasPrefix(value, prefix) {
		return false
	}
	if contains != "" && !strings.Contains(value, contains) {
		return false
	}
	return true
}

// createVersionFilter creates a unified filter function with logging context
func (vc *VersionChecker) createVersionFilter(ctx context.Context, cfg *melange.Configuration, filter *VersionFilter) func(string) bool {
	return func(rawVersion string) bool {
		// Extend for this filtering operation only - versionCtx is local to
		// this call, never fed back into the outer ctx.
		versionCtx := logging.With(ctx, "checking_version", rawVersion)

		// Apply ALL filtering logic with logging context
		processed, valid, err := filter.ProcessVersion(versionCtx, rawVersion, &cfg.Update)
		if err != nil {
			logging.From(versionCtx).Debug("Error processing version", "error", err)
			return false
		}

		if valid {
			logging.From(versionCtx).Debug("Version accepted", "original", rawVersion, "processed", processed)
		} else {
			logging.From(versionCtx).Debug("Version rejected", "original", rawVersion)
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

	// ctx already carries "stage"/"stage_index" - processor.Pipeline.Execute
	// seeds them before calling any stage method.

	if up.GetOptions().DryRun {
		logging.From(ctx).Info("Dry run - would update version",
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

	logging.From(ctx).Info("Version updated",
		"old_version", up.GetCurrentVersion(),
		"new_version", up.LatestVersion)

	return nil
}
