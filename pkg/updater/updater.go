package updater

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/pkg/anitya"
	"github.com/isometry/choam/pkg/git"
	githubClient "github.com/isometry/choam/pkg/github"
	"github.com/isometry/choam/pkg/types"
)

// UpdateResult represents the result of an update check
type UpdateResult struct {
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	HasUpdate      bool   `json:"has_update"`
	UpdateSource   string `json:"update_source"`
	IsManual       bool   `json:"is_manual"`
	Error          string `json:"error,omitempty"`
}

// Updater handles update detection for melange packages
type Updater struct {
	anityaClient *anitya.Client
	githubClient *githubClient.Client
	gitClient    *git.Client
	filter       *VersionFilter
	httpClient   *http.Client
	verbose      bool
}

// New creates a new updater
func New() *Updater {
	httpClient := &http.Client{
		Timeout: 60 * time.Second, // Standard timeout for all HTTP operations
	}

	return &Updater{
		anityaClient: anitya.New(),
		githubClient: githubClient.New(),
		gitClient:    git.New(),
		filter:       NewVersionFilter(),
		httpClient:   httpClient,
		verbose:      false,
	}
}

// SetVerbose sets the verbose flag for debugging output
func (u *Updater) SetVerbose(verbose bool) {
	u.verbose = verbose
	u.filter.SetVerbose(verbose)
}

// CreateVersionFilter creates a unified filter function that applies all filtering criteria
func (u *Updater) CreateVersionFilter(cfg *config.Configuration) types.VersionFilterFunc {
	return func(rawVersion string) bool {
		// Apply ALL filtering logic in one place:
		// 1. Strip prefix/suffix (from monitor config)
		// 2. Apply version transforms
		// 3. Check ignore regex patterns
		// 4. Validate version format
		// 5. Filter pre-releases if not enabled

		processed, valid, err := u.filter.ProcessVersion(rawVersion, &cfg.Update)
		if err != nil {
			if u.verbose {
				fmt.Fprintf(os.Stderr, "[DEBUG] Error processing version %q: %v\n", rawVersion, err)
			}
			return false
		}

		if u.verbose && valid {
			fmt.Fprintf(os.Stderr, "[DEBUG] Version %q ACCEPTED as %q\n", rawVersion, processed)
		}

		return valid
	}
}

// CheckUpdate checks for updates for a melange configuration
func (u *Updater) CheckUpdate(ctx context.Context, cfg *config.Configuration) (*UpdateResult, error) {
	result := &UpdateResult{
		PackageName:    cfg.Package.Name,
		CurrentVersion: cfg.Package.Version,
		HasUpdate:      false,
		IsManual:       cfg.Update.Manual,
	}

	// Check if updates are enabled
	if !cfg.Update.Enabled {
		return result, nil
	}

	// Check if update is excluded
	if cfg.Update.ExcludeReason != "" {
		result.Error = fmt.Sprintf("Updates excluded: %s", cfg.Update.ExcludeReason)
		return result, nil
	}

	// Get the latest VALID version (already filtered and processed)
	latestValidVersion, source, err := u.getLatestValidVersion(ctx, cfg)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	result.LatestVersion = latestValidVersion
	result.UpdateSource = source

	// Compare versions to check if we have an update
	comparator := NewVersionComparator()
	hasUpdate, err := comparator.IsNewer(cfg.Package.Version, latestValidVersion)
	if err != nil {
		result.Error = fmt.Errorf("comparing versions: %w", err).Error()
		return result, nil
	}

	result.HasUpdate = hasUpdate

	return result, nil
}

// getLatestValidVersion gets the latest VALID version from the appropriate source
// This combines fetching and filtering to find the first version that passes all validation rules
func (u *Updater) getLatestValidVersion(ctx context.Context, cfg *config.Configuration) (string, string, error) {
	updateConfig := &cfg.Update
	// Check GitHub monitor first (most common)
	if updateConfig.GitHubMonitor != nil {
		return u.getLatestValidGitHubVersion(ctx, cfg, updateConfig.GitHubMonitor)
	}

	// Check release monitor
	if updateConfig.ReleaseMonitor != nil {
		return u.getLatestValidReleaseMonitorVersion(ctx, cfg, updateConfig.ReleaseMonitor)
	}

	// Check git monitor
	if updateConfig.GitMonitor != nil {
		return u.getLatestValidGitVersion(ctx, cfg, updateConfig.GitMonitor)
	}

	return "", "", fmt.Errorf("no supported update monitor configured")
}

// getLatestValidGitHubVersion gets the latest VALID version from GitHub using unified filtering
func (u *Updater) getLatestValidGitHubVersion(ctx context.Context, cfg *config.Configuration, monitor *config.GitHubMonitor) (string, string, error) {
	repo, err := githubClient.ParseRepository(monitor.Identifier)
	if err != nil {
		return "", "github", fmt.Errorf("parsing repository identifier: %w", err)
	}

	// Create the unified filter function with ALL filtering logic
	filterFunc := u.CreateVersionFilter(cfg)

	// Determine source type
	source := "github-releases"
	if monitor.UseTags {
		source = "github-tags"
	}

	// Get the first valid version using the filter
	var validVersion string
	if monitor.UseTags {
		validVersion, err = u.githubClient.GetFirstValidTag(
			ctx,
			repo.Owner,
			repo.Name,
			monitor.TagFilterPrefix, // Pass prefix for API-level filtering
			filterFunc,
		)
	} else {
		validVersion, err = u.githubClient.GetFirstValidRelease(
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
	processed, _, _ := u.filter.ProcessVersion(validVersion, &cfg.Update)

	return processed, source, nil
}

// getLatestValidReleaseMonitorVersion gets the latest VALID version from release-monitoring.org
// For now, this falls back to the original method since anitya doesn't support batch processing
func (u *Updater) getLatestValidReleaseMonitorVersion(ctx context.Context, cfg *config.Configuration, monitor *config.ReleaseMonitor) (string, string, error) {
	// Get the single version from release monitor
	version, source, err := u.getReleaseMonitorVersion(ctx, monitor)
	if err != nil {
		return "", source, err
	}

	// Process it through our validation pipeline
	processed, valid, err := u.filter.ProcessVersion(version, &cfg.Update)
	if err != nil {
		return "", source, fmt.Errorf("processing version: %w", err)
	}

	if !valid {
		return "", source, fmt.Errorf("version %s filtered out by update rules", version)
	}

	return processed, source, nil
}

// getLatestValidGitVersion gets the latest VALID version from a Git repository using unified filtering
func (u *Updater) getLatestValidGitVersion(ctx context.Context, cfg *config.Configuration, monitor *config.GitMonitor) (string, string, error) {
	// Extract repository URL from the pipeline
	repoURL, err := u.extractRepositoryFromPipeline(cfg)
	if err != nil {
		return "", "git", fmt.Errorf("extracting repository from pipeline: %w", err)
	}

	// Create the unified filter function with ALL filtering logic
	filterFunc := u.CreateVersionFilter(cfg)

	// Get the first valid version using the filter
	validVersion, err := u.gitClient.GetFirstValidTag(ctx, repoURL, filterFunc)
	if err != nil {
		return "", "git", err
	}

	// Process the valid version to get the final processed form
	processed, _, _ := u.filter.ProcessVersion(validVersion, &cfg.Update)

	return processed, "git", nil
}

// getReleaseMonitorVersion gets the latest version from release-monitoring.org
func (u *Updater) getReleaseMonitorVersion(ctx context.Context, monitor *config.ReleaseMonitor) (string, string, error) {
	version, err := u.anityaClient.GetLatestVersion(ctx, monitor.Identifier)
	if err != nil {
		return "", "release-monitor", fmt.Errorf("getting version from release-monitoring.org: %w", err)
	}

	return version, "release-monitor", nil
}

// extractRepositoryFromPipeline extracts repository URL from git-checkout pipeline step
func (u *Updater) extractRepositoryFromPipeline(cfg *config.Configuration) (string, error) {
	for _, pipeline := range cfg.Pipeline {
		if pipeline.Uses == "git-checkout" && pipeline.With != nil {
			if repoURL, exists := pipeline.With["repository"]; exists {
				return repoURL, nil
			}
		}
	}
	return "", fmt.Errorf("no git-checkout pipeline step with repository found")
}

// CheckUpdates checks updates for multiple configurations
func (u *Updater) CheckUpdates(ctx context.Context, configs []*config.Configuration) ([]*UpdateResult, error) {
	results := make([]*UpdateResult, 0, len(configs))

	for _, cfg := range configs {
		result, err := u.CheckUpdate(ctx, cfg)
		if err != nil {
			// Create an error result
			result = &UpdateResult{
				PackageName:    cfg.Package.Name,
				CurrentVersion: cfg.Package.Version,
				HasUpdate:      false,
				Error:          err.Error(),
			}
		}
		results = append(results, result)
	}

	return results, nil
}

// LoadConfiguration loads a melange configuration from a file
func (u *Updater) LoadConfiguration(path string) (*config.Configuration, error) {
	cfg, err := config.ParseConfiguration(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("parsing configuration %s: %w", path, err)
	}

	return cfg, nil
}

// LoadConfigurations loads multiple melange configurations from files
func (u *Updater) LoadConfigurations(paths []string) ([]*config.Configuration, error) {
	configs := make([]*config.Configuration, 0, len(paths))

	for _, path := range paths {
		cfg, err := u.LoadConfiguration(path)
		if err != nil {
			return nil, fmt.Errorf("loading configuration %s: %w", path, err)
		}
		configs = append(configs, cfg)
	}

	return configs, nil
}
