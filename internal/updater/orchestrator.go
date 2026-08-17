package updater

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/anitya"
	"github.com/isometry/choam/internal/git"
	githubClient "github.com/isometry/choam/internal/github"
	"github.com/isometry/choam/internal/httpclient"
	"github.com/isometry/choam/internal/processor"
)

// UpdateOrchestrator manages the package update pipeline using a stage-based architecture
// It replaces the previous Updater with a cleaner separation of concerns and proper
// logging context throughout the entire process.
type UpdateOrchestrator struct {
	// Service clients (shared across all processors)
	anityaClient *anitya.Client
	githubClient *githubClient.Client
	gitClient    *git.Client
	httpClient   *http.Client

	// Processing components
	versionFilter     *VersionFilter
	versionComparator *VersionComparator
}

// NewOrchestrator creates a new update orchestrator with default HTTP timeout
func NewOrchestrator() *UpdateOrchestrator {
	return NewOrchestratorWithTimeout(httpclient.DefaultTimeout)
}

// NewOrchestratorWithTimeout creates a new update orchestrator with a custom HTTP timeout
func NewOrchestratorWithTimeout(httpTimeout time.Duration) *UpdateOrchestrator {
	// Create shared HTTP client with specified timeout
	httpClient := httpclient.NewHTTPClientWithTimeout(httpTimeout)

	return &UpdateOrchestrator{
		anityaClient:      anitya.New(httpClient),
		githubClient:      githubClient.New(httpClient),
		gitClient:         git.New(),
		httpClient:        httpClient,
		versionFilter:     NewVersionFilter(),
		versionComparator: NewVersionComparator(),
	}
}

// ProcessPackageCheck runs only the check pipeline for a package
// This loads the configuration and determines if updates are available
func (o *UpdateOrchestrator) ProcessPackageCheck(ctx context.Context, filePath string) (*UpdaterProcessor, error) {
	return o.processPackageCheckWithConfig(ctx, filePath, nil, nil)
}

// ProcessPackageCheckWithConfig runs check pipeline with pre-loaded configuration
func (o *UpdateOrchestrator) ProcessPackageCheckWithConfig(ctx context.Context, filePath string, cfg *melange.Configuration, originalContent []byte) (*UpdaterProcessor, error) {
	return o.processPackageCheckWithConfig(ctx, filePath, cfg, originalContent)
}

// processPackageCheckWithConfig is the internal implementation
func (o *UpdateOrchestrator) processPackageCheckWithConfig(ctx context.Context, filePath string, cfg *melange.Configuration, originalContent []byte) (*UpdaterProcessor, error) {
	// Load configuration if not provided
	if cfg == nil {
		loader := newMelangeLoader()
		var err error
		cfg, originalContent, err = loader.LoadWithPreservation(ctx, filePath)
		if err != nil {
			return nil, fmt.Errorf("loading configuration %s: %w", filePath, err)
		}
	}

	// Create processor using the modern architecture
	updaterProcessor := NewUpdaterProcessor(filePath, cfg.Package.Name, cfg.Package.Version, int64(cfg.Package.Epoch))
	updaterProcessor.Config = cfg
	updaterProcessor.OriginalYAML = originalContent
	updaterProcessor.SetCurrentYAML(originalContent)

	// Log start of check process
	updaterProcessor.GetLogger().Info("Starting package check")

	// Create pipeline for check-only operations
	pipeline := processor.NewPipeline("checker")
	pipeline.AddStages(NewVersionChecker(o))

	if err := pipeline.Execute(ctx, updaterProcessor); err != nil {
		updaterProcessor.AddError(err)
		return updaterProcessor, fmt.Errorf("check pipeline failed: %w", err)
	}

	updaterProcessor.GetLogger().Info("Package check completed",
		"update_available", updaterProcessor.UpdateAvailable,
		"latest_version", updaterProcessor.LatestVersion)

	return updaterProcessor, nil
}

// ProcessPackageApply runs the full pipeline (check + apply) for a package
// This includes checking for updates and applying them if found
func (o *UpdateOrchestrator) ProcessPackageApply(ctx context.Context, filePath string, options ProcessorOptions) (*UpdaterProcessor, error) {
	// Start with check phase (get the internal processor, not the legacy result)
	updaterProcessor, err := o.processPackageCheckWithConfig(ctx, filePath, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("check phase failed: %w", err)
	}

	// Convert options to the correct type
	processorOptions := processor.ProcessorOptions{
		DryRun:        options.DryRun,
		Force:         options.Force,
		SharedUpdates: options.SharedUpdates,
		BackupSuffix:  options.BackupSuffix,
		TempDir:       options.TempDir,
	}
	updaterProcessor.SetOptions(processorOptions)

	// Skip apply if no update available and not forced
	if !updaterProcessor.UpdateAvailable && !options.Force {
		updaterProcessor.GetLogger().Info("No updates available, skipping apply phase")
		return updaterProcessor, nil
	}

	// Skip manual updates unless forced
	if updaterProcessor.IsManual && !options.Force {
		updaterProcessor.AddMessage("manual update - automatic updates skipped")
		return updaterProcessor, nil
	}

	updaterProcessor.GetLogger().Info("Starting package apply", "force", options.Force, "dry_run", options.DryRun)

	// Create and execute the full pipeline for apply operations
	pipeline := NewPipeline(o)
	if err := pipeline.Execute(ctx, updaterProcessor); err != nil {
		updaterProcessor.AddError(err)
		return updaterProcessor, fmt.Errorf("apply pipeline failed: %w", err)
	}

	updaterProcessor.GetLogger().Info("Package apply completed",
		"has_changes", updaterProcessor.HasChanges(),
		"version_changed", updaterProcessor.VersionChanged,
		"epoch_changed", updaterProcessor.IsEpochChanged(),
		"pipeline_changes", len(updaterProcessor.PipelineChanges))

	return updaterProcessor, nil
}

// ProcessMultipleChecks processes multiple packages for update checking
func (o *UpdateOrchestrator) ProcessMultipleChecks(ctx context.Context, filePaths []string) ([]*UpdaterProcessor, error) {
	processors := make([]*UpdaterProcessor, 0, len(filePaths))

	for i, filePath := range filePaths {
		if err := ctx.Err(); err != nil {
			return processors, err
		}

		slog.Info("processing melange file", "file", filePath, "index", i+1, "total", len(filePaths)) //nolint:forbidigo // this IS the file attribution - the per-file processor logger is seeded just below

		processor, err := o.ProcessPackageCheck(ctx, filePath)
		if err != nil {
			// Create error processor to maintain consistent results
			if processor == nil {
				// Extract package name from path for error case
				pkgName := filepath.Base(strings.TrimSuffix(filePath, filepath.Ext(filePath)))
				processor = NewUpdaterProcessor(filePath, pkgName, "", 0)
			}
			processor.AddError(err)
		}
		processors = append(processors, processor)
	}

	return processors, nil
}

// ProcessMultipleApplies processes multiple packages for updates
func (o *UpdateOrchestrator) ProcessMultipleApplies(ctx context.Context, filePaths []string, options ProcessorOptions) ([]*UpdaterProcessor, error) {
	processors := make([]*UpdaterProcessor, 0, len(filePaths))

	for i, filePath := range filePaths {
		if err := ctx.Err(); err != nil {
			return processors, err
		}

		slog.Info("processing melange file", "file", filePath, "index", i+1, "total", len(filePaths)) //nolint:forbidigo // this IS the file attribution - the per-file processor logger is seeded just below

		processor, err := o.ProcessPackageApply(ctx, filePath, options)
		if err != nil {
			// Error is already recorded in processor, continue with other packages
			if processor == nil {
				// Extract package name from path for error case
				pkgName := filepath.Base(strings.TrimSuffix(filePath, filepath.Ext(filePath)))
				processor = NewUpdaterProcessor(filePath, pkgName, "", 0)
			}
			processor.AddError(err)
		}
		processors = append(processors, processor)
	}

	return processors, nil
}

// GetServiceClients returns the service clients for use by stages
func (o *UpdateOrchestrator) GetServiceClients() (anitya *anitya.Client, github *githubClient.Client, git *git.Client, http *http.Client) {
	return o.anityaClient, o.githubClient, o.gitClient, o.httpClient
}

// GetVersionComponents returns the version filtering and comparison components
func (o *UpdateOrchestrator) GetVersionComponents() (*VersionFilter, *VersionComparator) {
	return o.versionFilter, o.versionComparator
}
