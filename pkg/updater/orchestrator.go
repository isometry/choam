package updater

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/pkg/anitya"
	"github.com/isometry/choam/pkg/git"
	githubClient "github.com/isometry/choam/pkg/github"
	"github.com/isometry/choam/pkg/scan"
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

	// Stage registry for extensible pipeline
	stageRegistry *StageRegistry

	// Shared cache for vulnerability scans to avoid duplicate API calls
	vulnerabilityCache *scan.VulnerabilityCache

	// Configuration
	verbose bool
}

// NewOrchestrator creates a new update orchestrator with default configuration
func NewOrchestrator() *UpdateOrchestrator {
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	return &UpdateOrchestrator{
		anityaClient:       anitya.New(),
		githubClient:       githubClient.New(),
		gitClient:          git.New(),
		httpClient:         httpClient,
		versionFilter:      NewVersionFilter(),
		versionComparator:  NewVersionComparator(),
		stageRegistry:      DefaultStageRegistry(),
		vulnerabilityCache: scan.NewVulnerabilityCache(),
		verbose:            false,
	}
}

// SetVerbose configures verbose logging for the orchestrator
func (o *UpdateOrchestrator) SetVerbose(verbose bool) {
	o.verbose = verbose
	InitLogger(verbose)
}

// ProcessPackageCheck runs only the check pipeline for a package
// This loads the configuration and determines if updates are available
func (o *UpdateOrchestrator) ProcessPackageCheck(ctx context.Context, filePath string) (*PackageProcessor, error) {
	return o.processPackageCheckWithConfig(ctx, filePath, nil, nil)
}

// ProcessPackageCheckWithConfig runs check pipeline with pre-loaded configuration
func (o *UpdateOrchestrator) ProcessPackageCheckWithConfig(ctx context.Context, filePath string, cfg *melange.Configuration, originalContent []byte) (*PackageProcessor, error) {
	return o.processPackageCheckWithConfig(ctx, filePath, cfg, originalContent)
}

// processPackageCheckWithConfig is the internal implementation
func (o *UpdateOrchestrator) processPackageCheckWithConfig(ctx context.Context, filePath string, cfg *melange.Configuration, originalContent []byte) (*PackageProcessor, error) {
	// Load configuration if not provided
	if cfg == nil {
		loader := newMelangeLoader()
		var err error
		cfg, originalContent, err = loader.LoadWithPreservation(filePath)
		if err != nil {
			return nil, fmt.Errorf("loading configuration %s: %w", filePath, err)
		}
	}

	// Create processor with rich logging context
	processor := NewPackageProcessor(filePath, cfg.Package.Name, cfg.Package.Version, int64(cfg.Package.Epoch))
	processor.Config = cfg
	processor.OriginalYAML = originalContent
	processor.CurrentYAML = originalContent

	// Log start of check process
	processor.Logger.Info("Starting package check")

	// Run through check stages
	for _, stage := range o.stageRegistry.GetCheckStages() {
		stageLogger := processor.WithStage(stage.Name())
		stageLogger.Debug("Running check stage")

		if err := stage.Check(ctx, processor); err != nil {
			processor.AddError(fmt.Errorf("check stage %s failed: %w", stage.Name(), err))
			return processor, err
		}

		stageLogger.Debug("Check stage completed")
	}

	processor.Logger.Info("Package check completed",
		"update_available", processor.UpdateAvailable,
		"latest_version", processor.LatestVersion)

	return processor, nil
}

// ProcessPackageApply runs the full pipeline (check + apply) for a package
// This includes checking for updates and applying them if found
func (o *UpdateOrchestrator) ProcessPackageApply(ctx context.Context, filePath string, options ProcessorOptions) (*PackageProcessor, error) {
	// Start with check phase
	processor, err := o.ProcessPackageCheck(ctx, filePath)
	if err != nil {
		return processor, fmt.Errorf("check phase failed: %w", err)
	}

	// Set processing options
	processor.Options = options

	// Skip apply if no update available, no go/bump actions, and not forced
	// Note: Security scanning now always runs as part of go/bump processing
	if !processor.UpdateAvailable && !processor.HasGoDepsActions() && !options.Force {
		processor.Logger.Info("No updates or go/bump actions available, skipping apply phase")
		return processor, nil
	}

	// Skip manual updates unless forced
	if processor.IsManual && !options.Force {
		processor.AddMessage("manual update - automatic updates skipped")
		return processor, nil
	}

	processor.Logger.Info("Starting package apply", "force", options.Force, "dry_run", options.DryRun)

	// Run through apply stages
	for _, stage := range o.stageRegistry.GetApplyStages() {
		stageLogger := processor.WithStage(stage.Name())
		stageLogger.Debug("Running apply stage")

		if err := stage.Apply(ctx, processor); err != nil {
			processor.AddError(fmt.Errorf("apply stage %s failed: %w", stage.Name(), err))
			return processor, err
		}

		stageLogger.Debug("Apply stage completed", "has_changes", processor.HasChanges())
	}

	// Epoch bump handling is now done by EpochApplier stage

	processor.Logger.Info("Package apply completed",
		"has_changes", processor.HasChanges(),
		"version_changed", processor.VersionChanged,
		"epoch_changed", processor.EpochChanged,
		"pipeline_changes", len(processor.PipelineChanges),
		"security_fixes", len(processor.SecurityFixes))

	return processor, nil
}

// ProcessMultipleChecks processes multiple packages for update checking
func (o *UpdateOrchestrator) ProcessMultipleChecks(ctx context.Context, filePaths []string) ([]*PackageProcessor, error) {
	processors := make([]*PackageProcessor, 0, len(filePaths))

	for _, filePath := range filePaths {
		processor, err := o.ProcessPackageCheck(ctx, filePath)
		if err != nil {
			// Create error processor to maintain consistent results
			if processor == nil {
				processor = &PackageProcessor{
					FilePath: filePath,
					Logger:   slog.Default().With("file", filePath),
				}
			}
			processor.AddError(err)
		}
		processors = append(processors, processor)
	}

	return processors, nil
}

// ProcessMultipleApplies processes multiple packages for updates
func (o *UpdateOrchestrator) ProcessMultipleApplies(ctx context.Context, filePaths []string, options ProcessorOptions) ([]*PackageProcessor, error) {
	processors := make([]*PackageProcessor, 0, len(filePaths))

	for _, filePath := range filePaths {
		processor, err := o.ProcessPackageApply(ctx, filePath, options)
		if err != nil {
			// Error is already recorded in processor, continue with other packages
			if processor == nil {
				processor = &PackageProcessor{
					FilePath: filePath,
					Logger:   slog.Default().With("file", filePath),
				}
				processor.AddError(err)
			}
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

// GetVulnerabilityCache returns the shared vulnerability cache
func (o *UpdateOrchestrator) GetVulnerabilityCache() *scan.VulnerabilityCache {
	return o.vulnerabilityCache
}

// RegisterCheckStage adds a custom check stage to the pipeline
func (o *UpdateOrchestrator) RegisterCheckStage(stage CheckStage) {
	o.stageRegistry.RegisterCheckStage(stage)
}

// RegisterApplyStage adds a custom apply stage to the pipeline
func (o *UpdateOrchestrator) RegisterApplyStage(stage ApplyStage) {
	o.stageRegistry.RegisterApplyStage(stage)
}
