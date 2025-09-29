package updater

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	melangeConfig "github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/git"
	githubClient "github.com/isometry/choam/internal/github"
	"github.com/isometry/choam/internal/processor"
)

// PipelineProcessor implements ApplyStage for pipeline modifications
type PipelineProcessor struct {
	processor.BaseStage
	orchestrator *UpdateOrchestrator
}

func NewPipelineProcessor(orchestrator *UpdateOrchestrator) *PipelineProcessor {
	return &PipelineProcessor{
		BaseStage: processor.BaseStage{
			StageName:        "pipeline_process",
			StageDescription: "Process and update pipeline configurations",
		},
		orchestrator: orchestrator,
	}
}

func (pp *PipelineProcessor) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	up, ok := p.(*UpdaterProcessor)
	if !ok {
		return false, fmt.Errorf("expected UpdaterProcessor, got %T", p)
	}

	// Run if we have version changes that might require pipeline updates
	return up.VersionChanged, nil
}

func (pp *PipelineProcessor) Apply(ctx context.Context, p processor.Processor) error {
	up, ok := p.(*UpdaterProcessor)
	if !ok {
		return fmt.Errorf("expected UpdaterProcessor, got %T", p)
	}

	logger := up.WithStage(pp.Name())

	// Skip if no version update (pipelines only change with version updates)
	if !up.VersionChanged && !up.GetOptions().Force {
		logger.Debug("No version change - skipping pipeline updates")
		return nil
	}

	logger.Info("Starting pipeline updates")

	// Get service clients
	_, githubClient, gitClient, httpClient := pp.orchestrator.GetServiceClients()

	loader := newMelangeLoader()

	// Process git-checkout pipelines
	if err := pp.processGitCheckoutPipelines(ctx, up, loader, githubClient, gitClient, logger); err != nil {
		return fmt.Errorf("processing git-checkout pipelines: %w", err)
	}

	// Process fetch pipelines
	if err := pp.processFetchPipelines(ctx, up, loader, httpClient, logger); err != nil {
		return fmt.Errorf("processing fetch pipelines: %w", err)
	}

	logger.Info("Pipeline updates completed", "changes", len(up.PipelineChanges))
	return nil
}

// processGitCheckoutPipelines updates git-checkout pipelines with new expected-commit
func (pp *PipelineProcessor) processGitCheckoutPipelines(ctx context.Context, processor *UpdaterProcessor, loader *melangeConfig.Loader, githubClient *githubClient.Client, gitClient *git.Client, logger *slog.Logger) error {
	// Find git-checkout pipelines
	gitCheckoutIndices, err := loader.FindPipelinesByUse(processor.GetCurrentYAML(), "git-checkout")
	if err != nil {
		return fmt.Errorf("finding git-checkout pipelines: %w", err)
	}

	logger.Debug("Processing git-checkout pipelines", "count", len(gitCheckoutIndices))

	for _, index := range gitCheckoutIndices {
		pipelineLogger := processor.WithPipeline("git-checkout", index)
		pipelineLogger.Debug("Examining git-checkout pipeline", "index", index)

		if err := pp.updateGitCheckoutPipeline(ctx, processor, index, loader, githubClient, gitClient, pipelineLogger); err != nil {
			return fmt.Errorf("updating git-checkout[%d]: %w", index, err)
		}
	}

	return nil
}

// updateGitCheckoutPipeline updates a single git-checkout pipeline
func (pp *PipelineProcessor) updateGitCheckoutPipeline(ctx context.Context, processor *UpdaterProcessor, pipelineIndex int, loader *melangeConfig.Loader, githubClient *githubClient.Client, gitClient *git.Client, logger *slog.Logger) error {
	// Get current pipeline configuration
	withFields, err := loader.GetPipelineWithField(processor.GetCurrentYAML(), pipelineIndex)
	if err != nil {
		return fmt.Errorf("getting pipeline with fields: %w", err)
	}

	// Check if this pipeline has expected-commit
	currentCommit, hasExpectedCommit := withFields["expected-commit"]
	if !hasExpectedCommit {
		logger.Debug("Pipeline has no expected-commit field - skipping")
		return nil
	}

	// Get repository info
	repoURL, tag, err := pp.extractGitInfo(withFields, processor)
	if err != nil {
		return fmt.Errorf("extracting git info: %w", err)
	}

	// Get the commit SHA for the new version
	newCommit, err := pp.getCommitForTag(ctx, repoURL, tag, processor, githubClient, gitClient)
	if err != nil {
		return fmt.Errorf("getting commit for tag %s: %w", tag, err)
	}

	// Skip if commit hasn't changed
	if currentCommit == newCommit {
		logger.Debug("Commit unchanged - skipping pipeline update", "commit", newCommit[:12])
		return nil
	}

	// Update the expected-commit field
	updatedContent, err := loader.UpdatePipelineField(processor.GetCurrentYAML(), pipelineIndex, "expected-commit", newCommit)
	if err != nil {
		return fmt.Errorf("updating expected-commit: %w", err)
	}

	processor.SetCurrentYAML(updatedContent)

	// Record the change
	change := PipelineChange{
		Type:        "git-checkout",
		Index:       pipelineIndex,
		Field:       "expected-commit",
		OldValue:    currentCommit,
		NewValue:    newCommit,
		Description: fmt.Sprintf("pipeline[%d].with.expected-commit", pipelineIndex),
	}
	processor.AddPipelineChange(change)

	logger.Info("Git checkout pipeline updated", "old_commit", currentCommit[:12], "new_commit", newCommit[:12])
	return nil
}

// processFetchPipelines updates fetch pipelines with new expected-sha256 if URL changed
func (pp *PipelineProcessor) processFetchPipelines(ctx context.Context, processor *UpdaterProcessor, loader *melangeConfig.Loader, httpClient *http.Client, logger *slog.Logger) error {
	// Find fetch pipelines
	fetchIndices, err := loader.FindPipelinesByUse(processor.GetCurrentYAML(), "fetch")
	if err != nil {
		return fmt.Errorf("finding fetch pipelines: %w", err)
	}

	logger.Debug("Processing fetch pipelines", "count", len(fetchIndices))

	for _, index := range fetchIndices {
		pipelineLogger := processor.WithPipeline("fetch", index)
		pipelineLogger.Debug("Examining fetch pipeline", "index", index)

		if err := pp.updateFetchPipeline(ctx, processor, index, loader, httpClient, pipelineLogger); err != nil {
			return fmt.Errorf("updating fetch[%d]: %w", index, err)
		}
	}

	return nil
}

// updateFetchPipeline updates a single fetch pipeline
func (pp *PipelineProcessor) updateFetchPipeline(ctx context.Context, processor *UpdaterProcessor, pipelineIndex int, loader *melangeConfig.Loader, httpClient *http.Client, logger *slog.Logger) error {
	// Get current pipeline configuration
	withFields, err := loader.GetPipelineWithField(processor.GetCurrentYAML(), pipelineIndex)
	if err != nil {
		return fmt.Errorf("getting pipeline with fields: %w", err)
	}

	// Check if this pipeline has expected-sha256 and uri
	uri, hasURI := withFields["uri"]
	currentSHA, hasSHA := withFields["expected-sha256"]

	if !hasURI || !hasSHA {
		logger.Debug("Pipeline missing uri or expected-sha256 - skipping")
		return nil
	}

	// Check if URI contains version variable
	if !pp.uriContainsVersionVariable(uri) {
		logger.Debug("URI does not contain version variable - skipping")
		return nil
	}

	// Render the new URI with updated version using simple variable substitution
	newURI := substituteVariables(uri, processor.LatestVersion)

	// Skip if URI hasn't changed
	if uri == newURI {
		logger.Debug("URI unchanged - skipping fetch pipeline update")
		return nil
	}

	// Calculate SHA256 for the new URI
	checksumHelper := NewChecksumHelperWithClient(httpClient)
	newSHA256, err := checksumHelper.CalculateSHA256FromURL(ctx, newURI)
	if err != nil {
		return fmt.Errorf("calculating SHA256 for %s: %w", newURI, err)
	}

	// Update both URI and expected-sha256
	updatedContent := processor.GetCurrentYAML()

	// Update URI first
	updatedContent, err = loader.UpdatePipelineField(updatedContent, pipelineIndex, "uri", newURI)
	if err != nil {
		return fmt.Errorf("updating uri: %w", err)
	}

	// Update expected-sha256
	updatedContent, err = loader.UpdatePipelineField(updatedContent, pipelineIndex, "expected-sha256", newSHA256)
	if err != nil {
		return fmt.Errorf("updating expected-sha256: %w", err)
	}

	processor.SetCurrentYAML(updatedContent)

	// Record the change
	change := PipelineChange{
		Type:        "fetch",
		Index:       pipelineIndex,
		Field:       "uri/expected-sha256",
		OldValue:    fmt.Sprintf("%s (%s)", uri, currentSHA),
		NewValue:    fmt.Sprintf("%s (%s)", newURI, newSHA256),
		Description: fmt.Sprintf("pipeline[%d].with.uri and expected-sha256", pipelineIndex),
	}
	processor.AddPipelineChange(change)

	logger.Info("Fetch pipeline updated", "new_uri", newURI, "new_sha256", newSHA256[:12]+"...")
	return nil
}

// extractGitInfo extracts repository and tag information for git operations
func (pp *PipelineProcessor) extractGitInfo(withFields map[string]string, processor *UpdaterProcessor) (repoURL, tag string, err error) {
	// Try to get repository from with fields
	if repo, ok := withFields["repository"]; ok {
		repoURL = repo
	}

	// Try to get tag from with fields and substitute version
	if tagTemplate, ok := withFields["tag"]; ok {
		tag = substituteVariables(tagTemplate, processor.LatestVersion)
	}

	// If no repository in pipeline, try to get from update config
	if repoURL == "" {
		if processor.Config.Update.GitHubMonitor != nil {
			repoURL = fmt.Sprintf("https://github.com/%s.git", processor.Config.Update.GitHubMonitor.Identifier)
		}
	}

	if repoURL == "" {
		return "", "", fmt.Errorf("no repository URL found")
	}

	if tag == "" {
		tag = processor.LatestVersion
	}

	return repoURL, tag, nil
}

// getCommitForTag gets the commit SHA for a specific tag
func (pp *PipelineProcessor) getCommitForTag(ctx context.Context, repoURL, tag string, processor *UpdaterProcessor, client *githubClient.Client, gitClient *git.Client) (string, error) {
	// If update source is GitHub, try GitHub API first
	if strings.Contains(processor.UpdateSource, "github") {
		repo, err := githubClient.ParseRepository(strings.TrimSuffix(strings.TrimPrefix(repoURL, "https://github.com/"), ".git"))
		if err == nil {
			commitSHA, err := client.GetCommitForTag(ctx, repo.Owner, repo.Name, tag)
			if err == nil {
				return commitSHA, nil
			}
		}
	}

	// Fallback to git client
	return gitClient.GetCommitSHAForTag(ctx, repoURL, tag)
}

// uriContainsVersionVariable checks if a URI contains version variables
func (pp *PipelineProcessor) uriContainsVersionVariable(uri string) bool {
	versionVariables := []string{
		"${{package.version}}",
		"${package.version}",
		"${{package.full-version}}",
		"${package.full-version}",
	}

	for _, variable := range versionVariables {
		if strings.Contains(uri, variable) {
			return true
		}
	}

	return false
}