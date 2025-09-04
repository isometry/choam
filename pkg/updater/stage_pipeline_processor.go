package updater

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	melangeConfig "github.com/isometry/choam/pkg/config"
	"github.com/isometry/choam/pkg/git"
	"github.com/isometry/choam/pkg/github"
)

// PipelineProcessor implements ApplyStage to update pipeline configurations
type PipelineProcessor struct{}

func (pp *PipelineProcessor) Name() string {
	return "pipeline_update"
}

func (pp *PipelineProcessor) Description() string {
	return "Update pipeline configurations (git-checkout, fetch)"
}

// Apply updates pipeline configurations based on version changes
func (pp *PipelineProcessor) Apply(ctx context.Context, processor *PackageProcessor) error {
	logger := processor.WithStage(pp.Name())

	// Skip if no version update (pipelines only change with version updates)
	if !processor.VersionChanged && !processor.Options.Force {
		logger.Debug("No version change - skipping pipeline updates")
		return nil
	}

	logger.Info("Starting pipeline updates")

	// Get service clients
	orchestrator := NewOrchestrator()
	_, githubClient, gitClient, httpClient := orchestrator.GetServiceClients()

	loader := newMelangeLoader()

	// Process git-checkout pipelines
	if err := pp.processGitCheckoutPipelines(ctx, processor, loader, githubClient, gitClient, logger); err != nil {
		return fmt.Errorf("processing git-checkout pipelines: %w", err)
	}

	// Process fetch pipelines
	if err := pp.processFetchPipelines(ctx, processor, loader, httpClient, logger); err != nil {
		return fmt.Errorf("processing fetch pipelines: %w", err)
	}

	logger.Info("Pipeline updates completed", "changes", len(processor.PipelineChanges))
	return nil
}

// processGitCheckoutPipelines updates git-checkout pipelines with new expected-commit
func (pp *PipelineProcessor) processGitCheckoutPipelines(ctx context.Context, processor *PackageProcessor, loader *melangeConfig.Loader, githubClient *github.Client, gitClient *git.Client, logger *slog.Logger) error {
	// Find git-checkout pipelines
	gitCheckoutIndices, err := loader.FindPipelinesByUse(processor.CurrentYAML, "git-checkout")
	if err != nil {
		return fmt.Errorf("finding git-checkout pipelines: %w", err)
	}

	logger.Debug("Processing git-checkout pipelines", "count", len(gitCheckoutIndices))

	for _, index := range gitCheckoutIndices {
		pipelineLogger := processor.WithPipeline("git-checkout", index)

		if err := pp.updateGitCheckoutPipeline(ctx, processor, index, loader, githubClient, gitClient, pipelineLogger); err != nil {
			return fmt.Errorf("updating git-checkout[%d]: %w", index, err)
		}
	}

	return nil
}

// updateGitCheckoutPipeline updates a single git-checkout pipeline
func (pp *PipelineProcessor) updateGitCheckoutPipeline(ctx context.Context, processor *PackageProcessor, pipelineIndex int, loader *melangeConfig.Loader, githubClient *github.Client, gitClient *git.Client, logger *slog.Logger) error {
	// Get current pipeline configuration
	withFields, err := loader.GetPipelineWithField(processor.CurrentYAML, pipelineIndex)
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
	commitSHA, err := pp.getCommitForTag(ctx, repoURL, tag, processor, githubClient, gitClient)
	if err != nil {
		return fmt.Errorf("getting commit for tag %s: %w", tag, err)
	}

	// Only update if commit actually changed
	if currentCommit == commitSHA {
		logger.Debug("Commit unchanged - skipping", "commit", commitSHA)
		return nil
	}

	// Skip if dry run
	if processor.Options.DryRun {
		logger.Info("Dry run - would update expected-commit",
			"current", currentCommit,
			"new", commitSHA)
		change := PipelineChange{
			Type:        "git-checkout",
			Index:       pipelineIndex,
			Field:       "expected-commit",
			OldValue:    currentCommit,
			NewValue:    commitSHA,
			Description: fmt.Sprintf("would update pipeline[%d].with.expected-commit", pipelineIndex),
		}
		processor.AddPipelineChange(change)
		return nil
	}

	// Update the expected-commit field
	updatedContent, err := loader.UpdatePipelineField(processor.CurrentYAML, pipelineIndex, "expected-commit", commitSHA)
	if err != nil {
		return fmt.Errorf("updating expected-commit: %w", err)
	}

	processor.CurrentYAML = updatedContent

	// Record the change
	change := PipelineChange{
		Type:        "git-checkout",
		Index:       pipelineIndex,
		Field:       "expected-commit",
		OldValue:    currentCommit,
		NewValue:    commitSHA,
		Description: fmt.Sprintf("pipeline[%d].with.expected-commit", pipelineIndex),
	}
	processor.AddPipelineChange(change)

	logger.Info("Git-checkout pipeline updated", "commit", commitSHA)
	return nil
}

// processFetchPipelines updates fetch pipelines with new expected-sha256 if URL changed
func (pp *PipelineProcessor) processFetchPipelines(ctx context.Context, processor *PackageProcessor, loader *melangeConfig.Loader, httpClient *http.Client, logger *slog.Logger) error {
	// Find fetch pipelines
	fetchIndices, err := loader.FindPipelinesByUse(processor.CurrentYAML, "fetch")
	if err != nil {
		return fmt.Errorf("finding fetch pipelines: %w", err)
	}

	logger.Debug("Processing fetch pipelines", "count", len(fetchIndices))

	for _, index := range fetchIndices {
		pipelineLogger := processor.WithPipeline("fetch", index)

		if err := pp.updateFetchPipeline(ctx, processor, index, loader, httpClient, pipelineLogger); err != nil {
			return fmt.Errorf("updating fetch[%d]: %w", index, err)
		}
	}

	return nil
}

// updateFetchPipeline updates a single fetch pipeline
func (pp *PipelineProcessor) updateFetchPipeline(ctx context.Context, processor *PackageProcessor, pipelineIndex int, loader *melangeConfig.Loader, httpClient *http.Client, logger *slog.Logger) error {
	// Get current pipeline configuration
	withFields, err := loader.GetPipelineWithField(processor.CurrentYAML, pipelineIndex)
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

	// Check if the URI contains version variables that would change
	if !pp.uriContainsVersionVariable(uri) {
		logger.Debug("URI doesn't contain version variables - skipping")
		return nil
	}

	// Calculate new URI with updated version using renderer
	var newURI string
	renderer, rendererErr := melangeConfig.NewRenderer(processor.Config)
	if rendererErr != nil {
		// Fallback to existing method
		newURI = substituteVariablesWithConfig(uri, processor.LatestVersion, processor.Config)
	} else {
		renderedURI, renderErr := renderer.RenderString(uri)
		if renderErr != nil {
			// Fallback to existing method
			newURI = substituteVariablesWithConfig(uri, processor.LatestVersion, processor.Config)
		} else {
			newURI = renderedURI
		}
	}
	if newURI == uri {
		logger.Debug("URI unchanged after substitution - skipping")
		return nil
	}

	// Skip if dry run
	if processor.Options.DryRun {
		logger.Info("Dry run - would update fetch URI and SHA256",
			"current_uri", uri,
			"new_uri", newURI)
		change := PipelineChange{
			Type:        "fetch",
			Index:       pipelineIndex,
			Field:       "uri/expected-sha256",
			OldValue:    fmt.Sprintf("%s (%s)", uri, currentSHA),
			NewValue:    fmt.Sprintf("%s (new SHA256)", newURI),
			Description: fmt.Sprintf("would update pipeline[%d].with.uri and expected-sha256", pipelineIndex),
		}
		processor.AddPipelineChange(change)
		return nil
	}

	// Calculate new SHA256 for the new URI
	checksumHelper := NewChecksumHelperWithClient(httpClient)
	newSHA256, err := checksumHelper.CalculateSHA256FromURL(ctx, newURI)
	if err != nil {
		return fmt.Errorf("calculating SHA256 for %s: %w", newURI, err)
	}

	// Update both URI and expected-sha256
	updatedContent := processor.CurrentYAML

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

	processor.CurrentYAML = updatedContent

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
func (pp *PipelineProcessor) extractGitInfo(withFields map[string]string, processor *PackageProcessor) (repoURL, tag string, err error) {
	// Try to get repository from with fields
	if repo, ok := withFields["repository"]; ok {
		repoURL = repo
	}

	// Try to get tag from with fields and substitute version using renderer
	if tagTemplate, ok := withFields["tag"]; ok {
		// Use cloned config with updated version if processor has version change
		configForRendering := processor.Config
		if processor.VersionChanged && processor.LatestVersion != processor.Config.Package.Version {
			configForRendering = cloneConfigWithVersion(processor.Config, processor.LatestVersion)
			if configForRendering == nil {
				// Fallback to original config if cloning failed
				configForRendering = processor.Config
			}
		}

		renderer, rendererErr := melangeConfig.NewRenderer(configForRendering)
		if rendererErr != nil {
			// Fallback to existing method
			tag = substituteVariablesWithConfig(tagTemplate, processor.LatestVersion, processor.Config)
		} else {
			renderedTag, renderErr := renderer.RenderString(tagTemplate)
			if renderErr != nil {
				// Fallback to existing method
				tag = substituteVariablesWithConfig(tagTemplate, processor.LatestVersion, processor.Config)
			} else {
				tag = renderedTag
			}
		}
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
func (pp *PipelineProcessor) getCommitForTag(ctx context.Context, repoURL, tag string, processor *PackageProcessor, githubClient *github.Client, gitClient *git.Client) (string, error) {
	// If update source is GitHub, try GitHub API first
	if strings.Contains(processor.UpdateSource, "github") {
		repo, err := github.ParseRepository(strings.TrimSuffix(strings.TrimPrefix(repoURL, "https://github.com/"), ".git"))
		if err == nil {
			commitSHA, err := githubClient.GetCommitForTag(ctx, repo.Owner, repo.Name, tag)
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
