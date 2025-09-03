package updater

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"chainguard.dev/melange/pkg/config"
	melangeConfig "github.com/isometry/choam/pkg/config"
	"github.com/isometry/choam/pkg/git"
	"github.com/isometry/choam/pkg/github"
)

// PipelineUpdateResult represents the result of pipeline updates
type PipelineUpdateResult struct {
	Content        []byte   `json:"-"` // Updated YAML content
	UpdatesApplied []string `json:"updates_applied"`
	Errors         []string `json:"errors,omitempty"`
}

// PipelineUpdater handles updating pipeline configurations
type PipelineUpdater struct {
	githubClient   *github.Client
	gitClient      *git.Client
	httpClient     *http.Client
	checksumHelper *ChecksumHelper
}

// NewPipelineUpdater creates a new pipeline updater
func NewPipelineUpdater(githubClient *github.Client, gitClient *git.Client, httpClient *http.Client) *PipelineUpdater {
	return &PipelineUpdater{
		githubClient:   githubClient,
		gitClient:      gitClient,
		httpClient:     httpClient,
		checksumHelper: NewChecksumHelperWithClient(httpClient),
	}
}

// UpdatePipelines updates all relevant pipelines in the configuration
func (pu *PipelineUpdater) UpdatePipelines(ctx context.Context, cfg *config.Configuration, updateContext *UpdateContext, updateResult *UpdateResult, securityScan bool) error {
	loader := melangeConfig.NewLoader()

	// Handle version-dependent pipeline updates (git-checkout, fetch)
	// These only update when the version actually changes
	if updateResult.HasUpdate {
		// Find and update git-checkout pipelines
		gitCheckoutIndices, err := loader.FindPipelinesByUse(updateContext.CurrentContent, "git-checkout")
		if err != nil {
			return fmt.Errorf("finding git-checkout pipelines: %w", err)
		}

		for _, index := range gitCheckoutIndices {
			updated, err := pu.updateGitCheckoutPipeline(ctx, updateContext.CurrentContent, index, cfg, updateResult)
			if err != nil {
				return fmt.Errorf("updating git-checkout[%d]: %w", index, err)
			}
			if !bytes.Equal(updated, updateContext.CurrentContent) {
				updateContext.CurrentContent = updated
				updateContext.AddGitCheckoutUpdate(index)
			}
		}

		// Find and update fetch pipelines
		fetchIndices, err := loader.FindPipelinesByUse(updateContext.CurrentContent, "fetch")
		if err != nil {
			return fmt.Errorf("finding fetch pipelines: %w", err)
		}

		for _, index := range fetchIndices {
			updated, err := pu.updateFetchPipeline(ctx, updateContext.CurrentContent, index, cfg, updateResult)
			if err != nil {
				return fmt.Errorf("updating fetch[%d]: %w", index, err)
			}
			if !bytes.Equal(updated, updateContext.CurrentContent) {
				updateContext.CurrentContent = updated
				updateContext.AddFetchUpdate(index)
			}
		}
	}

	// Find and update go/bump pipelines
	goBumpUpdater := NewGoBumpUpdater(pu.httpClient)
	err := goBumpUpdater.UpdateGoBumpPipelines(ctx, updateContext, cfg, updateResult, securityScan)
	if err != nil {
		return fmt.Errorf("updating go/bump pipelines: %w", err)
	}

	return nil
}

// updateGitCheckoutPipeline updates a git-checkout pipeline with new expected-commit
func (pu *PipelineUpdater) updateGitCheckoutPipeline(ctx context.Context, yamlContent []byte, pipelineIndex int, cfg *config.Configuration, updateResult *UpdateResult) ([]byte, error) {
	loader := melangeConfig.NewLoader()

	// Get current pipeline configuration
	withFields, err := loader.GetPipelineWithField(yamlContent, pipelineIndex)
	if err != nil {
		return nil, fmt.Errorf("getting pipeline with fields: %w", err)
	}

	// Check if this pipeline has expected-commit (if not, skip)
	currentCommit, hasExpectedCommit := withFields["expected-commit"]
	if !hasExpectedCommit {
		return yamlContent, nil // No expected-commit to update
	}

	// Get repository info from the pipeline or update config
	repoURL, tag, err := pu.extractGitInfo(withFields, cfg, updateResult)
	if err != nil {
		return nil, fmt.Errorf("extracting git info: %w", err)
	}

	// Get the commit SHA for the new version
	commitSHA, err := pu.getCommitForTag(ctx, repoURL, tag, updateResult)
	if err != nil {
		return nil, fmt.Errorf("getting commit for tag %s: %w", tag, err)
	}

	// Only update if commit actually changed
	if currentCommit == commitSHA {
		return yamlContent, nil // No change needed
	}

	// Update the expected-commit field
	updatedContent, err := loader.UpdatePipelineField(yamlContent, pipelineIndex, "expected-commit", commitSHA)
	if err != nil {
		return nil, fmt.Errorf("updating expected-commit: %w", err)
	}

	return updatedContent, nil
}

// updateFetchPipeline updates a fetch pipeline with new expected-sha256 if URL changed
func (pu *PipelineUpdater) updateFetchPipeline(ctx context.Context, yamlContent []byte, pipelineIndex int, cfg *config.Configuration, updateResult *UpdateResult) ([]byte, error) {
	loader := melangeConfig.NewLoader()

	// Get current pipeline configuration
	withFields, err := loader.GetPipelineWithField(yamlContent, pipelineIndex)
	if err != nil {
		return nil, fmt.Errorf("getting pipeline with fields: %w", err)
	}

	// Check if this pipeline has expected-sha256 and uri
	uri, hasURI := withFields["uri"]
	_, hasSHA := withFields["expected-sha256"]

	if !hasURI || !hasSHA {
		return yamlContent, nil // Nothing to update
	}

	// Check if the URI contains version variables that would change
	if !pu.uriContainsVersionVariable(uri) {
		return yamlContent, nil // URI doesn't depend on version
	}

	// Calculate new URI with updated version
	newURI := substituteVariables(uri, updateResult.LatestVersion)
	if newURI == uri {
		return yamlContent, nil // No change in URI
	}

	// Calculate new SHA256 for the new URI
	newSHA256, err := pu.checksumHelper.CalculateSHA256FromURL(ctx, newURI)
	if err != nil {
		return nil, fmt.Errorf("calculating SHA256 for %s: %w", newURI, err)
	}

	// Update both the URI and expected-sha256
	updatedContent := yamlContent

	// Update URI first
	updatedContent, err = loader.UpdatePipelineField(updatedContent, pipelineIndex, "uri", newURI)
	if err != nil {
		return nil, fmt.Errorf("updating uri: %w", err)
	}

	// Update expected-sha256
	updatedContent, err = loader.UpdatePipelineField(updatedContent, pipelineIndex, "expected-sha256", newSHA256)
	if err != nil {
		return nil, fmt.Errorf("updating expected-sha256: %w", err)
	}

	return updatedContent, nil
}

// extractGitInfo extracts repository and tag information for git operations
func (pu *PipelineUpdater) extractGitInfo(withFields map[string]string, cfg *config.Configuration, updateResult *UpdateResult) (repoURL, tag string, err error) {
	// Try to get repository from with fields
	if repo, ok := withFields["repository"]; ok {
		repoURL = repo
	}

	// Try to get tag from with fields and substitute version
	if tagTemplate, ok := withFields["tag"]; ok {
		// Substitute version in tag (e.g., "v${{package.version}}" -> "v1.2.3")
		tag = substituteVariables(tagTemplate, updateResult.LatestVersion)
	}

	// If no repository in pipeline, try to get from update config
	if repoURL == "" {
		if cfg.Update.GitHubMonitor != nil {
			// Convert GitHub identifier to repository URL
			repoURL = fmt.Sprintf("https://github.com/%s.git", cfg.Update.GitHubMonitor.Identifier)
		}
	}

	if repoURL == "" {
		return "", "", fmt.Errorf("no repository URL found")
	}

	if tag == "" {
		// Use the latest version as tag if no tag template
		tag = updateResult.LatestVersion
	}

	return repoURL, tag, nil
}

// getCommitForTag gets the commit SHA for a specific tag
func (pu *PipelineUpdater) getCommitForTag(ctx context.Context, repoURL, tag string, updateResult *UpdateResult) (string, error) {
	// If update source is GitHub, try GitHub API first
	if strings.Contains(updateResult.UpdateSource, "github") {
		repo, err := github.ParseRepository(strings.TrimSuffix(strings.TrimPrefix(repoURL, "https://github.com/"), ".git"))
		if err == nil {
			commitSHA, err := pu.githubClient.GetCommitForTag(ctx, repo.Owner, repo.Name, tag)
			if err == nil {
				return commitSHA, nil
			}
		}
	}

	// Fallback to go-git
	return pu.gitClient.GetCommitSHAForTag(ctx, repoURL, tag)
}

// uriContainsVersionVariable checks if a URI contains version variables
func (pu *PipelineUpdater) uriContainsVersionVariable(uri string) bool {
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
