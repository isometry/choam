package updater

import (
	"context"
	"fmt"
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
	checksumHelper *ChecksumHelper
}

// NewPipelineUpdater creates a new pipeline updater
func NewPipelineUpdater(githubClient *github.Client, gitClient *git.Client) *PipelineUpdater {
	return &PipelineUpdater{
		githubClient:   githubClient,
		gitClient:      gitClient,
		checksumHelper: NewChecksumHelper(),
	}
}

// UpdatePipelines updates all relevant pipelines in the configuration
func (pu *PipelineUpdater) UpdatePipelines(ctx context.Context, cfg *config.Configuration, yamlContent []byte, updateResult *UpdateResult) (*PipelineUpdateResult, error) {
	loader := melangeConfig.NewLoader()
	result := &PipelineUpdateResult{
		Content:        yamlContent,
		UpdatesApplied: make([]string, 0),
		Errors:         make([]string, 0),
	}

	// Only update pipelines if version actually changed
	if !updateResult.HasUpdate {
		return result, nil
	}

	// Find and update git-checkout pipelines
	gitCheckoutIndices, err := loader.FindPipelinesByUse(yamlContent, "git-checkout")
	if err != nil {
		return result, fmt.Errorf("finding git-checkout pipelines: %w", err)
	}

	for _, index := range gitCheckoutIndices {
		updated, err := pu.updateGitCheckoutPipeline(ctx, result.Content, index, cfg, updateResult)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("git-checkout[%d]: %v", index, err))
			continue
		}
		if updated != nil {
			result.Content = updated
			result.UpdatesApplied = append(result.UpdatesApplied, fmt.Sprintf("pipeline[%d].with.expected-commit", index))
		}
	}

	// Find and update fetch pipelines
	fetchIndices, err := loader.FindPipelinesByUse(yamlContent, "fetch")
	if err != nil {
		return result, fmt.Errorf("finding fetch pipelines: %w", err)
	}

	for _, index := range fetchIndices {
		updated, err := pu.updateFetchPipeline(ctx, result.Content, index, cfg, updateResult)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("fetch[%d]: %v", index, err))
			continue
		}
		if updated != nil {
			result.Content = updated
			result.UpdatesApplied = append(result.UpdatesApplied, fmt.Sprintf("pipeline[%d].with.expected-sha256", index))
		}
	}

	// Find and update go/bump pipelines
	goBumpUpdater := NewGoBumpUpdater(pu.githubClient.GetHTTPClient())
	updatedContent, goBumpUpdates, err := goBumpUpdater.UpdateGoBumpPipelines(ctx, result.Content, cfg, updateResult)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("go/bump: %v", err))
	} else {
		result.Content = updatedContent
		result.UpdatesApplied = append(result.UpdatesApplied, goBumpUpdates...)
	}

	return result, nil
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
	if _, hasExpectedCommit := withFields["expected-commit"]; !hasExpectedCommit {
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
	newURI := pu.substituteVersionInURI(uri, cfg.Package.Version, updateResult.LatestVersion)
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
		tag = pu.substituteVersionInTemplate(tagTemplate, updateResult.LatestVersion)
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

// substituteVersionInURI substitutes version variables in a URI
func (pu *PipelineUpdater) substituteVersionInURI(uri, oldVersion, newVersion string) string {
	versionSubstitutions := map[string]string{
		"${{package.version}}":      newVersion,
		"${package.version}":        newVersion,
		"${{package.full-version}}": newVersion,
		"${package.full-version}":   newVersion,
	}

	result := uri
	for variable, value := range versionSubstitutions {
		result = strings.ReplaceAll(result, variable, value)
	}

	return result
}

// substituteVersionInTemplate substitutes version in a template string
func (pu *PipelineUpdater) substituteVersionInTemplate(template, version string) string {
	substitutions := map[string]string{
		"${{package.version}}":      version,
		"${package.version}":        version,
		"${{package.full-version}}": version,
		"${package.full-version}":   version,
	}

	result := template
	for variable, value := range substitutions {
		result = strings.ReplaceAll(result, variable, value)
	}

	return result
}
