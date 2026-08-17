package updater

import (
	"context"
	"fmt"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/logging"
)

// VersionFilter handles version filtering logic based on update configuration
type VersionFilter struct {
	comparator *VersionComparator
}

// NewVersionFilter creates a new version filter
func NewVersionFilter() *VersionFilter {
	return &VersionFilter{
		comparator: NewVersionComparator(),
	}
}

// isValidVersion checks if a version is valid semver and handles pre-release filtering
func (vf *VersionFilter) isValidVersion(version string, allowPreRelease bool) bool {
	return vf.comparator.IsValidVersion(version, allowPreRelease)
}

// ProcessVersion processes a single version through all the update
// configuration rules, logging intermediate decisions against the logger
// carried on ctx (see internal/logging) so they carry the caller's
// file/package/stage attribution.
func (vf *VersionFilter) ProcessVersion(ctx context.Context, version string, updateConfig *melange.Update) (string, bool, error) {
	if updateConfig == nil {
		return version, true, nil
	}

	processed := version

	// STAGE 1: NORMALIZATION - Prepare version for validation

	// 1a. Apply strip rules first (with glob support)
	beforeStrip := processed
	processed = vf.applyStripRules(processed, updateConfig)
	if processed != beforeStrip {
		logging.From(ctx).Debug("After stripping", "before", beforeStrip, "after", processed)
	}

	// 1b. Apply regex transformations
	if len(updateConfig.VersionTransform) > 0 {
		var err error
		beforeTransform := processed
		for _, transform := range updateConfig.VersionTransform {
			processed, err = vf.comparator.ApplyTransform(processed, transform.Match, transform.Replace)
			if err != nil {
				return "", false, fmt.Errorf("applying transform: %w", err)
			}
		}
		if processed != beforeTransform {
			logging.From(ctx).Debug("After transforms", "before", beforeTransform, "after", processed)
		}
	}

	// STAGE 2: VALIDATION - Filter out invalid versions

	// 2a. Check ignore patterns
	if len(updateConfig.IgnoreRegexPatterns) > 0 {
		ignored, err := vf.comparator.MatchesIgnorePattern(processed, updateConfig.IgnoreRegexPatterns)
		if err != nil {
			return "", false, fmt.Errorf("checking ignore patterns: %w", err)
		}
		if ignored {
			logging.From(ctx).Debug("Version ignored by pattern", "version", processed)
			return "", false, nil
		}
	}

	// 2b. Validate semver format and filter pre-releases
	if !vf.isValidVersion(processed, updateConfig.EnablePreReleaseTags) {
		logging.From(ctx).Debug("Version failed validity check", "version", processed)
		return "", false, nil // Invalid semver or unwanted pre-release
	}

	logging.From(ctx).Debug("Version accepted", "original", version, "processed", processed)
	return processed, true, nil
}

// applyStripRules applies prefix/suffix stripping based on the monitor configuration
func (vf *VersionFilter) applyStripRules(version string, updateConfig *melange.Update) string {
	processed := version

	// Apply rules based on which monitor is configured
	if updateConfig.ReleaseMonitor != nil {
		processed = stripVersionAffix(processed, updateConfig.ReleaseMonitor.StripPrefix, true)
		processed = stripVersionAffix(processed, updateConfig.ReleaseMonitor.StripSuffix, false)
	}

	if updateConfig.GitHubMonitor != nil {
		processed = stripVersionAffix(processed, updateConfig.GitHubMonitor.StripPrefix, true)
		processed = stripVersionAffix(processed, updateConfig.GitHubMonitor.StripSuffix, false)
	}

	if updateConfig.GitMonitor != nil {
		processed = stripVersionAffix(processed, updateConfig.GitMonitor.GetStripPrefix(), true)
		processed = stripVersionAffix(processed, updateConfig.GitMonitor.GetStripSuffix(), false)
	}

	return processed
}
