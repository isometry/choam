package updater

import (
	"fmt"
	"os"

	"chainguard.dev/melange/pkg/config"
)

// VersionFilter handles version filtering logic based on update configuration
type VersionFilter struct {
	comparator *VersionComparator
	verbose    bool
}

// NewVersionFilter creates a new version filter
func NewVersionFilter() *VersionFilter {
	return &VersionFilter{
		comparator: NewVersionComparator(),
		verbose:    false,
	}
}

// SetVerbose sets the verbose flag for debugging output
func (vf *VersionFilter) SetVerbose(verbose bool) {
	vf.verbose = verbose
	vf.comparator.SetVerbose(verbose)
}

// isValidVersion checks if a version is valid semver and handles pre-release filtering
func (vf *VersionFilter) isValidVersion(version string, allowPreRelease bool) bool {
	return vf.comparator.IsValidVersion(version, allowPreRelease)
}

// ProcessVersion processes a single version through all the update configuration rules
func (vf *VersionFilter) ProcessVersion(version string, updateConfig *config.Update) (string, bool, error) {
	if updateConfig == nil {
		return version, true, nil
	}

	if vf.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG] Processing version: %q\n", version)
	}

	processed := version

	// STAGE 1: NORMALIZATION - Prepare version for validation

	// 1a. Apply strip rules first (with glob support)
	beforeStrip := processed
	processed = vf.applyStripRules(processed, updateConfig)
	if vf.verbose && processed != beforeStrip {
		fmt.Fprintf(os.Stderr, "[DEBUG]   After stripping: %q -> %q\n", beforeStrip, processed)
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
		if vf.verbose && processed != beforeTransform {
			fmt.Fprintf(os.Stderr, "[DEBUG]   After transforms: %q -> %q\n", beforeTransform, processed)
		}
	}

	// STAGE 2: VALIDATION - Filter out invalid versions

	// 2a. Check ignore patterns
	if len(updateConfig.IgnoreRegexPatterns) > 0 {
		if vf.verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG]   Checking ignore patterns on %q: %v\n", processed, updateConfig.IgnoreRegexPatterns)
		}
		ignored, err := vf.comparator.MatchesIgnorePattern(processed, updateConfig.IgnoreRegexPatterns)
		if err != nil {
			return "", false, fmt.Errorf("checking ignore patterns: %w", err)
		}
		if ignored {
			if vf.verbose {
				fmt.Fprintf(os.Stderr, "[DEBUG]   Version %q IGNORED by pattern\n", processed)
			}
			return "", false, nil
		}
		if vf.verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG]   Version %q passed ignore patterns\n", processed)
		}
	}

	// 2b. Validate semver format and filter pre-releases
	if !vf.isValidVersion(processed, updateConfig.EnablePreReleaseTags) {
		if vf.verbose {
			fmt.Fprintf(os.Stderr, "[DEBUG]   Version %q failed validity check\n", processed)
		}
		return "", false, nil // Invalid semver or unwanted pre-release
	}

	if vf.verbose {
		fmt.Fprintf(os.Stderr, "[DEBUG]   Version %q ACCEPTED as %q\n", version, processed)
	}
	return processed, true, nil
}

// applyStripRules applies prefix/suffix stripping based on the monitor configuration
func (vf *VersionFilter) applyStripRules(version string, updateConfig *config.Update) string {
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
