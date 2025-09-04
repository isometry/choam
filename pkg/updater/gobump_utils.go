package updater

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/isometry/choam/pkg/scan"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// GoBumpUpdater handles Go dependency analysis utilities
type GoBumpUpdater struct {
	httpClient           *http.Client
	vulnerabilityScanner *scan.VulnerabilityScanner
}

// NewGoBumpUpdater creates a new go/bump utility helper
func NewGoBumpUpdater(httpClient *http.Client) *GoBumpUpdater {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &GoBumpUpdater{
		httpClient:           httpClient,
		vulnerabilityScanner: scan.NewVulnerabilityScanner(httpClient),
	}
}

// NewGoBumpUpdaterWithCache creates a new go/bump utility helper with vulnerability cache
func NewGoBumpUpdaterWithCache(httpClient *http.Client, cache *scan.VulnerabilityCache) *GoBumpUpdater {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &GoBumpUpdater{
		httpClient:           httpClient,
		vulnerabilityScanner: scan.NewVulnerabilityScannerWithCache(httpClient, cache),
	}
}

// BumpAnalysis represents the analysis result for a single bump
type BumpAnalysis struct {
	Module       string
	BumpVersion  string
	GoModVersion string
	Action       string // "keep", "remove-noop", "remove-downgrade", "remove-missing"
	Reason       string
}

// fetchGoMod fetches go.mod content from a git repository
func (gbu *GoBumpUpdater) fetchGoMod(ctx context.Context, repoURL, tag, goModPath string) ([]byte, error) {
	// Convert GitHub repository URL to raw content URL
	rawURL, err := gbu.buildRawURL(repoURL, tag, goModPath)
	if err != nil {
		return nil, fmt.Errorf("building raw URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := gbu.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching go.mod from %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d fetching %s", resp.StatusCode, rawURL)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return content, nil
}

// buildRawURL converts a GitHub repository URL to a raw content URL
func (gbu *GoBumpUpdater) buildRawURL(repoURL, tag, filepath string) (string, error) {
	// Handle GitHub URLs - convert to raw.githubusercontent.com format
	if strings.Contains(repoURL, "github.com") {
		githubURLPattern := regexp.MustCompile(`https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)
		matches := githubURLPattern.FindStringSubmatch(repoURL)
		if len(matches) == 3 {
			owner := matches[1]
			repo := matches[2]
			return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, tag, filepath), nil
		}
	}

	return "", fmt.Errorf("unsupported repository URL format: %s", repoURL)
}

// GoModInfo contains parsed go.mod information including requirements and replacements  
type GoModInfo struct {
	Requirements map[string]string            // module -> version
	Replacements map[string]*modfile.Replace  // module -> replacement
}

// parseGoMod parses go.mod content and extracts module requirements and replacements
func (gbu *GoBumpUpdater) parseGoMod(content []byte) (*GoModInfo, error) {
	modFile, err := modfile.Parse("go.mod", content, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	requirements := make(map[string]string)
	for _, req := range modFile.Require {
		requirements[req.Mod.Path] = req.Mod.Version
	}

	replacements := make(map[string]*modfile.Replace)
	for _, replace := range modFile.Replace {
		key := replace.Old.Path
		if replace.Old.Version != "" {
			key = replace.Old.Path + "@" + replace.Old.Version
		}
		replacements[key] = replace
	}

	return &GoModInfo{
		Requirements: requirements,
		Replacements: replacements,
	}, nil
}

// analyzeBumps analyzes each bump and determines whether to keep or remove it
func (gbu *GoBumpUpdater) analyzeBumps(deps []string, goModInfo *GoModInfo) ([]BumpAnalysis, []string) {
	var analysis []BumpAnalysis
	
	// First, deduplicate and keep only the latest version per module
	latestVersions := make(map[string]string)
	
	for _, dep := range deps {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}

		// Parse module@version
		parts := strings.Split(dep, "@")
		if len(parts) != 2 {
			// Malformed dep, keep it as is (but still dedupe)
			if _, exists := latestVersions[dep]; !exists {
				latestVersions[dep] = ""
			}
			continue
		}

		module := parts[0]
		bumpVersion := parts[1]
		
		// Keep only the latest version for each module
		if existing, exists := latestVersions[module]; exists {
			if existing == "" {
				// Previous was malformed, this one is valid
				latestVersions[module] = bumpVersion
			} else if semver.Compare(bumpVersion, existing) > 0 {
				// This version is newer
				latestVersions[module] = bumpVersion
			}
			// Otherwise keep existing
		} else {
			latestVersions[module] = bumpVersion
		}
	}

	// Now analyze the deduplicated dependencies
	var filteredDeps []string
	
	for module, bumpVersion := range latestVersions {
		if bumpVersion == "" {
			// Malformed dep, keep it as is
			filteredDeps = append(filteredDeps, module)
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  "",
				GoModVersion: "",
				Action:       "keep",
				Reason:       "malformed dependency, keeping as-is",
			})
			continue
		}

		// Check if this module exists in go.mod requirements
		goModVersion, exists := goModInfo.Requirements[module]
		if !exists {
			// Module not found in go.mod - remove it
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: "(missing)",
				Action:       "remove-missing",
				Reason:       "module not found in go.mod",
			})
			continue
		}

		// Check for replace directives that affect this module
		effectiveVersion := gbu.getEffectiveVersion(module, goModVersion, goModInfo.Replacements)
		
		// Compare versions using semantic versioning
		comparison := semver.Compare(bumpVersion, effectiveVersion)

		if comparison > 0 {
			// Bump version is ahead of go.mod version - keep it
			dep := fmt.Sprintf("%s@%s", module, bumpVersion)
			filteredDeps = append(filteredDeps, dep)
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "keep",
				Reason:       "bump version is newer than effective version",
			})
		} else if comparison == 0 {
			// Versions are equal - remove as no-op
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "remove-noop",
				Reason:       "bump version matches effective version",
			})
		} else {
			// Bump version is behind go.mod version - remove as downgrade
			analysis = append(analysis, BumpAnalysis{
				Module:       module,
				BumpVersion:  bumpVersion,
				GoModVersion: effectiveVersion,
				Action:       "remove-downgrade",
				Reason:       "bump version is older than effective version",
			})
		}
	}

	// Sort the filtered deps lexicographically for stability
	slices.Sort(filteredDeps)

	return analysis, filteredDeps
}

// getEffectiveVersion returns the effective version considering replace directives
func (gbu *GoBumpUpdater) getEffectiveVersion(module, originalVersion string, replacements map[string]*modfile.Replace) string {
	// Check for exact version replacement first (module@version)
	exactKey := module + "@" + originalVersion
	if replace, ok := replacements[exactKey]; ok {
		if gbu.isLocalPath(replace.New.Path) {
			// Local replacement - treat as effectively very new version
			return "v999.999.999" // This ensures bumps are considered downgrades
		}
		if replace.New.Version != "" {
			return replace.New.Version
		}
	}
	
	// Check for module-level replacement (all versions)
	if replace, ok := replacements[module]; ok {
		if gbu.isLocalPath(replace.New.Path) {
			// Local replacement - treat as effectively very new version
			return "v999.999.999" // This ensures bumps are considered downgrades
		}
		if replace.New.Version != "" {
			return replace.New.Version
		}
	}
	
	// No replacement, use original version
	return originalVersion
}

// isLocalPath determines if a path is a local filesystem path
func (gbu *GoBumpUpdater) isLocalPath(path string) bool {
	return path == "" ||
		strings.HasPrefix(path, ".") ||
		strings.HasPrefix(path, "/") ||
		strings.Contains(path, "\\") // Windows paths
}

// haveDepsChanged compares two dependency lists to determine if they're different
func (gbu *GoBumpUpdater) haveDepsChanged(existing, merged []string) bool {
	// Normalize both slices for comparison
	normalizeDepList := func(deps []string) []string {
		var normalized []string
		for _, dep := range deps {
			dep = strings.TrimSpace(dep)
			if dep != "" {
				normalized = append(normalized, dep)
			}
		}
		slices.Sort(normalized)
		return normalized
	}

	normalizedExisting := normalizeDepList(existing)
	normalizedMerged := normalizeDepList(merged)

	return !slices.Equal(normalizedExisting, normalizedMerged)
}