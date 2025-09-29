package gobump

import (
	"fmt"
	"maps"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// Parser handles parsing go.mod and go.sum files
type Parser struct{}

// NewParser creates a new parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseGoMod parses go.mod content and extracts module requirements and replacements
func (p *Parser) ParseGoMod(content []byte) (*GoModInfo, error) {
	modFile, err := modfile.Parse("go.mod", content, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	requirements := make(map[string]string)
	allRequirements := make(map[string]string)
	for _, req := range modFile.Require {
		requirements[req.Mod.Path] = req.Mod.Version
		allRequirements[req.Mod.Path] = req.Mod.Version
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
		Requirements:    requirements,
		AllRequirements: allRequirements,
		Replacements:    replacements,
	}, nil
}

// ParseGoSum parses go.sum content and extracts all module versions
// This is used to get indirect dependencies that aren't listed in go.mod (Go < 1.17)
func (p *Parser) ParseGoSum(content []byte) (map[string]string, error) {
	allDeps := make(map[string]string)
	lines := strings.SplitSeq(string(content), "\n")

	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// go.sum format: module version hash
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		module := parts[0]
		version := parts[1]

		// Skip /go.mod entries, we only want the actual module versions
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}

		// Keep the latest version for each module (go.sum may have multiple versions)
		if existing, ok := allDeps[module]; !ok || semver.Compare(version, existing) > 0 {
			allDeps[module] = version
		}
	}

	return allDeps, nil
}

// ParseGoModWithSum parses both go.mod and go.sum to get complete dependency information
func (p *Parser) ParseGoModWithSum(goModContent, goSumContent []byte) (*GoModInfo, error) {
	// First parse go.mod for direct dependencies and replacements
	goModInfo, err := p.ParseGoMod(goModContent)
	if err != nil {
		return nil, err
	}

	// Parse go.sum to get all dependencies (direct + indirect)
	if goSumContent != nil {
		allDeps, err := p.ParseGoSum(goSumContent)
		if err != nil {
			return nil, fmt.Errorf("parsing go.sum: %w", err)
		}

		// Update AllRequirements with complete dependency list
		maps.Copy(goModInfo.AllRequirements, allDeps)
	}

	return goModInfo, nil
}

// CreateVulnScanInput creates a vulnerability scanner input from GoModInfo
// This provides a unified list of dependencies for vulnerability scanning
func (p *Parser) CreateVulnScanInput(goModInfo *GoModInfo) string {
	var lines []string

	// Create a mock go.mod content with all dependencies for vulnerability scanning
	lines = append(lines, "module temp")
	lines = append(lines, "")
	lines = append(lines, "require (")

	for module, version := range goModInfo.AllRequirements {
		// Skip standard library modules
		if strings.HasPrefix(module, "std") {
			continue
		}
		lines = append(lines, fmt.Sprintf("\t%s %s", module, version))
	}

	lines = append(lines, ")")

	return strings.Join(lines, "\n")
}
