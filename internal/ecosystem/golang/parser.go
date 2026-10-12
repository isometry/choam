package golang

import (
	"fmt"
	"maps"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// parser handles parsing go.mod and go.sum files
type parser struct{}

// newParser creates a new parser
func newParser() *parser {
	return &parser{}
}

// parseGoMod parses go.mod content and extracts module requirements and replacements
func (p *parser) parseGoMod(content []byte) (*GoModInfo, error) {
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
		ModFile:         modFile,
	}, nil
}

// goSumMergeCutoff: from go 1.17, module graph pruning guarantees every
// module providing a transitively imported package (including test imports)
// is listed in go.mod's require block, so a go.sum-only module can never be
// linked into a build artifact - merging go.sum would only invent phantom
// scan targets whose "vulnerabilities" cannot affect anything that ships.
const goSumMergeCutoff = "v1.17"

// needsGoSumMerge reports whether AllRequirements must be widened with
// go.sum entries: only when the go directive is absent, unparsable, or
// predates the 1.17 pruning invariant (pre-1.17 go.mod lists direct
// requirements only, so go.sum is the sole source of indirect deps).
func needsGoSumMerge(modFile *modfile.File) bool {
	if modFile == nil || modFile.Go == nil || modFile.Go.Version == "" {
		return true
	}
	v := "v" + modFile.Go.Version // "1.17" and "1.21.0" are both valid with the prefix
	if !semver.IsValid(v) {
		return true // unparsable directive: fail wide (merge)
	}
	return semver.Compare(v, goSumMergeCutoff) < 0
}

// parseGoSum parses go.sum content and extracts all module versions. Only
// consulted for pre-1.17 modules (see needsGoSumMerge), whose go.mod doesn't
// list indirect dependencies.
func (p *parser) parseGoSum(content []byte) (map[string]string, error) {
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

// parseGoModWithSum parses both go.mod and go.sum to get complete dependency
// information. go.sum is merged into AllRequirements only for pre-1.17
// modules (see needsGoSumMerge) - for newer modules go.mod's require block
// already covers everything that can possibly be linked.
func (p *parser) parseGoModWithSum(goModContent, goSumContent []byte) (*GoModInfo, error) {
	// First parse go.mod for direct dependencies and replacements
	goModInfo, err := p.parseGoMod(goModContent)
	if err != nil {
		return nil, err
	}

	if goSumContent != nil && needsGoSumMerge(goModInfo.ModFile) {
		allDeps, err := p.parseGoSum(goSumContent)
		if err != nil {
			return nil, fmt.Errorf("parsing go.sum: %w", err)
		}

		// Update AllRequirements with complete dependency list
		maps.Copy(goModInfo.AllRequirements, allDeps)
	}

	return goModInfo, nil
}

// ParseReplace parses a bump step's replaces entry, "old=new@version" (the
// version split on the LAST "@", so old may carry its own "@version"); ok is
// false for an entry without "@" or without "=".
func ParseReplace(entry string) (oldPath, newPath, version string, ok bool) {
	idx := strings.LastIndex(entry, "@")
	if idx < 0 {
		return "", "", "", false
	}
	oldPath, newPath, ok = strings.Cut(entry[:idx], "=")
	if !ok {
		return "", "", "", false
	}
	return oldPath, newPath, entry[idx+1:], true
}

// TrimMajorSuffix strips a trailing /vN major-version path element
// (e.g. github.com/foo/bar/v2 -> github.com/foo/bar).
func TrimMajorSuffix(module string) string {
	idx := strings.LastIndex(module, "/")
	if idx < 0 {
		return module
	}
	last := module[idx+1:]
	if len(last) < 2 || last[0] != 'v' {
		return module
	}
	if _, err := strconv.Atoi(last[1:]); err != nil {
		return module
	}
	return module[:idx]
}
