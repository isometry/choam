package golang

import "golang.org/x/mod/modfile"

// GoModInfo contains parsed go.mod information including requirements and replacements
type GoModInfo struct {
	Requirements    map[string]string           // module -> version (direct dependencies)
	AllRequirements map[string]string           // module -> version (all dependencies including indirect)
	Replacements    map[string]*modfile.Replace // module -> replacement
	ModFile         *modfile.File               // the parsed go.mod, retained for the go directive (see needsGoSumMerge)
}

// bumpAnalysis represents the analysis result for a single candidate bump.
type bumpAnalysis struct {
	Module       string
	BumpVersion  string
	GoModVersion string
	Action       string // "keep", "remove-noop", "remove-downgrade", "remove-missing"
	Reason       string
}
