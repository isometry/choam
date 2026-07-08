package gobump

import (
	"time"

	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
)

// BumpAction summarizes a change needed for one or more module roots, for
// reporting purposes (see GoBumpResult.ActionsApplied).
type BumpAction struct {
	Action       string   `json:"action" yaml:"action"`                         // "needs_bump"
	Language     string   `json:"language" yaml:"language"`                     // "go", "rust", "java"
	Modroots     []string `json:"modroots" yaml:"modroots"`                     // module roots this action applies to
	Dependencies []string `json:"dependencies" yaml:"dependencies"`             // newly required dependency entries, in this language's grammar
	Replaces     []string `json:"replaces,omitempty" yaml:"replaces,omitempty"` // new/changed replace directives ("old=new@version", Go only)
	Reason       string   `json:"reason" yaml:"reason"`                         // human-readable reason
}

// StdlibBump records why a stdlib-driven epoch bump is (or would be)
// applied: rebuilding with the newest allowed Go release would fix stdlib
// advisories present in the toolchain the package was (estimatedly) last
// built with. One entry per go-package pin constraint that yields fixable
// vulnerabilities (see evaluateStdlibStaleness).
type StdlibBump struct {
	AssumedGoVersion string   `json:"assumed_go_version" yaml:"assumed_go_version"`
	AssumedFromDate  string   `json:"assumed_from_date" yaml:"assumed_from_date"`               // RFC3339 last-commit time
	GoPackagePin     string   `json:"go_package_pin,omitempty" yaml:"go_package_pin,omitempty"` // minor constraint, "" = unpinned
	RebuildGoVersion string   `json:"rebuild_go_version" yaml:"rebuild_go_version"`
	VulnIDs          []string `json:"vuln_ids" yaml:"vuln_ids"`
	UnlinkedVulnIDs  []string `json:"unlinked_vuln_ids,omitempty" yaml:"unlinked_vuln_ids,omitempty"`
	Validated        bool     `json:"validated" yaml:"validated"` // linked-import filtering applied
}

// SecurityFix represents a security vulnerability fix applied
type SecurityFix struct {
	Module        string `json:"module" yaml:"module"`               // affected package
	Vulnerability string `json:"vulnerability" yaml:"vulnerability"` // CVE or vulnerability ID
	OldVersion    string `json:"old_version" yaml:"old_version"`     // version before fix
	NewVersion    string `json:"new_version" yaml:"new_version"`     // version after fix
	Severity      string `json:"severity" yaml:"severity"`           // critical, high, medium, low
}

// GoBumpResult represents the result of a bump operation.
//
// Counting units: VulnerabilitiesFound and VulnerabilitiesFixed/Residual
// count advisories; ModulesBumped counts dependency entries changed. When
// Validated is true, Fixed/Residual are proven by simulating the bump against
// a real checkout; otherwise Fixed falls back to the historical
// modules-changed approximation.
type GoBumpResult struct {
	PackageName             string `json:"package_name" yaml:"package_name"`
	FilePath                string `json:"file_path" yaml:"file_path"`
	VulnerabilitiesFound    int    `json:"vulnerabilities_found" yaml:"vulnerabilities_found"`
	VulnerabilitiesFixed    int    `json:"vulnerabilities_fixed" yaml:"vulnerabilities_fixed"`
	VulnerabilitiesResidual int    `json:"vulnerabilities_residual" yaml:"vulnerabilities_residual"`

	// VulnerabilitiesUnreachable counts advisories affecting only modules
	// that are not linked into any build artifact (module-level go list
	// -deps reachability) - informational: no bump proposed, neither fixed
	// nor residual.
	VulnerabilitiesUnreachable int                 `json:"vulnerabilities_unreachable" yaml:"vulnerabilities_unreachable"`
	UnreachableVulnIDs         []string            `json:"unreachable_vuln_ids,omitempty" yaml:"unreachable_vuln_ids,omitempty"`
	ModulesBumped              int                 `json:"modules_bumped" yaml:"modules_bumped"`
	Validated                  bool                `json:"validated" yaml:"validated"`
	Residuals                  []simulate.Residual `json:"residuals,omitempty" yaml:"residuals,omitempty"`
	CriticalFixed              int                 `json:"critical_fixed" yaml:"critical_fixed"`
	HighFixed                  int                 `json:"high_fixed" yaml:"high_fixed"`
	SecurityFixes              []SecurityFix       `json:"security_fixes" yaml:"security_fixes"`
	ActionsApplied             []BumpAction        `json:"actions_applied" yaml:"actions_applied"`
	// StdlibBumps are the Go stdlib staleness findings that (each) justify
	// an epoch bump; StdlibChecked reports whether the staleness check ran
	// to completion (false when disabled, inapplicable, or skipped).
	StdlibBumps   []StdlibBump `json:"stdlib_bumps,omitempty" yaml:"stdlib_bumps,omitempty"`
	StdlibChecked bool         `json:"stdlib_checked" yaml:"stdlib_checked"`

	OldEpoch       int64    `json:"old_epoch" yaml:"old_epoch"`
	NewEpoch       int64    `json:"new_epoch" yaml:"new_epoch"`
	EpochChanged   bool     `json:"epoch_changed" yaml:"epoch_changed"`
	FileWasWritten bool     `json:"file_was_written" yaml:"file_was_written"`
	Messages       []string `json:"messages" yaml:"messages"`
	Error          string   `json:"error,omitempty" yaml:"error,omitempty"`
}

// ModrootAnalysis contains the dependency analysis for a single module root.
// A package may declare one or more module roots (via bump/go-bump pipeline
// steps' with.modroot, or a go/build step's with.modroot), each with its own
// manifest and therefore its own applicable set of security bumps.
type ModrootAnalysis struct {
	Modroot string `json:"modroot" yaml:"modroot"`

	// BuildPackages are this modroot's go/build steps' with.packages
	// patterns (space-separated grammar, relative to Modroot), whose
	// non-test import graphs define artifact reachability. Empty when no
	// go/build step covers this modroot (bump-step- or annotation-declared
	// roots); the simulation then over-approximates with ./....
	BuildPackages []string `json:"build_packages,omitempty" yaml:"build_packages,omitempty"`

	Deps         *ecosystem.ModuleDeps `json:"-" yaml:"-"` // ecosystem-internal, not serialized
	ScanResult   *scan.ScanResult      `json:"scan_result" yaml:"scan_result"`
	ExistingDeps []string              `json:"existing_deps" yaml:"existing_deps"` // deps currently declared for this root
	DesiredDeps  []string              `json:"desired_deps" yaml:"desired_deps"`   // deps this root should end up declaring

	// Replace directives ("old=new@version", Go only): what the root's bump
	// steps currently declare, and what they should end up declaring.
	// Analysis only carries existing replaces forward; the simulation adds
	// promotions (see SimulationStage and internal/simulate).
	ExistingReplaces []string `json:"existing_replaces,omitempty" yaml:"existing_replaces,omitempty"`
	DesiredReplaces  []string `json:"desired_replaces,omitempty" yaml:"desired_replaces,omitempty"`

	// RequiredGoVersion is the Go language version demanded by the proven
	// candidate set (bare form, e.g. "1.25"); set only when it exceeds the
	// module's own baseline (go directive / toolchain directive max - see
	// pristineGoBaseline). Empty = no raise needed or unknown. Populated by
	// the simulation (proven) or, when simulation didn't run, by the
	// best-effort proxy fallback (direct candidates only). Go only.
	RequiredGoVersion string `json:"required_go_version,omitempty" yaml:"required_go_version,omitempty"`

	// ExistingGoVersion is the highest with.go-version carried by existing
	// bump/go-bump steps covering this modroot (bare form); empty when none.
	// Carried so reconciliation can never lower a previously written value.
	// Go only.
	ExistingGoVersion string `json:"existing_go_version,omitempty" yaml:"existing_go_version,omitempty"`

	// SecurityBumpModules lists the rendered-grammar coordinates (see
	// splitCoordVersion and Ecosystem.BumpCoords) of the dependencies OSV
	// actually flagged as vulnerable for this modroot - i.e.
	// scanResult.SecurityBumps, not DesiredDeps. The desired set may carry
	// additional entries with no CVE of their own (e.g. coherence pins the
	// simulation promotes to keep the module graph resolvable); this
	// narrower list lets the applier credit only genuine CVE fixes toward
	// SecurityFixes/epoch-bump accounting, so a coherence-only entry can't
	// masquerade as a vulnerability fix. The simulation overwrites it
	// with its own CVE-backed module set (rendered paths, same coordinate
	// space) when it runs.
	SecurityBumpModules []string `json:"security_bump_modules" yaml:"security_bump_modules"`

	// SecurityBumpsByCoord maps each of those rendered coordinates back to
	// its originating OSV bump, so reporting can attribute real advisory IDs
	// and prior versions to a fix (OSV's own package names don't always
	// match the rendered grammar - Maven uses "groupId:artifactId", and v2+
	// Go module paths lack the /vN suffix).
	SecurityBumpsByCoord map[string]scan.SecurityBump `json:"security_bumps_by_coord,omitempty" yaml:"security_bumps_by_coord,omitempty"`

	// Simulation outcome for this modroot (Go only; nil/false when the bump
	// simulation didn't run - see SimulationStage).
	Simulated           bool                        `json:"simulated" yaml:"simulated"`
	SimulationConverged bool                        `json:"simulation_converged" yaml:"simulation_converged"`
	Residuals           []simulate.Residual         `json:"residuals,omitempty" yaml:"residuals,omitempty"`
	Dropped             []simulate.DroppedCandidate `json:"dropped,omitempty" yaml:"dropped,omitempty"`
}

// LanguageAnalysis contains the results of scanning one language's
// dependencies across all of its module roots.
type LanguageAnalysis struct {
	Language  string            `json:"language" yaml:"language"`
	ByModroot []ModrootAnalysis `json:"by_modroot" yaml:"by_modroot"`
}

// VulnerabilityAnalysis contains the results of scanning a package's
// dependencies across every language and module root discovered for it. A
// package may have more than one language (e.g. a Go service alongside a
// Rust CLI in the same repo).
type VulnerabilityAnalysis struct {
	ByLanguage           []LanguageAnalysis `json:"by_language" yaml:"by_language"`
	VulnerabilitiesFound int                `json:"vulnerabilities_found" yaml:"vulnerabilities_found"` // aggregated across all languages
	CriticalCount        int                `json:"critical_count" yaml:"critical_count"`
	HighCount            int                `json:"high_count" yaml:"high_count"`
	SecurityBumps        []string           `json:"security_bumps" yaml:"security_bumps"`
	BumpActions          []BumpAction       `json:"bump_actions" yaml:"bump_actions"` // each carries its own Language

	// Source coordinates from the package's git-checkout step, retained so
	// the simulation stage can clone the exact source the build will use.
	RepoURL        string `json:"repo_url,omitempty" yaml:"repo_url,omitempty"`
	Tag            string `json:"tag,omitempty" yaml:"tag,omitempty"`
	ExpectedCommit string `json:"expected_commit,omitempty" yaml:"expected_commit,omitempty"`
}

// ProcessorOptions configures processor behavior
type ProcessorOptions struct {
	DryRun       bool   `json:"dry_run" yaml:"dry_run"`
	BackupSuffix string `json:"backup_suffix" yaml:"backup_suffix"`
	TempDir      string `json:"temp_dir" yaml:"temp_dir"`

	// Validate enables bump simulation (default true): Go bump candidates
	// are applied to a clone of the upstream source with the real go
	// toolchain and OSV-rescanned to a fixpoint before being written (see
	// internal/simulate). Requires a go binary and network access; when
	// unavailable the run degrades to the unvalidated behavior and says so.
	Validate bool `json:"validate" yaml:"validate"`

	// SimulationTimeout bounds each package's bump simulation (default 10m).
	SimulationTimeout time.Duration `json:"simulation_timeout" yaml:"simulation_timeout"`

	// StdlibCheck enables the Go stdlib staleness check (see StdlibStage):
	// estimate the toolchain the package was last built with and bump the
	// epoch when a rebuild with the newest allowed Go release would fix
	// stdlib vulnerabilities. On by default at the CLI.
	StdlibCheck bool `json:"stdlib_check" yaml:"stdlib_check"`
}
