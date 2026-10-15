package gobump

import (
	"time"

	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/processor"
	"github.com/isometry/choam/internal/scan"
	"github.com/isometry/choam/internal/simulate"
)

// BumpAction summarizes a change needed for one or more module roots, for
// reporting purposes (see Result.ActionsApplied).
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
	AssumedGoVersion string `json:"assumed_go_version" yaml:"assumed_go_version"`
	AssumedFromDate  string `json:"assumed_from_date" yaml:"assumed_from_date"`               // RFC3339 raw last-commit time (the assumed-version lookup subtracts a publication-age lag margin; see stdlibToolchainLagMargin)
	GoPackagePin     string `json:"go_package_pin,omitempty" yaml:"go_package_pin,omitempty"` // minor constraint the package was built under, "" = unpinned
	// RebuildGoPackagePin is the minor constraint the NEXT build will use,
	// set only when it differs from GoPackagePin (a same-run go-package pin
	// raise, see reconcileGoPackagePins).
	RebuildGoPackagePin string   `json:"rebuild_go_package_pin,omitempty" yaml:"rebuild_go_package_pin,omitempty"`
	RebuildGoVersion    string   `json:"rebuild_go_version" yaml:"rebuild_go_version"`
	VulnIDs             []string `json:"vuln_ids" yaml:"vuln_ids"`
	UnlinkedVulnIDs     []string `json:"unlinked_vuln_ids,omitempty" yaml:"unlinked_vuln_ids,omitempty"`
	Validated           bool     `json:"validated" yaml:"validated"` // linked-import filtering applied
}

// ApkAdvisory is one epoch-addressable Chainguard/Wolfi OSV advisory (CGA-)
// affecting the package's own APK name at its pristine version-epoch,
// classified by whether this build provably fixes every component its
// upstream records affect (see classifyApk).
type ApkAdvisory struct {
	ID           string   `json:"id" yaml:"id"`                               // the CGA- record ID
	Upstream     []string `json:"upstream" yaml:"upstream"`                   // CVE-/GHSA-/GO- IDs it covers
	FixedVersion string   `json:"fixed_version" yaml:"fixed_version"`         // "<version>-r<FixedEpoch>"
	FixedEpoch   int64    `json:"fixed_epoch" yaml:"fixed_epoch"`             // N > the pristine epoch
	Status       string   `json:"status" yaml:"status"`                       // proven, unproven, first-party, not-applicable
	Reason       string   `json:"reason,omitempty" yaml:"reason,omitempty"`   // why not proven
	Modules      []string `json:"modules,omitempty" yaml:"modules,omitempty"` // affected modules, from the upstream records
}

// NeededAction kinds, in the order the report lists them.
const (
	ActionPatch  = "patch"  // a first-party advisory needs a source patch
	ActionRerun  = "rerun"  // the result is incomplete; rerun once the cause is gone
	ActionReview = "review" // a human must decide (a fix exists but was not applied/proven)
	ActionAccept = "accept" // nothing to do until upstream releases a fix
)

// NeededAction is one thing the user must do about a package's result.
type NeededAction struct {
	Kind    string `json:"kind" yaml:"kind"` // patch, rerun, review, accept
	Subject string `json:"subject" yaml:"subject"`
	Detail  string `json:"detail,omitempty" yaml:"detail,omitempty"`
}

// EpochReason is one clause of why the epoch moved (the epoch comment's
// wording) with the advisory IDs behind it.
type EpochReason struct {
	Kind    string   `json:"kind" yaml:"kind"` // deps, hygiene, stdlib, apk, build
	Text    string   `json:"text" yaml:"text"`
	VulnIDs []string `json:"vuln_ids,omitempty" yaml:"vuln_ids,omitempty"`
}

// ApkAlignment summarizes the apk advisory alignment (see ApkAdvisoryStage):
// Version is the pristine "<version>-r<epoch>" queried; TargetEpoch the
// epoch aligned to (Result.ApkEpochTarget); HighestFixedEpoch the highest
// fix epoch among addressable advisories; BlockedAt the lowest non-proven
// fix epoch other than not-applicable ones (0 = none); the counts are per
// display ID and fix; Ignored counts
// the advisories no epoch can clear or that cannot be correlated, of which
// Uncorrelated those without an upstream CVE/GHSA/GO ID.
type ApkAlignment struct {
	Version           string `json:"version" yaml:"version"`
	TargetEpoch       int64  `json:"target_epoch" yaml:"target_epoch"`
	HighestFixedEpoch int64  `json:"highest_fixed_epoch" yaml:"highest_fixed_epoch"`
	BlockedAt         int64  `json:"blocked_at,omitempty" yaml:"blocked_at,omitempty"`
	Proven            int    `json:"proven" yaml:"proven"`
	Unproven          int    `json:"unproven" yaml:"unproven"`
	FirstParty        int    `json:"first_party" yaml:"first_party"`
	NotApplicable     int    `json:"not_applicable,omitempty" yaml:"not_applicable,omitempty"`
	Ignored           int    `json:"ignored" yaml:"ignored"`
	Uncorrelated      int    `json:"uncorrelated,omitempty" yaml:"uncorrelated,omitempty"`
}

// SecurityFix represents a security vulnerability fix applied
type SecurityFix struct {
	Module        string `json:"module" yaml:"module"`               // affected package
	Vulnerability string `json:"vulnerability" yaml:"vulnerability"` // CVE or vulnerability ID
	OldVersion    string `json:"old_version" yaml:"old_version"`     // version before fix
	NewVersion    string `json:"new_version" yaml:"new_version"`     // version after fix
	Severity      string `json:"severity" yaml:"severity"`           // critical, high, medium, low
}

// Result represents the result of a bump operation.
//
// Counting units: VulnerabilitiesFound and VulnerabilitiesFixed/Residual
// count advisories; ModulesBumped counts dependency entries changed. When
// Validated is true, Fixed/Residual are proven by simulating the bump against
// a real checkout; otherwise Fixed falls back to the historical
// modules-changed approximation.
type Result struct {
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
	SimulationError            string              `json:"simulation_error,omitempty" yaml:"simulation_error,omitempty"` // why simulation was unavailable (Validated=false)
	Residuals                  []simulate.Residual `json:"residuals,omitempty" yaml:"residuals,omitempty"`
	CriticalFixed              int                 `json:"critical_fixed" yaml:"critical_fixed"`
	HighFixed                  int                 `json:"high_fixed" yaml:"high_fixed"`
	SecurityFixes              []SecurityFix       `json:"security_fixes" yaml:"security_fixes"`
	// HygieneBumps are the scanner-hygiene entries written (see
	// simulate.HygieneModule): modules raised only so module-level scanners
	// stop flagging advisories whose vulnerable packages are not linked.
	// Never security fixes - their advisories stay unreachable, uncounted by
	// Fixed; HygieneModulesBumped counts them (ModulesBumped does not).
	HygieneBumps         []SecurityFix `json:"hygiene_bumps,omitempty" yaml:"hygiene_bumps,omitempty"`
	HygieneModulesBumped int           `json:"hygiene_modules_bumped,omitempty" yaml:"hygiene_modules_bumped,omitempty"`
	ActionsApplied       []BumpAction  `json:"actions_applied" yaml:"actions_applied"`
	// SkipReasons say why (part of) the package was not analyzed (status
	// SKIPPED; see Processor.SkipReasons).
	SkipReasons []string `json:"skip_reasons,omitempty" yaml:"skip_reasons,omitempty"`
	// ExcludedReason is the choam/bump-exclude-reason annotation value (status
	// EXCLUDED; see Processor.ExcludedReason).
	ExcludedReason string `json:"excluded_reason,omitempty" yaml:"excluded_reason,omitempty"`
	// Notes are degradations shown at default verbosity (see
	// Processor.Notes); they do not change the row's status.
	Notes []string `json:"notes,omitempty" yaml:"notes,omitempty"`
	// StdlibBumps are the Go stdlib staleness findings that (each) justify
	// an epoch bump; StdlibChecked reports whether the staleness check ran
	// to completion (false when disabled, inapplicable, or skipped).
	StdlibBumps   []StdlibBump `json:"stdlib_bumps,omitempty" yaml:"stdlib_bumps,omitempty"`
	StdlibChecked bool         `json:"stdlib_checked" yaml:"stdlib_checked"`
	// ApkAdvisories are the Chainguard/Wolfi advisories for this package's
	// own APK name and version (see ApkAdvisoryStage); ApkEpochTarget is the
	// lowest epoch clearing the proven ones (0 = no raise); FirstPartyVulnIDs
	// are those matching no dependency or stdlib advisory.
	ApkAdvisories     []ApkAdvisory `json:"apk_advisories,omitempty" yaml:"apk_advisories,omitempty"`
	ApkEpochTarget    int64         `json:"apk_epoch_target,omitempty" yaml:"apk_epoch_target,omitempty"`
	FirstPartyVulnIDs []string      `json:"first_party_vuln_ids,omitempty" yaml:"first_party_vuln_ids,omitempty"`
	ApkAlignment      *ApkAlignment `json:"apk_alignment,omitempty" yaml:"apk_alignment,omitempty"`

	// ActionsNeeded are what the user must do about this result;
	// EpochReasons why the epoch moved (set only when it did).
	ActionsNeeded []NeededAction `json:"actions_needed,omitempty" yaml:"actions_needed,omitempty"`
	EpochReasons  []EpochReason  `json:"epoch_reasons,omitempty" yaml:"epoch_reasons,omitempty"`

	OldEpoch       int64    `json:"old_epoch" yaml:"old_epoch"`
	NewEpoch       int64    `json:"new_epoch" yaml:"new_epoch"`
	EpochChanged   bool     `json:"epoch_changed" yaml:"epoch_changed"`
	FileWasWritten bool     `json:"file_was_written" yaml:"file_was_written"`
	Messages       []string `json:"messages" yaml:"messages"`
	// MessageSections parallels Messages (see Processor.TagMessages); a
	// message beyond its end is SectionOther.
	MessageSections []string `json:"-" yaml:"-"`
	Error           string   `json:"error,omitempty" yaml:"error,omitempty"`
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

	// BuildTags are this modroot's go/build steps' build tags (each step's
	// toolchaintags - default netgo,osusergo - plus its tags), unioned, for
	// the simulation's compile gate. Empty when no go/build step covers it.
	BuildTags []string `json:"build_tags,omitempty" yaml:"build_tags,omitempty"`

	// BuildArches are the GOARCHes the package is built for (from
	// package.target-architecture) and BuildEnv the build environment the
	// spec sets for this modroot (see analysisUnit). Go only.
	BuildArches []string          `json:"-" yaml:"-"`
	BuildEnv    simulate.BuildEnv `json:"-" yaml:"-"`

	// BumpEngine is the apply semantics the build's bump step will use for
	// this modroot once written (see analysisUnit.Engine); BumpMigrating
	// marks a go/bump step that migrates to `uses: bump` when rewritten;
	// BumpNoTidy mirrors that step's `tidy: false`; GoPackageMinor is the Go
	// minor the build pins ("" when unpinned). BaselineTidies records that
	// the simulation found the pristine module tidies under omnibump (only
	// probed for a migrating `tidy: false` step). Go only.
	BumpEngine     simulate.Engine `json:"-" yaml:"-"`
	BumpMigrating  bool            `json:"-" yaml:"-"`
	BumpNoTidy     bool            `json:"-" yaml:"-"`
	GoPackageMinor string          `json:"-" yaml:"-"`
	BaselineTidies bool            `json:"-" yaml:"-"`

	Deps *ecosystem.ModuleDeps `json:"-" yaml:"-"` // ecosystem-internal, not serialized
	// ScannedPackages are the packages (at their pristine versions) the
	// analysis scan queried OSV for: an advisory absent from ScanResult but
	// affecting one of them does not affect the version shipped.
	ScannedPackages []scan.Package   `json:"-" yaml:"-"`
	ScanResult      *scan.ScanResult `json:"scan_result" yaml:"scan_result"`
	ExistingDeps    []string         `json:"existing_deps" yaml:"existing_deps"` // deps currently declared for this root
	DesiredDeps     []string         `json:"desired_deps" yaml:"desired_deps"`   // deps this root should end up declaring

	// Replace directives ("old=new@version", Go only): what the root's bump
	// steps currently declare, and what they should end up declaring.
	// Analysis only carries existing replaces forward; the simulation may
	// raise or retire them (see SimulationStage and internal/simulate).
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
	// simulation adds to keep the module graph resolvable); this
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
	// HygieneModules are the DesiredDeps entries the simulation proposed only
	// for scanner hygiene (see simulate.HygieneModule).
	HygieneModules []simulate.HygieneModule `json:"hygiene_modules,omitempty" yaml:"hygiene_modules,omitempty"`
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
	BumpActions          []BumpAction       `json:"bump_actions" yaml:"bump_actions"`                   // each carries its own Language

	// Source coordinates from the package's git-checkout step, retained so
	// the simulation stage can clone the exact source the build will use.
	RepoURL        string `json:"repo_url,omitempty" yaml:"repo_url,omitempty"`
	Tag            string `json:"tag,omitempty" yaml:"tag,omitempty"`
	ExpectedCommit string `json:"expected_commit,omitempty" yaml:"expected_commit,omitempty"`
}

// Options configures processor behavior: the shared processor
// options (DryRun, BackupSuffix, TempDir; Force is unused by bump) plus the
// bump-specific ones below.
type Options struct {
	processor.ProcessorOptions

	// Validate enables bump simulation (default true): Go bump candidates
	// are applied to a clone of the upstream source with the real go
	// toolchain and OSV-rescanned to a fixpoint before being written (see
	// internal/simulate). Requires a go binary and network access; when
	// unavailable the run degrades to the unvalidated behavior and says so.
	Validate bool `json:"validate" yaml:"validate"`

	// SimulationTimeout bounds each package's bump simulation (default 10m).
	SimulationTimeout time.Duration `json:"simulation_timeout" yaml:"simulation_timeout"`

	// Compile enables the simulation's compile gate (default true at the
	// CLI; --no-compile disables it): the validated deps set must also
	// compile the go/build packages without new failures (see
	// simulate.Compiler). Moot when Validate is false.
	Compile bool `json:"compile" yaml:"compile"`

	// StdlibCheck enables the Go stdlib staleness check (see StdlibStage):
	// estimate the toolchain the package was last built with and bump the
	// epoch when a rebuild with the newest allowed Go release would fix
	// stdlib vulnerabilities. On by default at the CLI.
	StdlibCheck bool `json:"stdlib_check" yaml:"stdlib_check"`

	// ApkAdvisoryCheck enables the Chainguard/Wolfi APK-advisory epoch
	// alignment (see ApkAdvisoryStage). On by default at the CLI.
	ApkAdvisoryCheck bool `json:"apk_advisory_check" yaml:"apk_advisory_check"`
}
