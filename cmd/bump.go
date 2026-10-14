package cmd

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aquasecurity/table"
	"github.com/isometry/choam/internal/gobump"
	"github.com/isometry/choam/internal/httpclient"
	"github.com/isometry/choam/internal/output"
	"github.com/isometry/choam/internal/processor"
	"github.com/spf13/cobra"
)

func NewBumpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "bump [path...]",
		Aliases: []string{"gobump"},
		Short:   "Fix module vulnerabilities using bump pipelines",
		Long: `Fix module vulnerabilities by adding or updating bump pipeline steps.
This command checks for vulnerabilities in the current version of a package's
dependencies and applies security fixes by updating bump pipelines. The
package epoch will be incremented when vulnerabilities are fixed.

Path can be a single file or a directory containing .yaml files.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runBump,
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be changed without making changes")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, yaml")
	cmd.Flags().StringVar(&backupSuffix, "backup-suffix", "", "Suffix for backup files (empty = no backup)")
	cmd.Flags().BoolVar(&noValidate, "no-validate", false, "Skip bump simulation (writes deps lists without proving they resolve or cover all advisories, and skips artifact-reachability filtering; go.sum narrowing still applies); requires a go toolchain otherwise")
	cmd.Flags().DurationVar(&simulationTimeout, "simulation-timeout", 10*time.Minute, "Per-package budget for bump simulation")
	cmd.Flags().BoolVar(&noCompile, "no-compile", false, "Skip the simulation's compile gate (validated deps are then only proven to resolve, not to compile the go/build packages); implied by --no-validate")
	cmd.Flags().BoolVar(&failOnResidual, "fail-on-residual", false, "Exit non-zero when any advisory remains residual or a first-party apk advisory needs a patch (files that error always exit non-zero)")
	cmd.Flags().BoolVar(&noStdlib, "no-stdlib", false, "Skip the Go stdlib staleness check (no epoch bump for toolchain-fixed vulnerabilities). The check is also skipped automatically for files with uncommitted changes.")
	cmd.Flags().BoolVar(&noApkAdvisories, "no-apk-advisories", false, "Skip the Chainguard/Wolfi apk advisory check (no epoch alignment with published apk advisories, no first-party patch alerts)")

	return cmd
}

// ErrBumpFailed is returned, after every result has been printed, when any
// file errored - or, with --fail-on-residual, when any advisory remains
// residual - so the command exits non-zero (cobra prints it once).
var ErrBumpFailed = errors.New("bump failed")

func runBump(cmd *cobra.Command, args []string) error {
	// Use the command context which supports cancellation (Ctrl+C)
	ctx := cmd.Context()

	// Initialize logging based on verbosity flag
	InitLogger(verbosity)

	// Collect all melange files from the provided paths
	files, err := collectMelangeFiles(args)
	if err != nil {
		return fmt.Errorf("collecting melange files: %w", err)
	}

	if len(files) == 0 {
		if outputFormat == "json" || outputFormat == "yaml" {
			return outputBumpStructured(nil, outputFormat) // keep structured stdout parseable
		}
		fmt.Println("No melange files found.")
		return nil
	}

	slog.Info("found melange files to check for vulnerabilities", "count", len(files)) //nolint:forbidigo // pre-per-file: no processor/ctx attribution exists yet

	// Configure processor options
	opts := buildBumpProcessorOptions()

	// Create shared HTTP client with custom timeout
	httpClient := httpclient.NewHTTPClientWithTimeout(httpTimeout)
	analyzer := gobump.NewAnalyzer(httpClient)

	results := make([]*gobump.Result, 0, len(files))
	for i, file := range files {
		if ctx.Err() != nil {
			break
		}

		slog.Info("processing melange file", "file", file, "index", i+1, "total", len(files)) //nolint:forbidigo // this IS the file attribution - the per-file ctx is seeded inside ProcessFile

		result, err := gobump.ProcessFile(ctx, file, opts, analyzer)
		if err != nil {
			// Already logged where it happened (ProcessFile's read/parse
			// errors, the pipeline's "Stage failed"); recorded in result.Error.
			if result == nil {
				// Read/parse failure: no processor, so no partial state.
				result = &gobump.Result{
					PackageName: strings.TrimSuffix(filepath.Base(file), filepath.Ext(file)),
					FilePath:    file,
				}
			}
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	// Partial results are printed even on cancellation.
	if err := outputBumpResults(results, outputFormat); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("bump cancelled after %d of %d file(s): %w", len(results), len(files), err)
	}
	return bumpExitError(summarizeBumpResults(results))
}

// bumpExitError maps the run summary to the command's exit status.
func bumpExitError(summary output.BumpSummary) error {
	switch {
	case summary.Errors > 0:
		return fmt.Errorf("%w: %d of %d file(s) errored", ErrBumpFailed, summary.Errors, summary.TotalPackages)
	case failOnResidual && summary.TotalVulnsResidual > 0:
		return fmt.Errorf("%w: %d residual advisory(ies) in %d file(s) (--fail-on-residual)", ErrBumpFailed, summary.TotalVulnsResidual, summary.PackagesPartial)
	case failOnResidual && summary.TotalFirstPartyVulns > 0:
		return fmt.Errorf("%w: %d first-party apk advisory(ies) need a patch in %d file(s) (--fail-on-residual)", ErrBumpFailed, summary.TotalFirstPartyVulns, summary.PackagesPatchNeeded)
	}
	return nil
}

// buildBumpProcessorOptions maps the bump command's flag-backed package
// variables onto gobump.Options. Factored out of runBump so the
// flag-to-option wiring (e.g. --no-stdlib -> StdlibCheck) is directly
// testable without driving the full command.
func buildBumpProcessorOptions() gobump.Options {
	return gobump.Options{
		ProcessorOptions: processor.ProcessorOptions{
			DryRun:       dryRun,
			BackupSuffix: backupSuffix,
			TempDir:      os.TempDir(),
		},
		Validate:          !noValidate,
		SimulationTimeout: simulationTimeout,
		Compile:           !noValidate && !noCompile,
		StdlibCheck:       !noStdlib,
		ApkAdvisoryCheck:  !noApkAdvisories,
	}
}

func outputBumpResults(results []*gobump.Result, format string) error {
	switch format {
	case "json":
		return outputBumpStructured(results, "json")
	case "yaml":
		return outputBumpStructured(results, "yaml")
	case "table":
		return outputBumpTable(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// summarizeBumpResults is the one aggregation behind both the table footer
// and the structured summary. An errored file counts only in Errors (its
// partial counts are incomplete); a file counts as fixed when it fixes at
// least one advisory (VulnerabilitiesFixed > 0 - see bumpRowStatus).
func summarizeBumpResults(results []*gobump.Result) output.BumpSummary {
	summary := output.BumpSummary{TotalPackages: len(results)}
	for _, r := range results {
		if distinct := output.DistinctStdlibVulnIDs(r.StdlibBumps); len(distinct) > 0 {
			summary.PackagesStdlibStale++
			summary.TotalStdlibVulns += len(distinct)
		}
		if r.Error != "" || len(r.ActionsNeeded) > 0 {
			summary.PackagesActionNeeded++
		}
		if r.Error != "" {
			summary.Errors++
			continue
		}
		if r.EpochChanged || r.FileWasWritten {
			summary.PackagesChanged++
		}
		if len(r.SkipReasons) > 0 {
			summary.PackagesSkipped++
		}
		if n := len(r.FirstPartyVulnIDs); n > 0 {
			summary.PackagesPatchNeeded++
			summary.TotalFirstPartyVulns += n
		}
		summary.TotalModulesBumped += r.ModulesBumped
		summary.TotalHygieneModulesBumped += r.HygieneModulesBumped
		if r.VulnerabilitiesFound == 0 {
			continue
		}
		summary.PackagesWithVulns++
		summary.TotalVulnsFound += r.VulnerabilitiesFound
		summary.TotalVulnsFixed += r.VulnerabilitiesFixed
		summary.TotalVulnsResidual += r.VulnerabilitiesResidual
		summary.TotalVulnsUnreachable += r.VulnerabilitiesUnreachable
		if !r.Validated {
			summary.PackagesUnvalidated++
		}
		if r.VulnerabilitiesFixed > 0 {
			summary.PackagesFixed++
		}
		if r.VulnerabilitiesResidual > 0 {
			summary.PackagesPartial++
		}
	}
	return summary
}

// outputBumpStructured renders the results keyed by file path (as given on
// the command line / discovered - unique, unlike basenames) plus the summary.
func outputBumpStructured(results []*gobump.Result, format string) error {
	resultsMap := make(map[string]*gobump.Result, len(results))
	for _, result := range results {
		resultsMap[result.FilePath] = result
	}
	response := output.BumpResponse{
		Results: resultsMap,
		Summary: summarizeBumpResults(results),
	}
	if format == "json" {
		return output.OutputJSON(os.Stdout, response)
	}
	return output.OutputYAML(os.Stdout, response)
}

// outputBumpTable renders the default report: the results table, why each
// changed file's epoch moved, the actions needed, one info line plus notes,
// the -v messages and a short footer. Every error, skip, residual and
// unvalidated write surfaces as an action - a package that was not (fully)
// analyzed or still carries advisories never silently reads as clean.
func outputBumpTable(results []*gobump.Result) error {
	renderBumpTable(results)
	renderWhy(results)
	renderActions(results)
	renderInfo(results)

	if verbosity > 0 {
		for _, result := range results {
			renderDetails(result)
		}
	}

	s := summarizeBumpResults(results)
	fmt.Printf("\nSummary: %d %s, %d changed, %d errors, %d skipped, %d %s\n",
		s.TotalPackages, pluralWord(s.TotalPackages, "file", "files"), s.PackagesChanged, s.Errors, s.PackagesSkipped,
		s.PackagesActionNeeded, pluralWord(s.PackagesActionNeeded, "needs action", "need action"))
	if dryRun {
		fmt.Println("(Dry run - no files were actually modified)")
	}
	return nil
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// detailSections is the -v details' section order (gobump.SectionHidden
// messages are not shown).
var detailSections = []string{gobump.SectionChanges, gobump.SectionAdvisories, gobump.SectionApk, gobump.SectionStdlib, gobump.SectionOther}

// renderDetails prints a file's -v narrative, grouped by section: Changes
// leads with the structured fixes and hygiene bumps, apk is rendered from
// the structured alignment; each section then lists its tagged messages.
func renderDetails(result *gobump.Result) {
	lines := make(map[string][]string)
	for _, fix := range result.SecurityFixes {
		lines[gobump.SectionChanges] = append(lines[gobump.SectionChanges], fixLine(fix))
	}
	for _, fix := range result.HygieneBumps {
		lines[gobump.SectionChanges] = append(lines[gobump.SectionChanges], "hygiene: "+fixLine(fix))
	}
	lines[gobump.SectionApk] = apkDetailLines(result)
	for i, message := range result.Messages {
		section := gobump.SectionOther
		if i < len(result.MessageSections) {
			section = result.MessageSections[i]
		}
		lines[section] = append(lines[section], message)
	}
	var out strings.Builder
	for _, section := range detailSections {
		if len(lines[section]) == 0 {
			continue
		}
		fmt.Fprintf(&out, "  %s:\n", section)
		for _, line := range lines[section] {
			fmt.Fprintf(&out, "    - %s\n", line)
		}
	}
	if out.Len() > 0 {
		fmt.Printf("\nDetails for %s:\n%s", result.PackageName, out.String())
	}
}

// fixLine renders a dependency change as "module old -> new [IDs]", CVE IDs
// first.
func fixLine(fix gobump.SecurityFix) string {
	var ids []string
	for id := range strings.SplitSeq(fix.Vulnerability, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b string) int {
		return cmp.Or(cmp.Compare(cveRank(a), cveRank(b)), strings.Compare(a, b))
	})
	line := fmt.Sprintf("%s %s -> %s", fix.Module, fix.OldVersion, fix.NewVersion)
	if len(ids) > 0 {
		line += " [" + strings.Join(ids, ", ") + "]"
	}
	return line
}

func cveRank(id string) int {
	if strings.HasPrefix(id, "CVE-") {
		return 0
	}
	return 1
}

// apkDetailMaxIDs caps the proven-advisory list.
const apkDetailMaxIDs = 5

// apkDetailLines renders the apk alignment: one counts line, the proven
// advisories, then by fix epoch one line per cause of the unproven ones and
// one per first-party advisory (one entry per display ID and fix, as the
// counts are).
func apkDetailLines(result *gobump.Result) []string {
	apk := result.ApkAlignment
	if apk == nil {
		return nil
	}
	if apk.HighestFixedEpoch == 0 && apk.Ignored == 0 {
		return []string{apk.Version + ": no apk advisories"}
	}
	ignored := fmt.Sprintf("%d ignored", apk.Ignored)
	if apk.Uncorrelated > 0 {
		ignored += fmt.Sprintf(" (%d without an upstream ID)", apk.Uncorrelated)
	}
	counts := fmt.Sprintf("%s: %d proven, %d unproven, %d first-party, %s", apk.Version, apk.Proven, apk.Unproven, apk.FirstParty, ignored)
	if apk.HighestFixedEpoch > 0 {
		counts += fmt.Sprintf("; reached -r%d of highest -r%d", result.NewEpoch, apk.HighestFixedEpoch)
	}
	lines := []string{counts}
	var proven []string
	var open []gobump.ApkAdvisory
	seen := make(map[string]bool)
	for _, adv := range result.ApkAdvisories {
		id := adv.DisplayID()
		key := id + "|" + adv.FixedVersion
		if seen[key] {
			continue
		}
		seen[key] = true
		if adv.Status == "proven" { // gobump's apkProven
			if !slices.Contains(proven, id) {
				proven = append(proven, id)
			}
			continue
		}
		open = append(open, adv)
	}
	if len(proven) > 0 {
		slices.SortFunc(proven, func(a, b string) int {
			return cmp.Or(cmp.Compare(cveRank(a), cveRank(b)), strings.Compare(a, b))
		})
		list := strings.Join(proven[:min(len(proven), apkDetailMaxIDs)], ", ")
		if len(proven) > apkDetailMaxIDs {
			list += fmt.Sprintf(" (+%d)", len(proven)-apkDetailMaxIDs)
		}
		lines = append(lines, "proven: "+list)
	}
	slices.SortFunc(open, func(a, b gobump.ApkAdvisory) int {
		return cmp.Or(cmp.Compare(a.FixedEpoch, b.FixedEpoch), cmp.Compare(cveRank(a.DisplayID()), cveRank(b.DisplayID())), strings.Compare(a.DisplayID(), b.DisplayID()))
	})
	// Unproven advisories group by (fix epoch, cause) - open is sorted, so a
	// group is a run of equal keys once sorted by cause too; first-party ones
	// stay one line each.
	slices.SortStableFunc(open, func(a, b gobump.ApkAdvisory) int {
		return cmp.Or(cmp.Compare(a.FixedEpoch, b.FixedEpoch), strings.Compare(a.Status, b.Status), strings.Compare(a.Reason, b.Reason))
	})
	for i := 0; i < len(open); {
		adv := open[i]
		if adv.Status != "unproven" { // gobump's apkUnproven
			lines = append(lines, fmt.Sprintf("%s %s (%s, fixed in %s): %s", adv.Status, adv.DisplayID(), adv.ID, adv.FixedVersion, adv.Reason))
			i++
			continue
		}
		var ids []string
		for ; i < len(open) && open[i].Status == adv.Status && open[i].FixedEpoch == adv.FixedEpoch && open[i].Reason == adv.Reason; i++ {
			ids = append(ids, fmt.Sprintf("%s (%s)", open[i].DisplayID(), open[i].ID))
		}
		lines = append(lines, fmt.Sprintf("unproven in -r%d (%d): %s: %s", adv.FixedEpoch, len(ids), strings.Join(ids, ", "), adv.Reason))
	}
	return lines
}

// renderBumpTable prints one row per file.
func renderBumpTable(results []*gobump.Result) {
	maxPkgLen := len("PACKAGE")
	for _, result := range results {
		maxPkgLen = max(maxPkgLen, len(result.PackageName))
	}
	maxPkgLen = min(maxPkgLen, 60)

	t := table.New(os.Stdout)
	t.SetRowLines(false)
	t.SetBorders(false)
	t.SetHeaders("PACKAGE", "FOUND", "FIXED", "RESIDUAL", "UNLINKED", "HYGIENE", "BUMPED", "STDLIB", "EPOCH", "STATUS")
	for _, result := range results {
		stdlibVulns := len(output.DistinctStdlibVulnIDs(result.StdlibBumps))
		epoch := fmt.Sprintf("%d", result.OldEpoch)
		if result.NewEpoch != result.OldEpoch {
			epoch = fmt.Sprintf("%d->%d", result.OldEpoch, result.NewEpoch)
		}
		t.AddRow(
			truncate(result.PackageName, maxPkgLen),
			fmt.Sprintf("%d", result.VulnerabilitiesFound),
			fmt.Sprintf("%d", result.VulnerabilitiesFixed),
			fmt.Sprintf("%d", result.VulnerabilitiesResidual),
			fmt.Sprintf("%d", result.VulnerabilitiesUnreachable),
			fmt.Sprintf("%d", result.HygieneModulesBumped),
			fmt.Sprintf("%d", result.ModulesBumped),
			stdlibColumnValue(stdlibVulns, result.StdlibChecked),
			epoch,
			bumpRowStatus(result, stdlibVulns),
		)
	}
	t.Render()
}

// renderWhy prints, per file whose epoch moved (never an ERROR or SKIPPED
// row), the epoch comment's clauses with their advisory counts and the apk
// alignment outcome. A block after the table rather than a spanning table
// row: aquasecurity/table's SetColSpans widens the other columns to fit a
// long cell (and panics in v1.11.0's auto-merge pass).
func renderWhy(results []*gobump.Result) {
	var lines []string
	for _, result := range results {
		if status := bumpRowStatus(result, len(output.DistinctStdlibVulnIDs(result.StdlibBumps))); !result.EpochChanged || status == "ERROR" || status == "SKIPPED" {
			continue
		}
		if why := whyLine(result); why != "" {
			lines = append(lines, fmt.Sprintf("  %s: %s", result.PackageName, why))
		}
	}
	if len(lines) > 0 {
		fmt.Printf("\nWhy:\n%s\n", strings.Join(lines, "\n"))
	}
}

// whyLine renders a result's epoch reasons as "text (N)" clauses plus, when
// apk advisories were aligned with, the apk outcome.
func whyLine(result *gobump.Result) string {
	var parts []string
	for _, reason := range result.EpochReasons {
		if len(reason.VulnIDs) > 0 {
			parts = append(parts, fmt.Sprintf("%s (%d)", reason.Text, len(reason.VulnIDs)))
		} else {
			parts = append(parts, reason.Text)
		}
	}
	why := strings.Join(parts, ", ")
	if apk := result.ApkAlignment; apk != nil && apk.HighestFixedEpoch > 0 {
		version := apk.Version
		if i := strings.LastIndex(version, "-r"); i >= 0 {
			version = version[:i]
		}
		line := fmt.Sprintf("apk: -r%d is the highest Wolfi advisory fix epoch for %s", apk.HighestFixedEpoch, version)
		if result.NewEpoch < apk.HighestFixedEpoch {
			line = fmt.Sprintf("apk: held at -r%d, -r%d advisory not proven (see actions)", result.NewEpoch, apk.BlockedAt)
		}
		if why != "" {
			why += "; "
		}
		why += line
	}
	return why
}

// actionOrder ranks action kinds for display; errors come from Result.Error.
var actionOrder = map[string]int{"error": 0, gobump.ActionPatch: 1, gobump.ActionRerun: 2, gobump.ActionReview: 3, gobump.ActionAccept: 4}

// actionMaxPackages caps the package names listed per action.
const actionMaxPackages = 3

// renderActions prints every result's needed actions (and errors) grouped by
// (kind, subject, detail) across files, most severe kind first, then by
// subject and detail.
func renderActions(results []*gobump.Result) {
	packages := make(map[gobump.NeededAction][]string)
	var keys []gobump.NeededAction
	add := func(action gobump.NeededAction, pkg string) {
		if _, ok := packages[action]; !ok {
			keys = append(keys, action)
		}
		if !slices.Contains(packages[action], pkg) {
			packages[action] = append(packages[action], pkg)
		}
	}
	for _, result := range results {
		if result.Error != "" { // its partial state is incomplete: the error is the action
			add(gobump.NeededAction{Kind: "error", Subject: result.Error}, result.PackageName)
			continue
		}
		for _, action := range result.ActionsNeeded {
			add(action, result.PackageName)
		}
	}
	if len(keys) == 0 {
		return
	}
	slices.SortFunc(keys, func(a, b gobump.NeededAction) int {
		return cmp.Or(cmp.Compare(actionOrder[a.Kind], actionOrder[b.Kind]), strings.Compare(a.Subject, b.Subject), strings.Compare(a.Detail, b.Detail))
	})
	fmt.Println("\nAction needed:")
	for _, action := range keys {
		line := action.Subject
		if action.Detail != "" {
			line += ": " + action.Detail
		}
		pkgs := packages[action]
		names := strings.Join(pkgs[:min(len(pkgs), actionMaxPackages)], ", ")
		if len(pkgs) > actionMaxPackages {
			names += fmt.Sprintf(", +%d more", len(pkgs)-actionMaxPackages)
		}
		fmt.Printf("  %-7s %s - %s\n", strings.ToUpper(action.Kind), line, names)
	}
}

// renderInfo prints one line of the nonzero informational counts, then each
// remaining note.
func renderInfo(results []*gobump.Result) {
	var unlinked, hygiene, apkIgnored, stdlibSkipped int
	for _, result := range results {
		unlinked += result.VulnerabilitiesUnreachable
		hygiene += result.HygieneModulesBumped
		if result.ApkAlignment != nil {
			apkIgnored += result.ApkAlignment.Ignored
		}
		if result.Error == "" && !result.StdlibChecked {
			stdlibSkipped++
		}
	}
	var counts []string
	for _, c := range []struct {
		n         int
		one, many string
	}{
		{unlinked, "advisory in unlinked modules", "advisories in unlinked modules"},
		{hygiene, "hygiene bump", "hygiene bumps"},
		{apkIgnored, "apk advisory ignored", "apk advisories ignored"},
		{stdlibSkipped, "stdlib check skipped", "stdlib checks skipped"},
	} {
		if c.n > 0 {
			counts = append(counts, fmt.Sprintf("%d %s", c.n, pluralWord(c.n, c.one, c.many)))
		}
	}
	var notes []string
	for _, result := range results {
		for _, note := range result.Notes {
			notes = append(notes, fmt.Sprintf("Note %s: %s", result.PackageName, note))
		}
	}
	if len(counts) == 0 && len(notes) == 0 {
		return
	}
	fmt.Println()
	if len(counts) > 0 {
		fmt.Printf("Info (-v for detail): %s\n", strings.Join(counts, ", "))
	}
	for _, note := range notes {
		fmt.Println(note)
	}
}

// bumpRowStatus computes the table STATUS cell for one result. "Fixed"
// means at least one advisory fixed (VulnerabilitiesFixed > 0), the same
// definition the summary counts:
//
//	ERROR          the file failed (partial counts shown)
//	SKIPPED        not analyzed (see SkipReasons) and nothing found
//	PATCH-NEEDED   a first-party apk advisory (own module affected) needs a
//	               source patch; wins over every success status below
//	APK-ALIGN      epoch raised only to align with a proven apk advisory
//	               (no module bumps, stdlib fixes or residuals)
//	UNVALIDATED    fixes written but not proven by simulation
//	PARTIAL        fixed some, residual advisories remain
//	FIXED          fixed by this run (modules or hygiene bumped, file
//	               written or epoch changed), nothing residual
//	NO-FIX         nothing fixed, residual advisories remain (simulated or
//	               not - e.g. no released fix)
//	UPDATED        file rewritten without fixing anything
//	UP-TO-DATE     advisories found, all handled by the existing deps list
//	               (incl. proven fixed with nothing changed by this run)
//	STDLIB-REBUILD no dependency advisories; epoch bumped for a stdlib fix
//	NO VULNS       nothing found
func bumpRowStatus(result *gobump.Result, stdlibVulns int) string {
	fixed := result.VulnerabilitiesFixed > 0
	switch {
	case result.Error != "":
		return "ERROR"
	case len(result.SkipReasons) > 0 && result.VulnerabilitiesFound == 0:
		return "SKIPPED"
	case len(result.FirstPartyVulnIDs) > 0:
		return "PATCH-NEEDED"
	case result.EpochChanged && result.ApkEpochTarget > 0 && result.ApkEpochTarget == result.NewEpoch &&
		result.ModulesBumped == 0 && result.HygieneModulesBumped == 0 &&
		stdlibVulns == 0 && result.VulnerabilitiesResidual == 0:
		return "APK-ALIGN"
	case result.VulnerabilitiesFound > 0:
		switch {
		case fixed && !result.Validated:
			return "UNVALIDATED"
		case fixed && result.VulnerabilitiesResidual > 0:
			return "PARTIAL"
		case fixed && !result.EpochChanged && !result.FileWasWritten && result.ModulesBumped == 0 && result.HygieneModulesBumped == 0:
			return "UP-TO-DATE" // proven fixed by deps an earlier run wrote
		case fixed:
			return "FIXED"
		case result.VulnerabilitiesResidual > 0:
			return "NO-FIX"
		case result.FileWasWritten:
			return "UPDATED"
		default:
			return "UP-TO-DATE"
		}
	case stdlibVulns > 0 && result.EpochChanged:
		return "STDLIB-REBUILD"
	default:
		return "NO VULNS"
	}
}

// stdlibColumnValue renders the table STDLIB column: "skip" when the check
// did not run (disabled, not applicable, or skipped - see the messages), "-"
// when it ran and found nothing to fix, else the count of distinct linked
// fixable stdlib vulnerability IDs (deduped across go-package pin
// constraints - see output.DistinctStdlibVulnIDs).
func stdlibColumnValue(stdlibVulns int, checked bool) string {
	switch {
	case !checked:
		return "skip"
	case stdlibVulns == 0:
		return "-"
	default:
		return fmt.Sprintf("%d", stdlibVulns)
	}
}
