package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/table"
	"github.com/isometry/choam/internal/gobump"
	"github.com/isometry/choam/internal/httpclient"
	"github.com/isometry/choam/internal/output"
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
	cmd.Flags().BoolVar(&failOnResidual, "fail-on-residual", false, "Exit non-zero when any advisory remains residual (files that error always exit non-zero)")
	cmd.Flags().BoolVar(&noStdlib, "no-stdlib", false, "Skip the Go stdlib staleness check (no epoch bump for toolchain-fixed vulnerabilities). The check is also skipped automatically for files with uncommitted changes.")

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
		fmt.Println("No melange files found.")
		return nil
	}

	slog.Info("found melange files to check for vulnerabilities", "count", len(files)) //nolint:forbidigo // pre-per-file: no processor/ctx attribution exists yet

	// Configure processor options
	opts := buildBumpProcessorOptions()

	if dryRun {
		fmt.Println("Dry run mode - no files will be modified")
	}

	// Create shared HTTP client with custom timeout
	httpClient := httpclient.NewHTTPClientWithTimeout(httpTimeout)
	analyzer := gobump.NewAnalyzer(httpClient)

	results := make([]*gobump.GoBumpResult, 0, len(files))
	for i, file := range files {
		if ctx.Err() != nil {
			break
		}

		slog.Info("processing melange file", "file", file, "index", i+1, "total", len(files)) //nolint:forbidigo // this IS the file attribution - the per-file ctx is seeded inside ProcessFile

		result, err := gobump.ProcessFile(ctx, file, opts, analyzer)
		if err != nil {
			slog.Error("processing melange file failed", "file", file, "error", err) //nolint:forbidigo // ProcessFile failed before/without seeding a ctx logger
			if result == nil {
				// Read/parse failure: no processor, so no partial state.
				result = &gobump.GoBumpResult{
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
	summary := summarizeBumpResults(results)
	switch {
	case summary.Errors > 0:
		return fmt.Errorf("%w: %d of %d file(s) errored", ErrBumpFailed, summary.Errors, summary.TotalPackages)
	case failOnResidual && summary.TotalVulnsResidual > 0:
		return fmt.Errorf("%w: %d residual advisory(ies) in %d file(s) (--fail-on-residual)", ErrBumpFailed, summary.TotalVulnsResidual, summary.PackagesPartial)
	}
	return nil
}

// buildBumpProcessorOptions maps the bump command's flag-backed package
// variables onto gobump.ProcessorOptions. Factored out of runBump so the
// flag-to-option wiring (e.g. --no-stdlib -> StdlibCheck) is directly
// testable without driving the full command.
func buildBumpProcessorOptions() gobump.ProcessorOptions {
	return gobump.ProcessorOptions{
		DryRun:            dryRun,
		BackupSuffix:      backupSuffix,
		TempDir:           os.TempDir(),
		Validate:          !noValidate,
		SimulationTimeout: simulationTimeout,
		Compile:           !noValidate && !noCompile,
		StdlibCheck:       !noStdlib,
	}
}

func outputBumpResults(results []*gobump.GoBumpResult, format string) error {
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
func summarizeBumpResults(results []*gobump.GoBumpResult) output.GoBumpSummary {
	summary := output.GoBumpSummary{TotalPackages: len(results)}
	for _, r := range results {
		if distinct := output.DistinctStdlibVulnIDs(r.StdlibBumps); len(distinct) > 0 {
			summary.PackagesStdlibStale++
			summary.TotalStdlibVulns += len(distinct)
		}
		if r.Error != "" {
			summary.Errors++
			continue
		}
		if len(r.SkipReasons) > 0 {
			summary.PackagesSkipped++
		}
		summary.TotalModulesBumped += r.ModulesBumped
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
func outputBumpStructured(results []*gobump.GoBumpResult, format string) error {
	resultsMap := make(map[string]*gobump.GoBumpResult, len(results))
	for _, result := range results {
		resultsMap[result.FilePath] = result
	}
	response := output.GoBumpResponse{
		Results: resultsMap,
		Summary: summarizeBumpResults(results),
	}
	if format == "json" {
		return output.OutputJSON(os.Stdout, response)
	}
	return output.OutputYAML(os.Stdout, response)
}

func outputBumpTable(results []*gobump.GoBumpResult) error {
	maxPkgLen := len("PACKAGE")
	for _, result := range results {
		maxPkgLen = max(maxPkgLen, len(result.PackageName))
	}
	maxPkgLen = min(maxPkgLen, 60)

	t := table.New(os.Stdout)
	t.SetRowLines(false)
	t.SetBorders(false)
	t.SetHeaders("PACKAGE", "FOUND", "FIXED", "RESIDUAL", "UNLINKED", "BUMPED", "STDLIB", "OLD EPOCH", "NEW EPOCH", "STATUS")
	for _, result := range results {
		stdlibVulns := len(output.DistinctStdlibVulnIDs(result.StdlibBumps))
		t.AddRow(
			truncate(result.PackageName, maxPkgLen),
			fmt.Sprintf("%d", result.VulnerabilitiesFound),
			fmt.Sprintf("%d", result.VulnerabilitiesFixed),
			fmt.Sprintf("%d", result.VulnerabilitiesResidual),
			fmt.Sprintf("%d", result.VulnerabilitiesUnreachable),
			fmt.Sprintf("%d", result.ModulesBumped),
			stdlibColumnValue(stdlibVulns, result.StdlibChecked),
			fmt.Sprintf("%d", result.OldEpoch),
			fmt.Sprintf("%d", result.NewEpoch),
			bumpRowStatus(result, stdlibVulns),
		)
	}
	t.Render()

	// Errors, skips, residuals and validation warnings are always shown - a
	// package that was not (fully) analyzed or still carries advisories must
	// never silently read as clean.
	for _, result := range results {
		if result.Error != "" {
			fmt.Printf("\nError for %s: %s\n", result.PackageName, result.Error)
		}
		if len(result.SkipReasons) > 0 {
			fmt.Printf("\nSkipped %s: %s\n", result.PackageName, strings.Join(result.SkipReasons, "; "))
		}
		if len(result.Residuals) > 0 {
			fmt.Printf("\nResidual vulnerabilities for %s (no reachable zero-vulnerability state):\n", result.PackageName)
			for _, residual := range result.Residuals {
				location := residual.Module
				if residual.ResolvedVersion != "" {
					location += "@" + residual.ResolvedVersion
				}
				detail := residual.Reason
				if residual.FixedVersion != "" {
					detail = fmt.Sprintf("needs %s: %s", residual.FixedVersion, residual.Reason)
				}
				vulns := strings.Join(residual.VulnIDs, ", ")
				if vulns == "" {
					vulns = "-"
				}
				fmt.Printf("  - %s [%s] %s\n", location, vulns, detail)
			}
		}
		if result.Error == "" && result.VulnerabilitiesFound > 0 && !result.Validated && (result.FileWasWritten || result.ModulesBumped > 0) {
			fmt.Printf("\nWARNING: %s deps list NOT validated - resolvability and completeness unproven\n", result.PackageName)
		}
	}

	if verbosity > 0 {
		for _, result := range results {
			if len(result.Messages) > 0 {
				fmt.Printf("\nMessages for %s:\n", result.PackageName)
				for _, message := range result.Messages {
					fmt.Printf("  - %s\n", message)
				}
			}
		}
	}

	s := summarizeBumpResults(results)
	footer := fmt.Sprintf("Summary: %d files processed, %d with vulnerabilities, %d fixed, %d errors",
		s.TotalPackages, s.PackagesWithVulns, s.PackagesFixed, s.Errors)
	if s.PackagesSkipped > 0 {
		footer += fmt.Sprintf(", %d skipped", s.PackagesSkipped)
	}
	if s.TotalVulnsFound > 0 {
		footer += fmt.Sprintf(" (%d advisories found, %d fixed, %d residual, %d in unlinked modules; %d modules bumped)",
			s.TotalVulnsFound, s.TotalVulnsFixed, s.TotalVulnsResidual, s.TotalVulnsUnreachable, s.TotalModulesBumped)
	}
	if s.PackagesStdlibStale > 0 {
		footer += fmt.Sprintf("; %d stdlib-stale", s.PackagesStdlibStale)
	}
	fmt.Printf("\n%s\n", footer)

	if dryRun {
		fmt.Println("(Dry run - no files were actually modified)")
	}

	return nil
}

// bumpRowStatus computes the table STATUS cell for one result. "Fixed"
// means at least one advisory fixed (VulnerabilitiesFixed > 0), the same
// definition the summary counts:
//
//	ERROR          the file failed (partial counts shown)
//	SKIPPED        not analyzed (see SkipReasons) and nothing found
//	UNVALIDATED    fixes written but not proven by simulation
//	PARTIAL        fixed some, residual advisories remain
//	FIXED          fixed, nothing residual
//	NO-FIX         nothing fixed, residual advisories remain (simulated or
//	               not - e.g. no released fix)
//	UPDATED        file rewritten without fixing anything
//	UP-TO-DATE     advisories found, all handled by the existing deps list
//	STDLIB-REBUILD no dependency advisories; epoch bumped for a stdlib fix
//	NO VULNS       nothing found
func bumpRowStatus(result *gobump.GoBumpResult, stdlibVulns int) string {
	fixed := result.VulnerabilitiesFixed > 0
	switch {
	case result.Error != "":
		return "ERROR"
	case len(result.SkipReasons) > 0 && result.VulnerabilitiesFound == 0:
		return "SKIPPED"
	case result.VulnerabilitiesFound > 0:
		switch {
		case fixed && !result.Validated:
			return "UNVALIDATED"
		case fixed && result.VulnerabilitiesResidual > 0:
			return "PARTIAL"
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
