package cmd

import (
	"fmt"
	"os"
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
	cmd.Flags().BoolVar(&noStdlib, "no-stdlib", false, "Skip the Go stdlib staleness check (no epoch bump for toolchain-fixed vulnerabilities). The check is also skipped automatically for files with uncommitted changes.")

	return cmd
}

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

	if verbosity > 0 {
		fmt.Fprintf(os.Stderr, "Found %d melange files to check for vulnerabilities\n", len(files))
	}

	// Configure processor options
	opts := buildBumpProcessorOptions()

	if dryRun {
		fmt.Println("Dry run mode - no files will be modified")
	}

	// Create shared HTTP client with custom timeout
	httpClient := httpclient.NewHTTPClientWithTimeout(httpTimeout)
	analyzer := gobump.NewAnalyzer(httpClient)

	// Process all files using shared processor architecture
	results := make([]*gobump.GoBumpResult, 0, len(files))
	for _, file := range files {
		result, err := gobump.ProcessFile(ctx, file, opts, analyzer)

		if err != nil {
			if verbosity > 0 {
				fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", file, err)
			}
			// Create error result
			result = &gobump.GoBumpResult{
				PackageName: extractPackageNameFromPath(file),
				FilePath:    file,
				Error:       err.Error(),
			}
		}
		results = append(results, result)
	}

	// Output results
	return outputBumpResults(results, outputFormat)
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

func outputBumpStructured(results []*gobump.GoBumpResult, format string) error {
	// Build map keyed by filename
	resultsMap := make(map[string]*gobump.GoBumpResult)
	for _, result := range results {
		filename := output.ExtractFilename(result.FilePath)
		resultsMap[filename] = result
	}

	// Calculate summary statistics
	summary := output.GoBumpSummary{
		TotalPackages: len(results),
	}
	for _, r := range results {
		if r.VulnerabilitiesFound > 0 {
			summary.PackagesWithVulns++
			summary.TotalVulnsFound += r.VulnerabilitiesFound
			if !r.Validated {
				summary.PackagesUnvalidated++
			}
		}
		if r.VulnerabilitiesFixed > 0 {
			summary.PackagesFixed++
			summary.TotalVulnsFixed += r.VulnerabilitiesFixed
		}
		if r.VulnerabilitiesResidual > 0 {
			summary.PackagesPartial++
			summary.TotalVulnsResidual += r.VulnerabilitiesResidual
		}
		summary.TotalVulnsUnreachable += r.VulnerabilitiesUnreachable
		summary.TotalModulesBumped += r.ModulesBumped
		if r.Error != "" {
			summary.Errors++
		}
		if distinct := output.DistinctStdlibVulnIDs(r.StdlibBumps); len(distinct) > 0 {
			summary.PackagesStdlibStale++
			summary.TotalStdlibVulns += len(distinct)
		}
	}

	// Wrap in response structure
	response := output.GoBumpResponse{
		Results: resultsMap,
		Summary: summary,
	}

	// Output in requested format
	if format == "json" {
		return output.OutputJSON(os.Stdout, response)
	}
	return output.OutputYAML(os.Stdout, response)
}

func outputBumpTable(results []*gobump.GoBumpResult) error {
	// Calculate max package name length
	maxPkgLen := len("PACKAGE")
	for _, result := range results {
		if len(result.PackageName) > maxPkgLen {
			maxPkgLen = len(result.PackageName)
		}
	}
	if maxPkgLen > 60 {
		maxPkgLen = 60
	}

	// Create and configure table
	t := table.New(os.Stdout)
	t.SetRowLines(false)
	t.SetBorders(false)
	t.SetHeaders("PACKAGE", "FOUND", "FIXED", "RESIDUAL", "UNLINKED", "BUMPED", "STDLIB", "OLD EPOCH", "NEW EPOCH", "STATUS")

	// Track statistics
	totalFiles := len(results)
	filesWithVulns := 0
	filesFixed := 0
	filesStdlibStale := 0
	totalVulnsFound := 0
	totalVulnsFixed := 0
	totalVulnsResidual := 0
	totalVulnsUnreachable := 0
	totalModulesBumped := 0
	errors := 0

	// Add rows
	for _, result := range results {
		stdlibVulns := len(output.DistinctStdlibVulnIDs(result.StdlibBumps))
		if stdlibVulns > 0 {
			filesStdlibStale++
		}

		if result.Error != "" {
			errors++
		} else if result.VulnerabilitiesFound > 0 {
			filesWithVulns++
			totalVulnsFound += result.VulnerabilitiesFound
			totalVulnsFixed += result.VulnerabilitiesFixed
			totalVulnsResidual += result.VulnerabilitiesResidual
			totalVulnsUnreachable += result.VulnerabilitiesUnreachable
			if dependencyFixApplied(result) {
				filesFixed++
			}
		}
		totalModulesBumped += result.ModulesBumped

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

	// Render the table
	t.Render()

	// Residuals and validation warnings are always shown - a package with
	// residual advisories must never silently read as clean.
	for _, result := range results {
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
		if result.Error == "" && result.VulnerabilitiesFound > 0 && !result.Validated {
			fmt.Printf("\nWARNING: %s deps list NOT validated - resolvability and completeness unproven\n", result.PackageName)
		}
	}

	// Show verbose details after the table
	if verbosity > 0 {
		for _, result := range results {
			if len(result.Messages) > 0 {
				fmt.Printf("\nMessages for %s:\n", result.PackageName)
				for _, message := range result.Messages {
					fmt.Printf("  - %s\n", message)
				}
			}

			if result.Error != "" {
				fmt.Printf("\nError for %s: %s\n", result.PackageName, result.Error)
			}
		}
	}

	// Summary
	summary := fmt.Sprintf("Summary: %d files processed, %d with vulnerabilities, %d fixed, %d errors",
		totalFiles, filesWithVulns, filesFixed, errors)

	if totalVulnsFound > 0 {
		summary += fmt.Sprintf(" (%d advisories found, %d fixed, %d residual, %d in unlinked modules; %d modules bumped)",
			totalVulnsFound, totalVulnsFixed, totalVulnsResidual, totalVulnsUnreachable, totalModulesBumped)
	}

	if filesStdlibStale > 0 {
		summary += fmt.Sprintf("; %d stdlib-stale", filesStdlibStale)
	}

	fmt.Printf("\n%s\n", summary)

	if dryRun {
		fmt.Println("(Dry run - no files were actually modified)")
	}

	return nil
}

// dependencyFixApplied returns true if the result includes any dependency-level
// fix attempt: either vulnerabilities were fixed (proven by simulation or
// approximated by module changes) or modules were bumped (attempted fix).
// This decouples dependency-fix status from epoch changes that may result
// solely from stdlib staleness checks.
func dependencyFixApplied(result *gobump.GoBumpResult) bool {
	return result.VulnerabilitiesFixed > 0 || result.ModulesBumped > 0
}

// bumpRowStatus computes the table STATUS cell for one result, mirroring the
// found/fixed/residual precedence used for dependency vulnerabilities and
// adding a distinct status for files whose only change is a stdlib-driven
// epoch bump: zero dependency vulnerabilities found, but the stdlib
// staleness check proposed one or more fixes and the epoch moved. Files with
// both dependency fixes and stdlib bumps keep their existing dependency-
// driven status - the STDLIB column carries that information instead.
func bumpRowStatus(result *gobump.GoBumpResult, stdlibVulns int) string {
	switch {
	case result.Error != "":
		return "ERROR"
	case result.VulnerabilitiesFound > 0:
		switch {
		case dependencyFixApplied(result):
			switch {
			case !result.Validated:
				return "UNVALIDATED"
			case result.VulnerabilitiesResidual > 0:
				return "PARTIAL"
			default:
				return "FIXED"
			}
		case result.FileWasWritten:
			return "UPDATED"
		default:
			// Vulnerabilities found but no changes needed (pipeline already correct)
			if result.Validated && result.VulnerabilitiesResidual > 0 {
				return "PARTIAL"
			}
			return "UP-TO-DATE"
		}
	case stdlibVulns > 0 && result.EpochChanged:
		return "STDLIB-REBUILD"
	default:
		return "NO VULNS"
	}
}

// stdlibColumnValue renders the table STDLIB column: the count of distinct
// linked fixable stdlib vulnerability IDs (deduped across go-package pin
// constraints - see output.DistinctStdlibVulnIDs), or "-" when the check
// didn't run or found nothing to fix.
func stdlibColumnValue(stdlibVulns int, checked bool) string {
	if !checked || stdlibVulns == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", stdlibVulns)
}

func extractPackageNameFromPath(filePath string) string {
	// Extract package name from file path for error cases
	parts := strings.Split(filePath, "/")
	if len(parts) > 0 {
		filename := parts[len(parts)-1]
		// Remove .yaml extension if present
		return strings.TrimSuffix(filename, ".yaml")
	}
	return "unknown"
}
