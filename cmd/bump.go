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
	opts := gobump.ProcessorOptions{
		DryRun:            dryRun,
		BackupSuffix:      backupSuffix,
		TempDir:           os.TempDir(),
		Validate:          !noValidate,
		SimulationTimeout: simulationTimeout,
	}

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
	t.SetHeaders("PACKAGE", "FOUND", "FIXED", "RESIDUAL", "UNLINKED", "BUMPED", "OLD EPOCH", "NEW EPOCH", "STATUS")

	// Track statistics
	totalFiles := len(results)
	filesWithVulns := 0
	filesFixed := 0
	totalVulnsFound := 0
	totalVulnsFixed := 0
	totalVulnsResidual := 0
	totalVulnsUnreachable := 0
	totalModulesBumped := 0
	errors := 0

	// Add rows
	for _, result := range results {
		status := "NO VULNS"
		if result.Error != "" {
			status = "ERROR"
			errors++
		} else if result.VulnerabilitiesFound > 0 {
			filesWithVulns++
			totalVulnsFound += result.VulnerabilitiesFound
			totalVulnsFixed += result.VulnerabilitiesFixed
			totalVulnsResidual += result.VulnerabilitiesResidual
			totalVulnsUnreachable += result.VulnerabilitiesUnreachable

			switch {
			case result.VulnerabilitiesFixed > 0 || result.EpochChanged:
				filesFixed++
				switch {
				case !result.Validated:
					status = "UNVALIDATED"
				case result.VulnerabilitiesResidual > 0:
					status = "PARTIAL"
				default:
					status = "FIXED"
				}
			case result.FileWasWritten:
				status = "UPDATED"
			default:
				// Vulnerabilities found but no changes needed (pipeline already correct)
				status = "UP-TO-DATE"
				if result.Validated && result.VulnerabilitiesResidual > 0 {
					status = "PARTIAL"
				}
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
			fmt.Sprintf("%d", result.OldEpoch),
			fmt.Sprintf("%d", result.NewEpoch),
			status,
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

	fmt.Printf("\n%s\n", summary)

	if dryRun {
		fmt.Println("(Dry run - no files were actually modified)")
	}

	return nil
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
