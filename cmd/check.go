package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aquasecurity/table"
	"github.com/isometry/choam/internal/output"
	"github.com/isometry/choam/internal/updater"
	"github.com/spf13/cobra"
)

func NewCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check [path...]",
		Short: "Check for available updates",
		Long: `Check for available updates in melange build specifications.
Path can be a single file or a directory containing .yaml files.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runCheck,
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, yaml")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be checked without making API calls")

	return cmd
}

func runCheck(cmd *cobra.Command, args []string) error {
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

	slog.Info("found melange files to check", "count", len(files)) //nolint:forbidigo // pre-per-file: no processor/ctx attribution exists yet

	if dryRun {
		fmt.Println("Dry run mode - would check the following files:")
		for _, file := range files {
			fmt.Printf("  %s\n", file)
		}
		return nil
	}

	// Create orchestrator with custom HTTP timeout
	orchestrator := updater.NewOrchestratorWithTimeout(httpTimeout)

	// Process all files for checking
	processors, err := orchestrator.ProcessMultipleChecks(ctx, files)
	if err != nil {
		return fmt.Errorf("checking updates: %w", err)
	}

	slog.Info("processed melange files", "count", len(processors)) //nolint:forbidigo // run-level summary, not attributable to any one file

	// Convert processors to results for output
	results := make([]*updater.UpdateResult, 0, len(processors))
	for _, proc := range processors {
		errorMsg := ""
		errors := proc.GetErrors()
		if len(errors) > 0 {
			errorStrs := make([]string, len(errors))
			for i, err := range errors {
				errorStrs[i] = err.Error()
			}
			errorMsg = strings.Join(errorStrs, "; ")
		}

		results = append(results, &updater.UpdateResult{
			PackageName:    proc.GetPackageName(),
			FilePath:       proc.GetFilePath(),
			CurrentVersion: proc.GetCurrentVersion(),
			LatestVersion:  proc.GetLatestVersion(),
			HasUpdate:      proc.UpdateAvailable,
			UpdateSource:   proc.UpdateSource,
			IsManual:       proc.IsManual,
			Error:          errorMsg,
		})
	}

	// Output results
	return outputResults(results, outputFormat)
}

func outputResults(results []*updater.UpdateResult, format string) error {
	switch format {
	case "json":
		return outputStructuredResults(results, "json")
	case "yaml":
		return outputStructuredResults(results, "yaml")
	case "table":
		return outputTable(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputStructuredResults(results []*updater.UpdateResult, format string) error {
	// Build map keyed by filename
	resultsMap := make(map[string]*updater.UpdateResult)
	for _, result := range results {
		filename := output.ExtractFilename(result.FilePath)
		resultsMap[filename] = result
	}

	// Calculate summary statistics
	summary := output.CheckSummary{
		TotalPackages: len(results),
	}
	for _, r := range results {
		if r.HasUpdate {
			summary.UpdatesAvailable++
		}
		if r.Error != "" {
			summary.Errors++
		}
		if r.IsManual {
			summary.Manual++
		}
	}

	// Wrap in response structure
	response := output.CheckResponse{
		Results: resultsMap,
		Summary: summary,
	}

	// Output in requested format
	if format == "json" {
		return output.OutputJSON(os.Stdout, response)
	}
	return output.OutputYAML(os.Stdout, response)
}

func outputTable(results []*updater.UpdateResult) error {
	// Calculate max package name length
	maxPkgLen := len("PACKAGE") // Start with header length
	for _, result := range results {
		if len(result.PackageName) > maxPkgLen {
			maxPkgLen = len(result.PackageName)
		}
	}
	// Cap at reasonable maximum
	if maxPkgLen > 60 {
		maxPkgLen = 60
	}

	// Create and configure table
	t := table.New(os.Stdout)
	t.SetRowLines(false)
	t.SetBorders(false)
	t.SetHeaders("PACKAGE", "CURRENT", "LATEST", "UPDATE", "SOURCE", "STATUS")

	// Add rows
	for _, result := range results {
		status := "OK"
		if result.Error != "" {
			status = "ERROR"
		} else if result.IsManual {
			status = "MANUAL"
		}

		updateStatus := "NO"
		if result.HasUpdate {
			updateStatus = "YES"
		}

		t.AddRow(
			truncate(result.PackageName, maxPkgLen),
			truncate(result.CurrentVersion, 15),
			truncate(result.LatestVersion, 15),
			updateStatus,
			truncate(result.UpdateSource, 20),
			status,
		)
	}

	// Render the table
	t.Render()

	// Print verbose error details after the table
	if verbosity > 0 {
		for _, result := range results {
			if result.Error != "" {
				fmt.Printf("\nError for %s: %s\n", result.PackageName, result.Error)
			}
		}
	}

	// Summary
	totalPackages := len(results)
	updatesAvailable := 0
	errors := 0
	manual := 0

	for _, result := range results {
		if result.HasUpdate {
			updatesAvailable++
		}
		if result.Error != "" {
			errors++
		}
		if result.IsManual {
			manual++
		}
	}

	summary := fmt.Sprintf("Summary: %d packages checked, %d updates available, %d errors",
		totalPackages, updatesAvailable, errors)

	if manual > 0 {
		summary += fmt.Sprintf(" (%d manual)", manual)
	}

	fmt.Printf("\n%s\n", summary)

	return nil
}
