package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/table"
	"github.com/isometry/choam/internal/output"
	"github.com/isometry/choam/internal/updater"
	"github.com/spf13/cobra"
)

func NewUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [path...]",
		Short: "Apply available updates to melange build specifications",
		Long: `Apply available updates to melange build specification files.
This command will update the package version, reset epoch, update pipeline
expected-commit values, fetch pipeline SHA256 checksums, and optionally
update shared dependencies.

Path can be a single file or a directory containing .yaml files.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runUpdate,
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be updated without making changes")
	cmd.Flags().BoolVar(&force, "force", false, "Force update even if no version change (increment epoch)")
	cmd.Flags().BoolVar(&updateShared, "shared", true, "Update shared dependencies")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json, yaml")
	cmd.Flags().StringVar(&backupSuffix, "backup-suffix", "", "Suffix for backup files (empty = no backup)")

	return cmd
}

func runUpdate(cmd *cobra.Command, args []string) error {
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

	slog.Info("found melange files to update", "count", len(files)) //nolint:forbidigo // pre-per-file: no processor/ctx attribution exists yet

	// Configure processor options (note: no more SecurityScan - always enabled)
	opts := updater.ProcessorOptions{
		DryRun:        dryRun,
		Force:         force,
		SharedUpdates: updateShared,
		BackupSuffix:  backupSuffix,
		TempDir:       os.TempDir(),
	}

	if dryRun {
		fmt.Println("Dry run mode - no files will be modified")
	}

	// Create orchestrator with custom HTTP timeout
	orchestrator := updater.NewOrchestratorWithTimeout(httpTimeout)

	// Process all files for updates
	processors, err := orchestrator.ProcessMultipleApplies(ctx, files, opts)
	if err != nil {
		return fmt.Errorf("processing updates: %w", err)
	}

	// Convert processors to results for output
	results := make([]*updater.ApplyResult, 0, len(processors))
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

		// Only include fixes in updates, not discovery messages
		updatesApplied := make([]string, 0)
		messages := proc.GetMessages()
		for _, msg := range messages {
			// Only include messages that indicate actual changes, not discoveries
			if strings.Contains(msg, "updated") || strings.Contains(msg, "bumped") ||
				strings.Contains(msg, "applied") || strings.Contains(msg, "fixed") {
				updatesApplied = append(updatesApplied, msg)
			}
		}

		result := &updater.ApplyResult{
			PackageName:    proc.GetPackageName(),
			FilePath:       proc.GetFilePath(),
			OldVersion:     proc.GetCurrentVersion(),
			NewVersion:     proc.GetCurrentVersion(), // Default to current
			OldEpoch:       proc.GetCurrentEpoch(),
			NewEpoch:       proc.GetNewEpoch(),
			UpdatesApplied: updatesApplied,
			SharedUpdates:  make([]string, 0), // TODO: Implement if needed
			FileWasWritten: proc.HasFileChanges(),
			IsManual:       proc.IsManual,
			Error:          errorMsg,
		}

		// If version changed, update new version
		if proc.IsVersionChanged() {
			result.NewVersion = proc.GetLatestVersion()
		}

		// Add backup path if configured
		if backupSuffix != "" {
			ext := filepath.Ext(proc.GetFilePath())
			base := strings.TrimSuffix(proc.GetFilePath(), ext)
			result.BackupCreated = base + backupSuffix + ext
		}

		results = append(results, result)
	}

	// Output results
	return outputUpdateResults(results, outputFormat)
}

func outputUpdateResults(results []*updater.ApplyResult, format string) error {
	switch format {
	case "json":
		return outputUpdateStructured(results, "json")
	case "yaml":
		return outputUpdateStructured(results, "yaml")
	case "table":
		return outputUpdateTable(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputUpdateStructured(results []*updater.ApplyResult, format string) error {
	// Build map keyed by filename
	resultsMap := make(map[string]*updater.ApplyResult)
	for _, result := range results {
		filename := output.ExtractFilename(result.FilePath)
		resultsMap[filename] = result
	}

	// Calculate summary statistics
	summary := output.UpdateSummary{
		TotalPackages: len(results),
	}
	for _, r := range results {
		if r.FileWasWritten {
			summary.SuccessfulUpdates++
		}
		if r.Error != "" {
			summary.Errors++
		}
		if r.IsManual {
			summary.Manual++
		}
	}

	// Wrap in response structure
	response := output.UpdateResponse{
		Results: resultsMap,
		Summary: summary,
	}

	// Output in requested format
	if format == "json" {
		return output.OutputJSON(os.Stdout, response)
	}
	return output.OutputYAML(os.Stdout, response)
}

func outputUpdateTable(results []*updater.ApplyResult) error {
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

	// Calculate max updates width
	maxUpdatesLen := len("UPDATES") // Start with header length
	for _, result := range results {
		for _, update := range result.UpdatesApplied {
			if len(update) > maxUpdatesLen {
				maxUpdatesLen = len(update)
			}
		}
	}
	// Cap at reasonable maximum for updates
	if maxUpdatesLen > 50 {
		maxUpdatesLen = 50
	}

	// Create and configure table
	t := table.New(os.Stdout)
	t.SetRowLines(false)
	t.SetBorders(false)
	t.SetHeaders("PACKAGE", "OLD VERSION", "NEW VERSION", "UPDATES", "STATUS")

	// Track statistics
	totalFiles := len(results)
	successfulUpdates := 0
	errors := 0

	// Add rows
	for _, result := range results {
		status := "NO UPDATE"
		if result.Error != "" {
			status = "ERROR"
			errors++
		} else if result.IsManual {
			status = "MANUAL"
		} else if result.FileWasWritten {
			status = "OK"
			successfulUpdates++
		} else if len(result.UpdatesApplied) > 0 {
			status = "NO UPDATE"
		}

		// Format updates applied as multiline for table display
		updatesApplied := "none"
		if len(result.UpdatesApplied) > 0 {
			// Truncate each line individually for multiline display
			var truncatedUpdates []string
			for _, update := range result.UpdatesApplied {
				truncatedUpdates = append(truncatedUpdates, truncate(update, maxUpdatesLen))
			}
			updatesApplied = strings.Join(truncatedUpdates, "\n")
		}

		t.AddRow(
			truncate(result.PackageName, maxPkgLen),
			truncate(result.OldVersion, 15),
			truncate(result.NewVersion, 15),
			updatesApplied, // Already truncated per line above
			status,
		)
	}

	// Render the table
	t.Render()

	// Show verbose details after the table
	if verbosity > 0 {
		for _, result := range results {
			if len(result.SharedUpdates) > 0 {
				fmt.Printf("\nShared updates for %s:\n", result.PackageName)
				for _, shared := range result.SharedUpdates {
					fmt.Printf("  - %s\n", shared)
				}
			}

			if result.Error != "" {
				fmt.Printf("\nError for %s: %s\n", result.PackageName, result.Error)
			}

			if result.BackupCreated != "" && !dryRun {
				fmt.Printf("\nBackup for %s: %s\n", result.PackageName, result.BackupCreated)
			}
		}
	}

	// Count manual packages
	manual := 0
	for _, result := range results {
		if result.IsManual {
			manual++
		}
	}

	// Summary
	summary := fmt.Sprintf("Summary: %d files processed, %d updated, %d errors",
		totalFiles, successfulUpdates, errors)

	if manual > 0 {
		summary += fmt.Sprintf(" (%d manual)", manual)
	}

	fmt.Printf("\n%s\n", summary)

	if dryRun {
		fmt.Println("(Dry run - no files were actually modified)")
	}

	return nil
}
