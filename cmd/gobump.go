package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/aquasecurity/table"
	"github.com/isometry/choam/internal/gobump"
	"github.com/spf13/cobra"
)

func NewGoBumpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gobump [path...]",
		Short: "Fix Go module vulnerabilities using go/bump pipelines",
		Long: `Fix Go module vulnerabilities by adding or updating go/bump pipeline steps.
This command checks for vulnerabilities in the current version of Go modules
and applies security fixes by updating go/bump pipelines. The package epoch
will be incremented when vulnerabilities are fixed.

Path can be a single file or a directory containing .yaml files.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runGoBump,
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be changed without making changes")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
	cmd.Flags().StringVar(&backupSuffix, "backup-suffix", "", "Suffix for backup files (empty = no backup)")

	return cmd
}

func runGoBump(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

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
		fmt.Fprintf(os.Stderr, "Found %d melange files to check for Go vulnerabilities\n", len(files))
	}

	// Configure processor options
	opts := gobump.ProcessorOptions{
		DryRun:       dryRun,
		BackupSuffix: backupSuffix,
		TempDir:      os.TempDir(),
	}

	if dryRun {
		fmt.Println("Dry run mode - no files will be modified")
	}

	// Create HTTP client and components
	httpClient := &http.Client{}
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
	return outputGoBumpResults(results, outputFormat)
}

func outputGoBumpResults(results []*gobump.GoBumpResult, format string) error {
	switch format {
	case "json":
		return outputGoBumpJSON(results)
	case "table":
		return outputGoBumpTable(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputGoBumpJSON(results []*gobump.GoBumpResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func outputGoBumpTable(results []*gobump.GoBumpResult) error {
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
	t.SetHeaders("PACKAGE", "VULNS FOUND", "VULNS FIXED", "OLD EPOCH", "NEW EPOCH", "STATUS")

	// Track statistics
	totalFiles := len(results)
	filesWithVulns := 0
	filesFixed := 0
	totalVulnsFound := 0
	totalVulnsFixed := 0
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
			if result.VulnerabilitiesFixed > 0 {
				// Actual changes were made and applied
				status = "FIXED"
				filesFixed++
				totalVulnsFixed += result.VulnerabilitiesFixed
			} else if result.EpochChanged {
				// Epoch changed but no security fixes counted (shouldn't happen but handle it)
				status = "FIXED"
				filesFixed++
			} else if result.FileWasWritten {
				// File was written but no fixes counted (rare edge case)
				status = "UPDATED"
			} else {
				// Vulnerabilities found but no changes needed (pipeline already correct)
				status = "UP-TO-DATE"
			}
		}

		vulnsFoundStr := "0"
		if result.VulnerabilitiesFound > 0 {
			vulnsFoundStr = fmt.Sprintf("%d", result.VulnerabilitiesFound)
		}

		vulnsFixedStr := "0"
		if result.VulnerabilitiesFixed > 0 {
			vulnsFixedStr = fmt.Sprintf("%d", result.VulnerabilitiesFixed)
		}

		oldEpochStr := fmt.Sprintf("%d", result.OldEpoch)
		newEpochStr := fmt.Sprintf("%d", result.NewEpoch)

		t.AddRow(
			truncate(result.PackageName, maxPkgLen),
			vulnsFoundStr,
			vulnsFixedStr,
			oldEpochStr,
			newEpochStr,
			status,
		)
	}

	// Render the table
	t.Render()

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
		summary += fmt.Sprintf(" (%d vulnerabilities found, %d fixed)", totalVulnsFound, totalVulnsFixed)
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
