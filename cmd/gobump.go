package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/aquasecurity/table"
	"github.com/isometry/choam/pkg/gobump"
	"github.com/spf13/cobra"
	melange "chainguard.dev/melange/pkg/config"
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
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	return cmd
}

func runGoBump(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Collect all melange files from the provided paths
	files, err := collectMelangeFiles(args)
	if err != nil {
		return fmt.Errorf("collecting melange files: %w", err)
	}

	if len(files) == 0 {
		fmt.Println("No melange files found.")
		return nil
	}

	if verbose {
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
	checker := gobump.NewChecker(analyzer)
	applier := gobump.NewApplier(analyzer)

	// Process all files
	results := make([]*gobump.GoBumpResult, 0, len(files))
	for _, file := range files {
		result, err := processGoBumpFile(ctx, file, opts, checker, applier)
		if err != nil {
			if verbose {
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

func processGoBumpFile(ctx context.Context, filePath string, opts gobump.ProcessorOptions, checker *gobump.Checker, applier *gobump.Applier) (*gobump.GoBumpResult, error) {
	// Read and parse melange file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", filePath, err)
	}

	// Parse melange configuration
	cfg, err := melange.ParseConfiguration(ctx, filePath)
	if err != nil {
		return nil, fmt.Errorf("parsing melange configuration: %w", err)
	}

	// Create processor
	processor := gobump.NewProcessor(filePath, cfg.Package.Name, cfg.Package.Version, int64(cfg.Package.Epoch))
	processor.Config = cfg
	processor.OriginalYAML = content
	processor.CurrentYAML = content
	processor.SetOptions(opts)

	// Check for vulnerabilities
	analysis, err := checker.CheckVulnerabilities(ctx, processor)
	if err != nil {
		processor.AddError(err)
		return processor.ToResult(), fmt.Errorf("checking vulnerabilities: %w", err)
	}

	processor.VulnerabilityAnalysis = analysis

	// If no vulnerabilities found, we're done
	if analysis.VulnerabilitiesFound == 0 {
		processor.AddMessage("No vulnerabilities found")
		return processor.ToResult(), nil
	}

	// Apply go/bump changes
	if err := applier.ApplyGoBumpChanges(ctx, processor, analysis); err != nil {
		processor.AddError(err)
		return processor.ToResult(), fmt.Errorf("applying go/bump changes: %w", err)
	}

	// Apply epoch bump if needed
	if processor.EpochChanged {
		if err := processor.ApplyEpochBump(); err != nil {
			processor.AddError(err)
			return processor.ToResult(), fmt.Errorf("applying epoch bump: %w", err)
		}
	}

	// Write file if changes were made
	if processor.HasFileChanges() {
		if err := processor.WriteFile(); err != nil {
			processor.AddError(err)
			return processor.ToResult(), fmt.Errorf("writing file: %w", err)
		}
	}

	return processor.ToResult(), nil
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
				status = "FIXED"
				filesFixed++
				totalVulnsFixed += result.VulnerabilitiesFixed
			} else {
				status = "FOUND"
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
	if verbose {
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
		if strings.HasSuffix(filename, ".yaml") {
			filename = filename[:len(filename)-5]
		}
		return filename
	}
	return "unknown"
}