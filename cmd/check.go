package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aquasecurity/table"
	"github.com/isometry/choam/pkg/updater"
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

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "table", "Output format: table, json")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be checked without making API calls")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	return cmd
}

func runCheck(cmd *cobra.Command, args []string) error {
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
		fmt.Fprintf(os.Stderr, "Found %d melange files to check\n", len(files))
	}

	if dryRun {
		fmt.Println("Dry run mode - would check the following files:")
		for _, file := range files {
			fmt.Printf("  %s\n", file)
		}
		return nil
	}

	// Create updater and load configurations
	u := updater.New()
	u.SetVerbose(verbose)
	configs, err := u.LoadConfigurations(files)
	if err != nil {
		return fmt.Errorf("loading configurations: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Loaded %d configurations\n", len(configs))
	}

	// Check for updates
	results, err := u.CheckUpdates(ctx, configs)
	if err != nil {
		return fmt.Errorf("checking updates: %w", err)
	}

	// Output results
	return outputResults(results, outputFormat)
}

func outputResults(results []*updater.UpdateResult, format string) error {
	switch format {
	case "json":
		return outputJSON(results)
	case "table":
		return outputTable(results)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputJSON(results []*updater.UpdateResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
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
	if verbose {
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