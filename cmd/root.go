package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var yamlExtensions = []string{".yaml", ".yml"}

var (
	// Common flags shared across commands
	outputFormat string
	dryRun       bool
	verbosity    int
	force        bool

	// Update-specific flags
	updateShared bool
	backupSuffix string
)

// NewRootCmd creates the root command
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "choam",
		Short: "A CLI tool for detecting available updates in melange build specifications",
		Long: `CHOAM checks for available updates in melange build specification files,
respecting the update configuration schema and integrating with GitHub, Git,
and release-monitoring.org.`,
		SilenceUsage: true,
	}

	// Global flags available to all subcommands
	cmd.PersistentFlags().CountVarP(&verbosity, "verbose", "v", "Increase verbosity: -v (info), -vv (debug)")

	cmd.AddCommand(NewCheckCmd())
	cmd.AddCommand(NewUpdateCmd())
	cmd.AddCommand(NewGoBumpCmd())

	return cmd
}

// isYAMLFile checks if a filename has a YAML extension
func isYAMLFile(filename string) bool {
	lowerName := strings.ToLower(filename)
	for _, ext := range yamlExtensions {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}

// collectMelangeFiles collects all YAML files from the provided paths
func collectMelangeFiles(paths []string) ([]string, error) {
	var files []string

	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("checking path %s: %w", path, err)
		}

		if stat.IsDir() {
			// Walk directory and collect .yaml files
			dirFiles, err := collectFromDirectory(path)
			if err != nil {
				return nil, fmt.Errorf("collecting from directory %s: %w", path, err)
			}
			files = append(files, dirFiles...)
		} else {
			// Single file
			if isYAMLFile(path) {
				files = append(files, path)
			}
		}
	}

	return files, nil
}

// collectFromDirectory collects YAML files from a directory
func collectFromDirectory(dir string) ([]string, error) {
	var files []string

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if isYAMLFile(name) {
			fullPath := filepath.Join(dir, name)
			files = append(files, fullPath)
		}
	}

	return files, nil
}

// truncate truncates a string to the specified length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
