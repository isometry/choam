package gobump

import (
	"context"
	"fmt"
	"os"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/processor"
)

// ProcessFile processes a single file using the shared pipeline architecture
func ProcessFile(ctx context.Context, filePath string, opts ProcessorOptions, analyzer *Analyzer) (*GoBumpResult, error) {
	// Read and parse melange file (same as before)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", filePath, err)
	}

	// Parse melange configuration
	cfg, err := melange.ParseConfiguration(ctx, filePath)
	if err != nil {
		return nil, fmt.Errorf("parsing melange configuration: %w", err)
	}

	// Create the new processor with the shared architecture
	goBumpProcessor := NewGoBumpProcessor(filePath, cfg.Package.Name, cfg.Package.Version, int64(cfg.Package.Epoch))
	goBumpProcessor.Config = cfg
	goBumpProcessor.OriginalYAML = content
	goBumpProcessor.SetCurrentYAML(content)
	goBumpProcessor.SetOptions(processor.ProcessorOptions{
		DryRun:        opts.DryRun,
		Force:         false,
		SharedUpdates: false,
		BackupSuffix:  opts.BackupSuffix,
		TempDir:       opts.TempDir,
	})

	// Create and execute the pipeline
	pipeline := NewGoBumpPipeline(analyzer, opts)

	if err := pipeline.Execute(ctx, goBumpProcessor); err != nil {
		goBumpProcessor.AddError(err)
		return goBumpProcessor.ToResult(), fmt.Errorf("pipeline execution failed: %w", err)
	}

	return goBumpProcessor.ToResult(), nil
}
