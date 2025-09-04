package updater

import (
	"log/slog"
	"os"
)

// InitLogger initializes the default slog logger with the appropriate level
// based on the verbose flag. This should be called once at the start of
// update operations to configure logging for the entire pipeline.
func InitLogger(verbose bool) {
	var level slog.Level
	if verbose {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}

	// Create a text handler that writes to stderr for better debugging
	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}
