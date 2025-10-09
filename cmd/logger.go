package cmd

import (
	"log/slog"
	"os"
)

// InitLogger initializes application-wide structured logging based on verbosity.
//
// Verbosity levels:
//
//	0: Warn  - Only warnings, errors, and command summaries (default)
//	1: Info  - High-level operation progress (-v)
//	2+: Debug - Detailed decision-making and filtering (-vv)
func InitLogger(verbosity int) {
	var level slog.Level
	switch verbosity {
	case 0:
		level = slog.LevelWarn
	case 1:
		level = slog.LevelInfo
	default: // 2+
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)
}
