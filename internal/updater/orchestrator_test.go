package updater

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noUpdateFixtureYAML has update.enabled: false, so ProcessPackageCheck hits
// VersionChecker.Check's fast "Updates disabled" path - no network access
// required, safe to run anywhere.
const noUpdateFixtureYAML = `package:
  name: no-update-example
  version: "1.0.0"
  epoch: 0

update:
  enabled: false
`

// TestProcessPackageCheck_LogsCarryFileAttributionNoDuplicateKeys is a
// regression test: ctx now carries "stage"/"stage_index"/"pipeline" from
// processor.Pipeline.Execute's seeding (see internal/processor/pipeline.go),
// and individual stages (VersionChecker.Check et al.) must read that via
// logging.From(ctx) rather than re-adding their own "stage" layer - doing so
// silently duplicated the key on every record from a real run.
func TestProcessPackageCheck_LogsCarryFileAttributionNoDuplicateKeys(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "no-update.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte(noUpdateFixtureYAML), 0o644))

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	orchestrator := NewOrchestrator()
	proc, err := orchestrator.ProcessPackageCheck(t.Context(), filePath)
	require.NoError(t, err)
	require.NotNil(t, proc)

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.NotEmpty(t, lines, "expected at least one log record from a real pipeline run")

	wantFile := "file=" + filePath
	for _, line := range lines {
		assert.Contains(t, line, wantFile, "every record must carry this file's attribution")
		assert.LessOrEqual(t, strings.Count(line, "stage="), 1, "stage= must not be duplicated: %s", line)
		assert.LessOrEqual(t, strings.Count(line, "pipeline="), 1, "pipeline= must not be duplicated: %s", line)
		assert.Equal(t, 1, strings.Count(line, "file="), "file= must appear exactly once: %s", line)
	}
}
