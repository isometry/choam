package gobump

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

// notBumpableFixtureYAML has no bump/go-bump steps and no go/build or
// cargo/build steps, so ProcessFile hits checkVulnerabilities' "not a
// bumpable project" fast path (stages.go) - no network access and no go
// toolchain required, so this is safe to run in any environment.
const notBumpableFixtureYAML = `package:
  name: not-bumpable
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}
`

// TestProcessFile_LogsCarryFileAttribution is the acceptance test for the
// per-file ctx boundary wired in adapter.go: every log record emitted while
// processing one melange spec file - however deep in the pipeline - must
// carry file= for that spec's path, and never carry it twice (Into replaces,
// not layers - see internal/logging).
func TestProcessFile_LogsCarryFileAttribution(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-bumpable.yaml")
	require.NoError(t, os.WriteFile(filePath, []byte(notBumpableFixtureYAML), 0o644))

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	result, err := ProcessFile(t.Context(), filePath, ProcessorOptions{}, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.NotEmpty(t, lines, "expected at least one log record from a real pipeline run")

	wantFile := "file=" + filePath
	for _, line := range lines {
		assert.Contains(t, line, wantFile, "every record must carry this file's attribution")
		assert.Equal(t, 1, strings.Count(line, "file="), "file= must appear exactly once per record: %s", line)
	}
}

// TestProcessFile_ReadFailureIsAttributed confirms a file that can't even be
// read is still logged with its path - the boundary this attributes BEFORE
// a processor (and its logger) exists.
func TestProcessFile_ReadFailureIsAttributed(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	_, err := ProcessFile(t.Context(), missing, ProcessorOptions{}, nil)

	require.Error(t, err)
	assert.Contains(t, buf.String(), "file="+missing)
}
