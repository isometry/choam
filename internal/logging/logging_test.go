package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestFrom_NoLoggerOnContext_ReturnsDefault(t *testing.T) {
	if got := From(context.Background()); got != slog.Default() {
		t.Errorf("From(bare ctx) = %p, want slog.Default() = %p", got, slog.Default())
	}
}

func TestFrom_ResolvesDefaultLazily(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := context.Background()
	first := From(ctx)

	var buf bytes.Buffer
	newDefault := slog.New(slog.NewTextHandler(&buf, nil))
	slog.SetDefault(newDefault)

	second := From(ctx)
	if second != newDefault {
		t.Errorf("From(ctx) after SetDefault = %p, want the new default %p", second, newDefault)
	}
	if first == second {
		t.Errorf("From should re-resolve slog.Default() on every call, not cache it")
	}
}

func TestInto_From_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil)).With("file", "pkg.yaml")

	ctx := Into(context.Background(), logger)
	if got := From(ctx); got != logger {
		t.Errorf("From(Into(ctx, logger)) = %p, want %p", got, logger)
	}

	got := From(ctx)
	got.Info("hello")
	if !strings.Contains(buf.String(), "file=pkg.yaml") {
		t.Errorf("logged record missing file attribute: %s", buf.String())
	}
}

func TestInto_Twice_Replaces(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	first := slog.New(handler).With("file", "a.yaml")
	second := slog.New(handler).With("file", "b.yaml")

	ctx := Into(context.Background(), first)
	ctx = Into(ctx, second)

	got := From(ctx)
	if got != second {
		t.Errorf("From(ctx) after second Into = %p, want the replacement logger %p", got, second)
	}

	got.Info("hello")
	out := buf.String()
	if strings.Count(out, "file=") != 1 {
		t.Errorf("expected exactly one file= attribute, got: %s", out)
	}
	if !strings.Contains(out, "file=b.yaml") {
		t.Errorf("expected file=b.yaml (the replacement), got: %s", out)
	}
}

func TestWith_LayersOntoExistingLogger(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, nil)
	base := slog.New(handler).With("file", "pkg.yaml")

	ctx := Into(context.Background(), base)
	ctx = With(ctx, "stage", "epoch")
	ctx = With(ctx, "stage_index", 3)

	From(ctx).Info("hello")
	out := buf.String()
	for _, want := range []string{"file=pkg.yaml", "stage=epoch", "stage_index=3"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got: %s", want, out)
		}
	}
	if strings.Count(out, "file=") != 1 {
		t.Errorf("expected exactly one file= attribute, got: %s", out)
	}
}

func TestWith_NoExistingLogger_ExtendsDefault(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := With(context.Background(), "file", "pkg.yaml")
	From(ctx).Info("hello")
	if !strings.Contains(buf.String(), "file=pkg.yaml") {
		t.Errorf("expected file=pkg.yaml in output: %s", buf.String())
	}
}

func TestForFile(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ForFile("pkg.yaml").Warn("could not parse")
	if !strings.Contains(buf.String(), "file=pkg.yaml") {
		t.Errorf("ForFile logger missing file attribute: %s", buf.String())
	}
}
