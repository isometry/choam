// Package logging carries a *slog.Logger through a context.Context, layered
// with attributes (file, package, stage, modroot, ...) as ctx flows deeper
// into a call chain. It is the sole mechanism CHOAM uses to attribute log
// output to the melange spec file being processed: ctx is already threaded
// everywhere for cancellation, so the logger rides along on it rather than
// being passed as a separate parameter or hung off a struct field.
//
// Two invariants matter for correctness:
//
//   - Into REPLACES the logger stored on ctx; it never layers on top of a
//     logger already stored there. slog does not dedupe attribute keys, so
//     stacking a second "file" attribute onto an existing one would emit
//     duplicate "file=" pairs on every record. Use With to add attributes -
//     it reads the current logger, extends it, and replaces via Into in one
//     step.
//   - From resolves slog.Default() lazily, at call time, not at package
//     init or at the time Into was called. Tests routinely swap the default
//     logger via slog.SetDefault mid-run; From must keep observing whichever
//     default is current for any ctx that was never given its own logger.
package logging

import (
	"context"
	"log/slog"

	"github.com/chainguard-dev/clog"
)

type ctxKey struct{}

// Into returns a copy of ctx carrying logger. It replaces any logger
// previously stored on ctx - see the package doc for why layering is unsafe.
func Into(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, logger)
}

// From returns the logger stored on ctx by Into, or slog.Default() if ctx
// carries none. The default is resolved at call time so it tracks any later
// slog.SetDefault.
func From(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && logger != nil {
		return logger
	}
	return slog.Default()
}

// ForFile returns a logger scoped to a melange spec file, for use before a
// processor.Processor (which would normally own this attribution) exists -
// e.g. while reading or parsing the file.
func ForFile(path string) *slog.Logger {
	return slog.Default().With("file", path)
}

// With returns a copy of ctx whose logger has args appended, layering onto
// whatever logger ctx already carries (or slog.Default() if none). This is
// the safe way to add attributes as ctx descends a call chain - see the
// package doc for why calling Into directly with an unrelated logger is not.
func With(ctx context.Context, args ...any) context.Context {
	return Into(ctx, From(ctx).With(args...))
}

// Library returns a copy of ctx carrying a clog logger - the logging facade
// chainguard-dev libraries such as omnibump read from ctx - that writes into
// From(ctx) (so records keep the file/modroot attribution), tagged
// source=name and demoted to Debug: what a library says about one simulated
// apply is diagnostic detail for -vv, not part of the operational stream.
func Library(ctx context.Context, name string) context.Context {
	logger := slog.New(debugHandler{inner: From(ctx).Handler()}).With("source", name)
	return clog.WithLogger(ctx, clog.NewLogger(logger))
}

// debugHandler re-levels every record to Debug before handing it on.
type debugHandler struct{ inner slog.Handler }

func (h debugHandler) Enabled(ctx context.Context, _ slog.Level) bool {
	return h.inner.Enabled(ctx, slog.LevelDebug)
}

func (h debugHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Level = slog.LevelDebug
	return h.inner.Handle(ctx, r)
}

func (h debugHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return debugHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h debugHandler) WithGroup(name string) slog.Handler {
	return debugHandler{inner: h.inner.WithGroup(name)}
}
