package simulate

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/isometry/choam/internal/logging"
)

// Trial tracing (Debug level only; see logTrial/logRepair). The message
// strings are stable: tests capture these records to assert what each trial
// applied, so later stages that restructure the trials must keep emitting
// them.
const (
	trialLogMsg  = "simulate: trial"
	repairLogMsg = "simulate: repair decision"

	maxTrialLogDiff   = 25 // changed modules listed per trial record
	maxTrialLogErrors = 3  // compile error lines listed per trial record
)

// trialLog describes one trial for logTrial: the pins it applied (in apply
// order), and whichever outcome applies - a resolve/tidy rejection, a
// compile report (gate trials), or a rescan (refinement trials).
type trialLog struct {
	purpose   string
	subject   string // module the trial is about, when it has one (the relaxed bump)
	pins      []*candState
	reject    string
	resolved  map[string]string
	compiled  *trialOutcome
	raises    []raise
	residuals int
}

// pinRole names the provenance a pin carries in the loop, for tracing:
// remedy (ambiguous-import repair), coherence (compile-gate co-update
// repair), cve (advisory-backed), hygiene (scanner hygiene, see hygienePass),
// seed (caller-provided, no advisory), raise.
func pinRole(c *candState) string {
	switch {
	case c.remedy:
		return "remedy"
	case c.repair:
		return "coherence"
	case c.FromCVE:
		return "cve"
	case len(c.hygieneIDs) > 0:
		return "hygiene"
	case c.seed:
		return "seed"
	default:
		return "raise"
	}
}

// trialPin renders a pin as "module@version(role)", replaces as
// "old=module@version(role)".
func trialPin(c *candState) string {
	coord := c.Module + "@" + c.Version
	if c.Replace {
		coord = c.OldPath() + "=" + coord
	}
	return coord + "(" + pinRole(c) + ")"
}

// logTrial emits one structured Debug record per trial: the pins applied
// with their roles, the resolved graph's changes against the pristine
// baseline (capped), and the outcome. It returns immediately when Debug is
// disabled, so the formatting costs nothing on normal runs.
func (l *loop) logTrial(ctx context.Context, tl trialLog) {
	logger := logging.From(ctx)
	if !logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	pins := make([]string, 0, len(tl.pins))
	for _, c := range tl.pins {
		pins = append(pins, trialPin(c))
	}
	attrs := []any{"modroot", l.req.Modroot, "purpose", tl.purpose, "pins", pins}
	if tl.subject != "" {
		attrs = append(attrs, "subject", tl.subject)
	}
	if tl.reject != "" {
		attrs = append(attrs, "outcome", "rejected", "reject", firstLine(tl.reject))
		logger.Debug(trialLogMsg, attrs...)
		return
	}
	if tl.resolved != nil {
		attrs = append(attrs, "resolved_diff", l.resolvedDiff(tl.resolved))
	}
	if st := tl.compiled; st != nil {
		outcome := "compiles"
		if len(st.failures) > 0 {
			outcome = "breaks compile"
		}
		attrs = append(attrs, "outcome", outcome, "failing", len(st.failures))
		if len(st.failures) > 0 {
			attrs = append(attrs, "failing_owners", failingOwners(st), "errors", firstCompileErrors(st.failures, maxTrialLogErrors))
		}
	} else {
		raises := make([]string, 0, len(tl.raises))
		for _, r := range tl.raises {
			raises = append(raises, r.module+"@"+r.version)
		}
		attrs = append(attrs, "outcome", "resolved", "raises", raises, "residuals", tl.residuals)
	}
	logger.Debug(trialLogMsg, attrs...)
}

// resolvedDiff lists the modules whose resolved version differs from the
// pristine baseline graph ("module old->new"; "-" for absent), capped at
// maxTrialLogDiff with a trailing "+N more". The baseline is the compile
// gate's pristine tidied graph when known, else the caller's go.mod view.
func (l *loop) resolvedDiff(resolved map[string]string) []string {
	baseline := l.baselineResolved
	if baseline == nil {
		baseline = l.req.Baseline
	}
	orDash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	var changed []string
	for _, module := range sortedKeys(resolved) {
		if resolved[module] != baseline[module] {
			changed = append(changed, module+" "+orDash(baseline[module])+"->"+resolved[module])
		}
	}
	for _, module := range sortedKeys(baseline) {
		if _, ok := resolved[module]; !ok {
			changed = append(changed, module+" "+baseline[module]+"->-")
		}
	}
	if len(changed) > maxTrialLogDiff {
		more := len(changed) - maxTrialLogDiff
		changed = append(changed[:maxTrialLogDiff], fmt.Sprintf("+%d more", more))
	}
	return changed
}

// failingOwners lists the distinct modules owning a trial's newly failing
// packages ("(main)" for the main module), sorted.
func failingOwners(st *trialOutcome) []string {
	owners := make(map[string]struct{})
	for pkg := range st.failures {
		owner := st.report.Modules[pkg]
		if owner == "" {
			owner = "(main)"
		}
		owners[owner] = struct{}{}
	}
	return sortedKeys(owners)
}

// firstCompileErrors renders up to n compile failures, one line each, in
// package order (see firstCompileError for the line shape).
func firstCompileErrors(failures map[string][]string, n int) []string {
	var lines []string
	for _, pkg := range sortedKeys(failures) {
		if len(lines) == n {
			break
		}
		lines = append(lines, firstCompileError(map[string][]string{pkg: failures[pkg]}))
	}
	return lines
}

// repairLog describes one compile-gate repair decision for logRepair: the
// failing module, its version, the raised dependencies that outgrew it,
// and either the chosen raise (to/source) or the skip reason.
type repairLog struct {
	module, from, to, source string
	outgrown                 map[string]string
	skip                     string
}

// logRepair emits one structured Debug record per repair decision (free
// when Debug is disabled).
func (l *loop) logRepair(ctx context.Context, rl repairLog) {
	logger := logging.From(ctx)
	if !logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	outgrown := make([]string, 0, len(rl.outgrown))
	for _, dep := range sortedKeys(rl.outgrown) {
		outgrown = append(outgrown, dep+"@"+rl.outgrown[dep])
	}
	attrs := []any{"modroot", l.req.Modroot, "module", rl.module, "from", rl.from, "outgrown", outgrown}
	if rl.skip != "" {
		attrs = append(attrs, "decision", "skip", "reason", rl.skip)
	} else {
		attrs = append(attrs, "decision", "raise", "to", rl.to, "source", rl.source)
	}
	logger.Debug(repairLogMsg, attrs...)
}

// firstCompileError renders the first (by package path) compile failure as
// "pkg: file.go:line:col: message", trimming the file's directory.
func firstCompileError(failures map[string][]string) string {
	pkgs := sortedKeys(failures)
	if len(pkgs) == 0 || len(failures[pkgs[0]]) == 0 {
		return "unknown compile error"
	}
	line := failures[pkgs[0]][0]
	if idx := strings.Index(line, ".go:"); idx >= 0 {
		file := line[:idx+len(".go")]
		line = filepath.Base(file) + line[idx+len(".go"):]
	}
	return pkgs[0] + ": " + line
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(text), "\n")
	return line
}
