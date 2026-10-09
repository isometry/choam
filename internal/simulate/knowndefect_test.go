package simulate

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// tb is what a knownDefect body may use: enough for testify's assert and
// require plus logging and the test context. *testing.T satisfies it, so a
// body runs unchanged under assertFixed.
type tb interface {
	require.TestingT
	Helper()
	Logf(format string, args ...any)
	Context() context.Context
}

// defectRecorder collects a knownDefect body's failures instead of failing
// the test. FailNow (testify's require) ends the body goroutine.
type defectRecorder struct {
	t      *testing.T
	mu     sync.Mutex
	failed bool
	errors []string
}

func (r *defectRecorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func (r *defectRecorder) FailNow() {
	r.mu.Lock()
	r.failed = true
	r.mu.Unlock()
	runtime.Goexit()
}

func (r *defectRecorder) Helper()                         {}
func (r *defectRecorder) Logf(format string, args ...any) { r.t.Helper(); r.t.Logf(format, args...) }
func (r *defectRecorder) Context() context.Context        { return r.t.Context() }

// knownDefect runs body, which pins the CORRECT behaviour, in a sub-test and
// requires that it still FAILS: the defect is recorded (logged with its
// failures) without turning the suite red, and the suite does go red the
// moment the defect is fixed without flipping the marker.
//
// To flip a marker once its stage lands, rename the call: knownDefect(...)
// -> assertFixed(...). The body then runs as an ordinary assertion.
func knownDefect(t *testing.T, defect string, body func(t tb)) {
	t.Helper()
	t.Run("known_defect", func(t *testing.T) {
		rec := &defectRecorder{t: t}
		done := make(chan struct{})
		go func() {
			defer close(done)
			body(rec)
		}()
		<-done
		if !rec.failed {
			t.Errorf("known defect appears FIXED - flip knownDefect to assertFixed: %s", defect)
			return
		}
		t.Logf("known defect still present: %s\n  %s", defect, strings.Join(rec.errors, "\n  "))
	})
}

// assertFixed is the flipped form of knownDefect: body runs as an ordinary
// test (the defect label is kept only for the record).
func assertFixed(t *testing.T, _ string, body func(t tb)) {
	t.Helper()
	body(t)
}

// Known defects pinned by the replay tests, named by the plan stage that
// fixes them (see the soft-wondering-kettle plan).
const (
	defectFamilyCoUpdate = "stage4: compile gate cannot move the otel/log v0.21 train together " +
		"(lagging otlploghttp skipped as blamed, trials polluted by unrelated coherence raises); " +
		"family candidates rejected as 'breaks compile'"
	defectRungFallback = "stage4: a CVE candidate whose top fix breaks compile is rejected outright " +
		"instead of relaxing one fix rung (sdk v1.45.0 -> v1.43.0); it stays at baseline"
	defectTrialPollution = "stage4: gate admission trials carry coherence raises for unrelated " +
		"blamed candidates, so an independent compiling fix is rejected"
)

func TestKnownDefectHelper(t *testing.T) {
	// A body that fails is recorded, not propagated.
	knownDefect(t, "helper self-test", func(t tb) {
		require.Equal(t, 1, 2)
	})
	// assertFixed runs the body directly.
	ran := false
	assertFixed(t, "helper self-test", func(t tb) { ran = true })
	require.True(t, ran)
}
