// Package gobump is the bump orchestration for all ecosystems: vulnerability
// analysis per language and modroot, reconciling each language's bump
// pipeline steps, results, epoch and the pipeline plumbing.
//
// Some stages and helpers are Go-only and named as such: the simulation
// (go_simulate.go), the stdlib staleness check (go_stdlib*.go), go-package
// pins (go_pin.go, go_pin_stage.go), the best-effort go-version fallback
// (go_version_fallback.go, go_fallback_stage.go), `go/bump` step editing and
// its migration to `uses: bump` (go_step.go, go_migrate.go) and Go unit
// discovery (go_discovery.go). The generic code reaches them only through
// those stages and the seams they name (goStepRewrite, goUnitDetails).
package gobump
