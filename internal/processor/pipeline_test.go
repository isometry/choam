package processor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock stages for testing

type mockExecutableStage struct {
	BaseStage
	shouldRun     bool
	shouldRunErr  error
	executeErr    error
	executeCalled bool
	executeFunc   func(ctx context.Context, p Processor) error // Custom execute function
}

func (m *mockExecutableStage) ShouldRun(ctx context.Context, p Processor) (bool, error) {
	return m.shouldRun, m.shouldRunErr
}

func (m *mockExecutableStage) Execute(ctx context.Context, p Processor) error {
	m.executeCalled = true
	if m.executeFunc != nil {
		return m.executeFunc(ctx, p)
	}
	return m.executeErr
}

type mockCheckStage struct {
	BaseStage
	shouldRun    bool
	shouldRunErr error
	checkErr     error
	checkCalled  bool
}

func (m *mockCheckStage) ShouldRun(ctx context.Context, p Processor) (bool, error) {
	return m.shouldRun, m.shouldRunErr
}

func (m *mockCheckStage) Check(ctx context.Context, p Processor) error {
	m.checkCalled = true
	return m.checkErr
}

type mockApplyStage struct {
	BaseStage
	shouldRun    bool
	shouldRunErr error
	applyErr     error
	applyCalled  bool
}

func (m *mockApplyStage) ShouldRun(ctx context.Context, p Processor) (bool, error) {
	return m.shouldRun, m.shouldRunErr
}

func (m *mockApplyStage) Apply(ctx context.Context, p Processor) error {
	m.applyCalled = true
	return m.applyErr
}

type mockValidatingStage struct {
	BaseStage
	shouldRun      bool
	validateErr    error
	executeErr     error
	validateCalled bool
	executeCalled  bool
}

func (m *mockValidatingStage) ShouldRun(ctx context.Context, p Processor) (bool, error) {
	return m.shouldRun, nil
}

func (m *mockValidatingStage) Validate(ctx context.Context, p Processor) error {
	m.validateCalled = true
	return m.validateErr
}

func (m *mockValidatingStage) Execute(ctx context.Context, p Processor) error {
	m.executeCalled = true
	return m.executeErr
}

// Mock stage without any execution interface (for error testing)
type mockInvalidStage struct {
	BaseStage
	shouldRun bool
}

func (m *mockInvalidStage) ShouldRun(ctx context.Context, p Processor) (bool, error) {
	return m.shouldRun, nil
}

// Helper function to create test processor
func createTestProcessor() *BaseProcessor {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise in tests
	}))

	proc := NewBaseProcessor("/test/package.yaml", "test-package", "1.0.0", 0)
	proc.Logger = logger
	return proc
}

func TestNewPipeline(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")

	assert.NotNil(t, pipeline)
	assert.Equal(t, "test-pipeline", pipeline.Name)
	assert.NotNil(t, pipeline.Stages)
	assert.Empty(t, pipeline.Stages)
	assert.NotNil(t, pipeline.Registry)
	assert.True(t, pipeline.Options.StopOnError)
	assert.False(t, pipeline.Options.SkipValidation)
}

func TestPipeline_AddStage(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "test-stage"},
		shouldRun: true,
	}

	pipeline.AddStage(stage)

	require.Len(t, pipeline.Stages, 1)
	assert.Equal(t, "test-stage", pipeline.Stages[0].Name())
}

func TestPipeline_AddStages(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage1 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "stage1"},
		shouldRun: true,
	}
	stage2 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "stage2"},
		shouldRun: true,
	}

	pipeline.AddStages(stage1, stage2)

	require.Len(t, pipeline.Stages, 2)
	assert.Equal(t, "stage1", pipeline.Stages[0].Name())
	assert.Equal(t, "stage2", pipeline.Stages[1].Name())
}

func TestPipeline_SetOptions(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	opts := PipelineOptions{
		StopOnError:       false,
		SkipValidation:    true,
		ParallelExecution: true,
	}

	pipeline.SetOptions(opts)

	assert.False(t, pipeline.Options.StopOnError)
	assert.True(t, pipeline.Options.SkipValidation)
	assert.True(t, pipeline.Options.ParallelExecution)
}

func TestPipeline_Execute_EmptyPipeline(t *testing.T) {
	pipeline := NewPipeline("empty-pipeline")
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_SingleExecutableStage(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "test-stage"},
		shouldRun: true,
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.True(t, stage.executeCalled, "Execute should have been called")
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_SingleCheckStage(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockCheckStage{
		BaseStage: BaseStage{StageName: "check-stage"},
		shouldRun: true,
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.True(t, stage.checkCalled, "Check should have been called")
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_SingleApplyStage(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockApplyStage{
		BaseStage: BaseStage{StageName: "apply-stage"},
		shouldRun: true,
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.True(t, stage.applyCalled, "Apply should have been called")
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_MultipleStagesInOrder(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")

	executionOrder := []string{}
	orderMutex := &sync.Mutex{}

	stage1 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "stage1"},
		shouldRun: true,
	}
	stage1.executeFunc = func(ctx context.Context, p Processor) error {
		orderMutex.Lock()
		executionOrder = append(executionOrder, "stage1")
		orderMutex.Unlock()
		return nil
	}

	stage2 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "stage2"},
		shouldRun: true,
	}
	stage2.executeFunc = func(ctx context.Context, p Processor) error {
		orderMutex.Lock()
		executionOrder = append(executionOrder, "stage2")
		orderMutex.Unlock()
		return nil
	}

	stage3 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "stage3"},
		shouldRun: true,
	}
	stage3.executeFunc = func(ctx context.Context, p Processor) error {
		orderMutex.Lock()
		executionOrder = append(executionOrder, "stage3")
		orderMutex.Unlock()
		return nil
	}

	pipeline.AddStages(stage1, stage2, stage3)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.Equal(t, []string{"stage1", "stage2", "stage3"}, executionOrder)
	assert.True(t, stage1.executeCalled)
	assert.True(t, stage2.executeCalled)
	assert.True(t, stage3.executeCalled)
}

func TestPipeline_Execute_StageSkippedWhenShouldRunFalse(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "skipped-stage"},
		shouldRun: false, // Stage should not run
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.False(t, stage.executeCalled, "Execute should not have been called")
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_ShouldRunError_StopOnError(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockExecutableStage{
		BaseStage:    BaseStage{StageName: "error-stage"},
		shouldRun:    true,
		shouldRunErr: errors.New("shouldRun check failed"),
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checking if stage error-stage should run")
	assert.False(t, stage.executeCalled, "Execute should not have been called")
	assert.Len(t, proc.GetErrors(), 1)
}

func TestPipeline_Execute_ShouldRunError_ContinueOnError(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	pipeline.SetOptions(PipelineOptions{StopOnError: false})

	stage1 := &mockExecutableStage{
		BaseStage:    BaseStage{StageName: "error-stage"},
		shouldRun:    true,
		shouldRunErr: errors.New("shouldRun check failed"),
	}
	stage2 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "success-stage"},
		shouldRun: true,
	}

	pipeline.AddStages(stage1, stage2)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err, "Pipeline should complete even with error")
	assert.False(t, stage1.executeCalled)
	assert.True(t, stage2.executeCalled, "Second stage should still execute")
	assert.Len(t, proc.GetErrors(), 1)
}

func TestPipeline_Execute_ExecutionError_StopOnError(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")

	stage1 := &mockExecutableStage{
		BaseStage:  BaseStage{StageName: "error-stage"},
		shouldRun:  true,
		executeErr: errors.New("execution failed"),
	}
	stage2 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "never-runs"},
		shouldRun: true,
	}

	pipeline.AddStages(stage1, stage2)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stage error-stage failed")
	assert.True(t, stage1.executeCalled)
	assert.False(t, stage2.executeCalled, "Second stage should not execute after error")
	assert.Len(t, proc.GetErrors(), 1)
}

func TestPipeline_Execute_ExecutionError_ContinueOnError(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	pipeline.SetOptions(PipelineOptions{StopOnError: false})

	stage1 := &mockExecutableStage{
		BaseStage:  BaseStage{StageName: "error-stage"},
		shouldRun:  true,
		executeErr: errors.New("execution failed"),
	}
	stage2 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "success-stage"},
		shouldRun: true,
	}

	pipeline.AddStages(stage1, stage2)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err, "Pipeline should complete despite error")
	assert.True(t, stage1.executeCalled)
	assert.True(t, stage2.executeCalled, "Second stage should execute despite first stage error")
	assert.Len(t, proc.GetErrors(), 1)
}

func TestPipeline_Execute_ValidatingStage_Success(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockValidatingStage{
		BaseStage: BaseStage{StageName: "validating-stage"},
		shouldRun: true,
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.True(t, stage.validateCalled, "Validate should have been called")
	assert.True(t, stage.executeCalled, "Execute should have been called")
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_ValidatingStage_ValidationError_StopOnError(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockValidatingStage{
		BaseStage:   BaseStage{StageName: "validating-stage"},
		shouldRun:   true,
		validateErr: errors.New("validation failed"),
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validating stage validating-stage")
	assert.True(t, stage.validateCalled)
	assert.False(t, stage.executeCalled, "Execute should not be called after validation failure")
	assert.Len(t, proc.GetErrors(), 1)
}

func TestPipeline_Execute_ValidatingStage_SkipValidation(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	pipeline.SetOptions(PipelineOptions{
		StopOnError:    true,
		SkipValidation: true,
	})

	stage := &mockValidatingStage{
		BaseStage:   BaseStage{StageName: "validating-stage"},
		shouldRun:   true,
		validateErr: errors.New("validation would fail"),
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.False(t, stage.validateCalled, "Validate should not be called when SkipValidation is true")
	assert.True(t, stage.executeCalled, "Execute should be called")
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_ValidatingStage_ValidationError_ContinueOnError(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	pipeline.SetOptions(PipelineOptions{StopOnError: false})

	stage1 := &mockValidatingStage{
		BaseStage:   BaseStage{StageName: "validating-stage-error"},
		shouldRun:   true,
		validateErr: errors.New("validation failed"),
	}
	stage2 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "success-stage"},
		shouldRun: true,
	}

	pipeline.AddStages(stage1, stage2)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err, "Pipeline should complete despite validation error")
	assert.True(t, stage1.validateCalled)
	assert.False(t, stage1.executeCalled, "Execute should not be called after validation failure")
	assert.True(t, stage2.executeCalled, "Second stage should still execute")
	assert.Len(t, proc.GetErrors(), 1)
}

func TestPipeline_Execute_InvalidStage_NoExecutionInterface(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	stage := &mockInvalidStage{
		BaseStage: BaseStage{StageName: "invalid-stage"},
		shouldRun: true,
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not implement any execution interface")
	assert.Len(t, proc.GetErrors(), 1)
}

func TestPipeline_Execute_MixedStageTypes(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")

	execStage := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "exec-stage"},
		shouldRun: true,
	}
	checkStage := &mockCheckStage{
		BaseStage: BaseStage{StageName: "check-stage"},
		shouldRun: true,
	}
	applyStage := &mockApplyStage{
		BaseStage: BaseStage{StageName: "apply-stage"},
		shouldRun: true,
	}

	pipeline.AddStages(execStage, checkStage, applyStage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.True(t, execStage.executeCalled)
	assert.True(t, checkStage.checkCalled)
	assert.True(t, applyStage.applyCalled)
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_MixedSkippedAndRunning(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")

	stage1 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "run-stage"},
		shouldRun: true,
	}
	stage2 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "skip-stage"},
		shouldRun: false, // This stage should be skipped
	}
	stage3 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "run-stage-2"},
		shouldRun: true,
	}

	pipeline.AddStages(stage1, stage2, stage3)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.True(t, stage1.executeCalled)
	assert.False(t, stage2.executeCalled, "Stage 2 should be skipped")
	assert.True(t, stage3.executeCalled)
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_ProcessorChangesTracked(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")

	stage := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "change-stage"},
		shouldRun: true,
	}
	stage.executeFunc = func(ctx context.Context, p Processor) error {
		p.AddChange(Change{
			Type:        "test",
			Field:       "test-field",
			Description: "test change",
		})
		return nil
	}

	pipeline.AddStage(stage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.True(t, proc.HasChanges())
	assert.Len(t, proc.GetChanges(), 1)
	assert.Equal(t, "test", proc.GetChanges()[0].Type)
}

func TestPipeline_Execute_ContextCancellation(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")

	stage := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "context-stage"},
		shouldRun: true,
	}
	stage.executeFunc = func(ctx context.Context, p Processor) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	pipeline.AddStage(stage)
	proc := createTestProcessor()

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := pipeline.Execute(ctx, proc)

	// Context cancellation should propagate through stage execution
	// The stage checks context and should return error
	assert.Error(t, err)
}

func TestPipeline_Execute_ComplexScenario(t *testing.T) {
	// Test a realistic pipeline with multiple stage types, validation, and error handling
	pipeline := NewPipeline("complex-pipeline")

	// Stage 1: Validating stage that succeeds
	valStage := &mockValidatingStage{
		BaseStage: BaseStage{StageName: "validate-inputs"},
		shouldRun: true,
	}

	// Stage 2: Check stage that succeeds
	checkStage := &mockCheckStage{
		BaseStage: BaseStage{StageName: "check-requirements"},
		shouldRun: true,
	}

	// Stage 3: Executable stage that gets skipped
	skipStage := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "optional-stage"},
		shouldRun: false,
	}

	// Stage 4: Apply stage that succeeds
	applyStage := &mockApplyStage{
		BaseStage: BaseStage{StageName: "apply-changes"},
		shouldRun: true,
	}

	pipeline.AddStages(valStage, checkStage, skipStage, applyStage)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err)
	assert.True(t, valStage.validateCalled)
	assert.True(t, valStage.executeCalled)
	assert.True(t, checkStage.checkCalled)
	assert.False(t, skipStage.executeCalled)
	assert.True(t, applyStage.applyCalled)
	assert.Empty(t, proc.GetErrors())
}

func TestPipeline_Execute_ErrorAccumulation_ContinueOnError(t *testing.T) {
	pipeline := NewPipeline("test-pipeline")
	pipeline.SetOptions(PipelineOptions{StopOnError: false})

	// Multiple stages that fail
	stage1 := &mockExecutableStage{
		BaseStage:  BaseStage{StageName: "error-stage-1"},
		shouldRun:  true,
		executeErr: errors.New("error 1"),
	}
	stage2 := &mockExecutableStage{
		BaseStage:  BaseStage{StageName: "error-stage-2"},
		shouldRun:  true,
		executeErr: errors.New("error 2"),
	}
	stage3 := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "success-stage"},
		shouldRun: true,
	}

	pipeline.AddStages(stage1, stage2, stage3)
	proc := createTestProcessor()

	err := pipeline.Execute(context.Background(), proc)

	assert.NoError(t, err, "Pipeline should complete")
	assert.Len(t, proc.GetErrors(), 2, "Should have accumulated 2 errors")
	assert.True(t, stage1.executeCalled)
	assert.True(t, stage2.executeCalled)
	assert.True(t, stage3.executeCalled)
}

// Benchmark tests

func BenchmarkPipeline_Execute_SingleStage(b *testing.B) {
	pipeline := NewPipeline("benchmark-pipeline")
	stage := &mockExecutableStage{
		BaseStage: BaseStage{StageName: "bench-stage"},
		shouldRun: true,
	}
	pipeline.AddStage(stage)
	proc := createTestProcessor()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stage.executeCalled = false
		_ = pipeline.Execute(ctx, proc)
	}
}

func BenchmarkPipeline_Execute_MultipleStages(b *testing.B) {
	pipeline := NewPipeline("benchmark-pipeline")

	for i := range 10 {
		stage := &mockExecutableStage{
			BaseStage: BaseStage{StageName: fmt.Sprintf("stage-%d", i)},
			shouldRun: true,
		}
		pipeline.AddStage(stage)
	}

	proc := createTestProcessor()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pipeline.Execute(ctx, proc)
	}
}
