package stages

import (
	"context"
	"fmt"
	"os"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/isometry/choam/internal/processor"
)

// ValidationStage validates YAML syntax and structure
type ValidationStage struct {
	processor.BaseStage
	ValidateOriginal bool // Also validate original YAML
	ValidateCurrent  bool // Validate current YAML
}

// NewValidationStage creates a new validation stage
func NewValidationStage(validateOriginal, validateCurrent bool) *ValidationStage {
	return &ValidationStage{
		BaseStage: processor.BaseStage{
			StageName:        "validation",
			StageDescription: "Validate YAML syntax and melange configuration",
		},
		ValidateOriginal: validateOriginal,
		ValidateCurrent:  validateCurrent,
	}
}

func (v *ValidationStage) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	// Always run validation if requested
	return v.ValidateOriginal || v.ValidateCurrent, nil
}

func (v *ValidationStage) Apply(ctx context.Context, p processor.Processor) error {
	logger := p.GetLogger().With("stage", v.Name())

	if v.ValidateOriginal {
		if err := v.validateYAML(p.GetOriginalYAML(), "original"); err != nil {
			logger.Error("Original YAML validation failed", "error", err)
			return fmt.Errorf("original YAML validation failed: %w", err)
		}
		logger.Debug("Original YAML validation passed")
	}

	if v.ValidateCurrent {
		if err := v.validateYAML(p.GetCurrentYAML(), "current"); err != nil {
			logger.Error("Current YAML validation failed", "error", err)
			return fmt.Errorf("current YAML validation failed: %w", err)
		}
		logger.Debug("Current YAML validation passed")
	}

	p.AddMessage("YAML validation passed")
	return nil
}

func (v *ValidationStage) validateYAML(yamlContent []byte, label string) error {
	if len(yamlContent) == 0 {
		return fmt.Errorf("%s YAML is empty", label)
	}

	// Try to parse as melange configuration
	tempFile, err := os.CreateTemp("", "validation_*.yaml")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer func() { _ = os.Remove(tempFile.Name()) }()

	if err := os.WriteFile(tempFile.Name(), yamlContent, 0644); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}

	_, err = melange.ParseConfiguration(context.Background(), tempFile.Name())
	if err != nil {
		return fmt.Errorf("parsing melange configuration: %w", err)
	}

	return nil
}
