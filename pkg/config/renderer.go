package config

import (
	"fmt"
	"strconv"

	"chainguard.dev/melange/pkg/cond"
	melange "chainguard.dev/melange/pkg/config"
)

// Renderer provides variable rendering for melange configurations
// It builds a complete variable context and can render strings or entire configs
type Renderer struct {
	config      *melange.Configuration
	variableMap map[string]string
}

// NewRenderer creates a new renderer for the given melange configuration
func NewRenderer(cfg *melange.Configuration) (*Renderer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	renderer := &Renderer{
		config: cfg,
	}

	// Build the complete variable map
	if err := renderer.buildVariableMap(); err != nil {
		return nil, fmt.Errorf("building variable map: %w", err)
	}

	return renderer, nil
}

// buildVariableMap constructs a complete map of all available variables
func (r *Renderer) buildVariableMap() error {
	varMap := make(map[string]string)

	// Add standard melange variables
	r.addStandardVariables(varMap)

	// Add user-defined vars from config
	if err := r.addUserVars(varMap); err != nil {
		return fmt.Errorf("adding user vars: %w", err)
	}

	// Apply var-transforms
	if err := r.applyVarTransforms(varMap); err != nil {
		return fmt.Errorf("applying var transforms: %w", err)
	}

	r.variableMap = varMap
	return nil
}

// addStandardVariables adds all standard melange template variables
func (r *Renderer) addStandardVariables(varMap map[string]string) {
	pkg := r.config.Package

	// Package variables
	varMap[melange.SubstitutionPackageName] = pkg.Name
	varMap[melange.SubstitutionPackageVersion] = pkg.Version
	varMap[melange.SubstitutionPackageFullVersion] = pkg.Version
	varMap[melange.SubstitutionPackageEpoch] = strconv.FormatUint(pkg.Epoch, 10)
	varMap[melange.SubstitutionPackageDescription] = pkg.Description

	// Target variables (commonly used defaults)
	// These would normally be set by the build environment, but we provide sensible defaults
	varMap[melange.SubstitutionTargetsDestdir] = "/home/build/melange-out/pkg"
	varMap[melange.SubstitutionTargetsContextdir] = "/home/build/melange-out/ctx"
	varMap[melange.SubstitutionTargetsOutdir] = "/home/build/melange-out"
	varMap[melange.SubstitutionSubPkgDir] = "/home/build/melange-out/subpkg"

	// Build variables (commonly used defaults)
	varMap[melange.SubstitutionBuildArch] = "x86_64"
	varMap[melange.SubstitutionBuildGoArch] = "amd64"

	// Host triplet variables (commonly used defaults)
	varMap[melange.SubstitutionHostTripletGnu] = "x86_64-alpine-linux-musl"
	varMap[melange.SubstitutionHostTripletRust] = "x86_64-alpine-linux-musl"

	// Cross-compilation triplets (defaults)
	varMap[melange.SubstitutionCrossTripletGnuGlibc] = "x86_64-alpine-linux-gnu"
	varMap[melange.SubstitutionCrossTripletGnuMusl] = "x86_64-alpine-linux-musl"
	varMap[melange.SubstitutionCrossTripletRustGlibc] = "x86_64-alpine-linux-gnu"
	varMap[melange.SubstitutionCrossTripletRustMusl] = "x86_64-alpine-linux-musl"

	// Context variables
	varMap[melange.SubstitutionContextName] = pkg.Name
}

// addUserVars adds user-defined variables from the config
func (r *Renderer) addUserVars(varMap map[string]string) error {
	// Use melange's native method to get vars
	configVars, err := r.config.GetVarsFromConfig()
	if err != nil {
		return fmt.Errorf("getting vars from config: %w", err)
	}

	// Add all user vars to our map
	for key, value := range configVars {
		// Resolve any variables in the value itself
		resolved, err := cond.Subst(value, r.createLookupFunc(varMap))
		if err != nil {
			// If substitution fails, use the original value
			resolved = value
		}
		varMap[key] = resolved
	}

	return nil
}

// applyVarTransforms applies var-transforms to create derived variables
func (r *Renderer) applyVarTransforms(varMap map[string]string) error {
	// Use melange's native method to apply transforms
	return r.config.PerformVarSubstitutions(varMap)
}

// createLookupFunc creates a VariableLookupFunction that can resolve variables from our map
func (r *Renderer) createLookupFunc(varMap map[string]string) cond.VariableLookupFunction {
	return func(key string) (string, error) {
		// Try direct key lookup
		if value, exists := varMap[key]; exists {
			return value, nil
		}

		// Try with ${{}} wrapper
		wrappedKey := fmt.Sprintf("${{%s}}", key)
		if value, exists := varMap[wrappedKey]; exists {
			return value, nil
		}

		return "", fmt.Errorf("variable %q not defined", key)
	}
}

// RenderString renders a template string with full variable substitution
func (r *Renderer) RenderString(template string) (string, error) {
	if template == "" {
		return "", nil
	}

	lookupFunc := r.createLookupFunc(r.variableMap)
	result, err := cond.Subst(template, lookupFunc)
	if err != nil {
		return "", fmt.Errorf("rendering template %q: %w", template, err)
	}

	return result, nil
}

// GetVariableMap returns a copy of the complete variable map
func (r *Renderer) GetVariableMap() map[string]string {
	result := make(map[string]string, len(r.variableMap))
	for k, v := range r.variableMap {
		result[k] = v
	}
	return result
}

// GetVariable gets the value of a specific variable
func (r *Renderer) GetVariable(key string) (string, bool) {
	// Try direct key
	if value, exists := r.variableMap[key]; exists {
		return value, true
	}

	// Try with ${{}} wrapper
	wrappedKey := fmt.Sprintf("${{%s}}", key)
	if value, exists := r.variableMap[wrappedKey]; exists {
		return value, true
	}

	return "", false
}

// RenderConfig creates a new configuration with all variables resolved
// This is useful when you need a fully rendered config for processing
func (r *Renderer) RenderConfig() (*melange.Configuration, error) {
	// For now, we'll focus on RenderString as it's the primary need
	// Full config rendering would be more complex and may not be immediately needed
	return nil, fmt.Errorf("full config rendering not implemented yet - use RenderString for specific fields")
}
