package output

import (
	"github.com/isometry/choam/internal/gobump"
	"github.com/isometry/choam/internal/updater"
)

// CheckResponse wraps check command results with summary metadata
type CheckResponse struct {
	Results map[string]*updater.UpdateResult `json:"results" yaml:"results"`
	Summary CheckSummary                     `json:"summary" yaml:"summary"`
}

// CheckSummary provides aggregate statistics for check command
type CheckSummary struct {
	TotalPackages    int `json:"total_packages" yaml:"total_packages"`
	UpdatesAvailable int `json:"updates_available" yaml:"updates_available"`
	Errors           int `json:"errors" yaml:"errors"`
	Manual           int `json:"manual" yaml:"manual"`
}

// UpdateResponse wraps update command results with summary metadata
type UpdateResponse struct {
	Results map[string]*updater.ApplyResult `json:"results" yaml:"results"`
	Summary UpdateSummary                   `json:"summary" yaml:"summary"`
}

// UpdateSummary provides aggregate statistics for update command
type UpdateSummary struct {
	TotalPackages     int `json:"total_packages" yaml:"total_packages"`
	SuccessfulUpdates int `json:"successful_updates" yaml:"successful_updates"`
	Errors            int `json:"errors" yaml:"errors"`
	Manual            int `json:"manual" yaml:"manual"`
}

// GoBumpResponse wraps gobump command results with summary metadata
type GoBumpResponse struct {
	Results map[string]*gobump.GoBumpResult `json:"results" yaml:"results"`
	Summary GoBumpSummary                   `json:"summary" yaml:"summary"`
}

// GoBumpSummary provides aggregate statistics for gobump command. Vuln
// counts are advisories; TotalModulesBumped counts changed dependency entries.
type GoBumpSummary struct {
	TotalPackages       int `json:"total_packages" yaml:"total_packages"`
	PackagesWithVulns   int `json:"packages_with_vulns" yaml:"packages_with_vulns"`
	PackagesFixed       int `json:"packages_fixed" yaml:"packages_fixed"`
	PackagesPartial     int `json:"packages_partial" yaml:"packages_partial"`
	PackagesUnvalidated int `json:"packages_unvalidated" yaml:"packages_unvalidated"`
	TotalVulnsFound     int `json:"total_vulns_found" yaml:"total_vulns_found"`
	TotalVulnsFixed     int `json:"total_vulns_fixed" yaml:"total_vulns_fixed"`
	TotalVulnsResidual  int `json:"total_vulns_residual" yaml:"total_vulns_residual"`
	// TotalVulnsUnreachable counts advisories affecting only modules not
	// linked into any build artifact (informational; not fixed, not residual).
	TotalVulnsUnreachable int `json:"total_vulns_unreachable" yaml:"total_vulns_unreachable"`
	TotalModulesBumped    int `json:"total_modules_bumped" yaml:"total_modules_bumped"`
	Errors                int `json:"errors" yaml:"errors"`
}
