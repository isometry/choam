package anitya

import (
	"encoding/json"
	"fmt"
	"time"
)

// UnixTime represents a Unix timestamp that can be unmarshaled from JSON
type UnixTime time.Time

// UnmarshalJSON implements json.Unmarshaler for UnixTime
func (ut *UnixTime) UnmarshalJSON(data []byte) error {
	var timestamp float64
	if err := json.Unmarshal(data, &timestamp); err != nil {
		return fmt.Errorf("unmarshaling unix timestamp: %w", err)
	}

	*ut = UnixTime(time.Unix(int64(timestamp), 0))
	return nil
}

// Time returns the time.Time representation
func (ut UnixTime) Time() time.Time {
	return time.Time(ut)
}

// Project represents a project from the release-monitoring.org API
type Project struct {
	ID             int      `json:"id"`
	Name           string   `json:"name"`
	Backend        string   `json:"backend"`
	Ecosystem      string   `json:"ecosystem"`
	Homepage       string   `json:"homepage"`
	CreatedOn      UnixTime `json:"created_on"`
	UpdatedOn      UnixTime `json:"updated_on"`
	Version        string   `json:"version"`
	StableVersions []string `json:"stable_versions"`
	Versions       []string `json:"versions"`
}

// ProjectResponse represents the API response structure
type ProjectResponse struct {
	Items      []Project `json:"items"`
	Page       int       `json:"page"`
	ItemsCount int       `json:"items_count"`
	Total      int       `json:"total"`
}
