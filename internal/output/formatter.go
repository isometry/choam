package output

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

// OutputJSON writes data as formatted JSON to the given writer
func OutputJSON(w io.Writer, data interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// OutputYAML writes data as formatted YAML to the given writer
func OutputYAML(w io.Writer, data interface{}) error {
	bytes, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	_, err = w.Write(bytes)
	return err
}

// ExtractFilename extracts the filename (with extension) from a full file path
func ExtractFilename(path string) string {
	return filepath.Base(path)
}
