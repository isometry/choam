package utils

import "strings"

// YAMLExtensions contains the valid YAML file extensions
var YAMLExtensions = []string{".yaml", ".yml"}

// IsYAMLFile checks if a filename has a YAML extension
func IsYAMLFile(filename string) bool {
	lowerName := strings.ToLower(filename)
	for _, ext := range YAMLExtensions {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}
