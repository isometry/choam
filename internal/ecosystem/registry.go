package ecosystem

import (
	"fmt"
	"sort"
)

// registry maps a melange with.language: token to a factory for its
// Ecosystem implementation. Language packages register themselves from
// their own init() (see internal/ecosystem/golang), so this package never
// imports them directly - callers trigger registration with a blank import
// of the language packages they want available.
var registry = make(map[string]func() Ecosystem)

// Register registers a factory for the named ecosystem language token.
func Register(language string, factory func() Ecosystem) {
	registry[language] = factory
}

// New returns the Ecosystem implementation for a melange with.language:
// token ("go", "rust", "java"). The corresponding language package must
// have been blank-imported for its factory to be registered.
func New(language string) (Ecosystem, error) {
	factory, ok := registry[language]
	if !ok {
		return nil, fmt.Errorf("unsupported language: %q", language)
	}
	return factory(), nil
}

// Names returns every registered language token, sorted, so callers can
// enumerate known languages (e.g. to check for a per-language annotation)
// without hardcoding the list themselves.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
