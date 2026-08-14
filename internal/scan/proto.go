package scan

import "google.golang.org/protobuf/types/known/structpb"

// structAsMap converts a protobuf Struct to a plain map, preserving the
// nil-means-absent distinction (AsMap on a nil Struct would return an
// empty, non-nil map).
func structAsMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// stringField extracts a top-level string field from a Struct; returns ""
// when the struct is nil, the key is absent, or the value is not a string.
func stringField(s *structpb.Struct, key string) string {
	return s.GetFields()[key].GetStringValue()
}
