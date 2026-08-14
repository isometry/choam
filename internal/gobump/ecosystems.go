package gobump

// Blank-import every ecosystem.Ecosystem implementation so their init()
// functions register themselves with internal/ecosystem's registry.
import (
	_ "github.com/isometry/choam/internal/ecosystem/golang"
	_ "github.com/isometry/choam/internal/ecosystem/java"
	_ "github.com/isometry/choam/internal/ecosystem/rust"
)
