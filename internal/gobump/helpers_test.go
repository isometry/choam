package gobump

import (
	"testing"
)

// certManagerLikeYAML mirrors the shape of a real multi-modroot package: two
// bump steps whose modroot lists partially overlap ("cmd/b" and "." are
// covered by both), with different dependency sets.
const certManagerLikeYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/bump
    with:
      deps: |-
        github.com/foo/bar@v1.1.1
        golang.org/x/net@v0.55.0
      modroot: |-
        cmd/a
        cmd/b
        .

  - uses: bump
    with:
      deps: |-
        github.com/foo/baz@v2.2.2
        golang.org/x/net@v0.55.0
      modroot: |-
        cmd/b
        .
        test/e2e
`

const singleGoBumpYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/build
    with:
      packages: .

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
`

const noBumpStepYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/build
    with:
      packages: .
`

func newTestProcessor(t *testing.T, yamlContent string) *GoBumpProcessor {
	t.Helper()
	gp := NewGoBumpProcessor("/test/example.yaml", "example", "1.0.0", 0)
	gp.OriginalYAML = []byte(yamlContent)
	gp.SetCurrentYAML([]byte(yamlContent))
	return gp
}

// roots projects analysis units onto their modroots, for assertions that
// only care about which modroots were discovered.
func roots(units []analysisUnit) []string {
	return unitRoots(units)
}
