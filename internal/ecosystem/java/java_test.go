package java

import (
	"context"
	"testing"

	"github.com/isometry/choam/internal/ecosystem"
	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pomFixture = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>example</artifactId>
  <version>1.0.0</version>

  <properties>
    <netty.version>4.1.94.Final</netty.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>io.netty</groupId>
      <artifactId>netty-codec-http</artifactId>
      <version>${netty.version}</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>unresolved-parent-prop</artifactId>
      <version>${parent.only.version}</version>
    </dependency>
  </dependencies>
</project>
`

func TestEcosystem_Analyze(t *testing.T) {
	eco := New()

	deps, err := eco.Analyze(context.Background(), map[string][]byte{"pom.xml": []byte(pomFixture)})
	require.NoError(t, err)
	require.NotNil(t, deps)

	byCoord := make(map[string]ecosystem.Dep, len(deps.Deps))
	for _, dep := range deps.Deps {
		byCoord[dep.Coord] = dep
	}

	// Property-resolved version.
	netty, ok := byCoord["io.netty:netty-codec-http"]
	require.True(t, ok, "expected io.netty:netty-codec-http in analyzed deps")
	assert.Equal(t, "4.1.94.Final", netty.Version)
	assert.Equal(t, "io.netty", netty.GroupID)
	assert.Equal(t, "netty-codec-http", netty.ArtifactID)

	// Plain literal version.
	junit, ok := byCoord["junit:junit"]
	require.True(t, ok, "expected junit:junit in analyzed deps")
	assert.Equal(t, "4.13.2", junit.Version)

	// Property defined only in an unfetched parent POM - must be skipped,
	// never scanned as a literal "${...}" string.
	_, unresolved := byCoord["com.example:unresolved-parent-prop"]
	assert.False(t, unresolved, "dependency with an unresolvable property must be skipped")
}

func TestEcosystem_Analyze_MissingPom(t *testing.T) {
	eco := New()
	_, err := eco.Analyze(context.Background(), map[string][]byte{})
	require.Error(t, err)
}

func TestEcosystem_ScanPackages(t *testing.T) {
	eco := New()
	deps := &ecosystem.ModuleDeps{
		Deps: []ecosystem.Dep{
			{Coord: "io.netty:netty-codec-http", Name: "io.netty:netty-codec-http", Version: "4.1.94.Final"},
			{Coord: "junit:junit", Name: "junit:junit", Version: ""}, // unresolved - excluded from scan
		},
	}

	pkgs := eco.ScanPackages(t.Context(), deps)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "io.netty:netty-codec-http", pkgs[0].Name)
	assert.Equal(t, "Maven", pkgs[0].Ecosystem)
}

func TestEcosystem_FilterBumps(t *testing.T) {
	eco := New()
	deps := &ecosystem.ModuleDeps{
		Deps: []ecosystem.Dep{
			{Coord: "io.netty:netty-codec-http", Name: "io.netty:netty-codec-http", GroupID: "io.netty", ArtifactID: "netty-codec-http", Version: "4.1.90.Final"},
		},
	}

	t.Run("keeps bump newer than current, rendered as groupId@artifactId@version", func(t *testing.T) {
		result := eco.FilterBumps(context.Background(), nil, []scan.SecurityBump{
			{Name: "io.netty:netty-codec-http", FixedVersion: "4.1.94.Final"},
		}, deps)
		assert.Equal(t, []string{"io.netty@netty-codec-http@4.1.94.Final"}, result)
	})

	t.Run("drops bump for coordinate absent from pom.xml", func(t *testing.T) {
		result := eco.FilterBumps(context.Background(), nil, []scan.SecurityBump{
			{Name: "com.example:not-present", FixedVersion: "1.0.0"},
		}, deps)
		assert.Empty(t, result)
	})

	t.Run("existing 3-part entries parsed and re-filtered", func(t *testing.T) {
		result := eco.FilterBumps(context.Background(), []string{"io.netty@netty-codec-http@4.1.92.Final"}, nil, deps)
		assert.Equal(t, []string{"io.netty@netty-codec-http@4.1.92.Final"}, result)
	})
}

func TestEcosystem_BumpCoords(t *testing.T) {
	eco := New()
	deps := &ecosystem.ModuleDeps{
		Deps: []ecosystem.Dep{
			{Coord: "io.netty:netty-codec-http", Name: "io.netty:netty-codec-http", GroupID: "io.netty", ArtifactID: "netty-codec-http", Version: "4.1.90.Final"},
		},
	}

	t.Run("colon OSV name maps to rendered groupId@artifactId via pom entry", func(t *testing.T) {
		bump := scan.SecurityBump{Name: "io.netty:netty-codec-http", FixedVersion: "4.1.94.Final", VulnIDs: []string{"GHSA-xxxx"}}
		coords := eco.BumpCoords(t.Context(), []scan.SecurityBump{bump}, deps)
		require.Len(t, coords, 1)
		assert.Equal(t, bump, coords["io.netty@netty-codec-http"])
	})

	t.Run("coordinate absent from pom falls back to colon substitution", func(t *testing.T) {
		coords := eco.BumpCoords(t.Context(), []scan.SecurityBump{
			{Name: "com.example:not-present", FixedVersion: "1.0.0"},
		}, deps)
		require.Len(t, coords, 1)
		assert.Contains(t, coords, "com.example@not-present")
	})
}
