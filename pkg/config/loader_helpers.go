package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"
)

// createStringNode creates a simple string AST node with proper indentation
func createStringNode(value string, indentLevel int) *ast.StringNode {
	pos := &token.Position{
		Line:        1,
		Column:      1,
		Offset:      0,
		IndentNum:   indentLevel * 2, // 2 spaces per indent level
		IndentLevel: indentLevel,
	}
	stringToken := token.String(value, value, pos)
	return ast.String(stringToken)
}

// createBlockScalarNode creates an AST LiteralNode for block scalar content (|-)
func createBlockScalarNode(content string, indentLevel int) *ast.LiteralNode {
	// Create separate position instances to avoid pointer sharing
	literalPos := &token.Position{
		Line:        1,
		Column:      1,
		Offset:      0,
		IndentNum:   indentLevel * 2,
		IndentLevel: indentLevel,
	}

	contentPos := &token.Position{
		Line:        2,
		Column:      0,
		Offset:      3,                     // After " |-\n"
		IndentNum:   (indentLevel + 1) * 2, // Content indented one more level
		IndentLevel: indentLevel + 1,
	}

	// Create the literal indicator token for "|-"
	// Origin must include space before and newline after for proper YAML formatting
	literalToken := token.Literal("|-", " |-\n", literalPos)
	literalToken.Type = token.LiteralType
	literalToken.Indicator = token.BlockScalarIndicator

	// Prepare the indented content for Origin
	// Each line needs 8 spaces of indentation to align with YAML structure
	lines := strings.Split(content, "\n")
	indentedLines := make([]string, len(lines))
	for i, line := range lines {
		if line != "" {
			indentedLines[i] = "        " + line // 8 spaces indentation
		} else {
			indentedLines[i] = line // Keep empty lines as-is
		}
	}
	// Add trailing newlines like in the real parsed version
	indentedOrigin := strings.Join(indentedLines, "\n") + "\n\n  "

	// Create the string token
	// Value: raw content without indentation (for programmatic access)
	// Origin: indented content with proper YAML formatting (for String() output)
	stringToken := token.String(content, indentedOrigin, contentPos)

	// Create the string node from the token
	stringNode := ast.String(stringToken)

	// Create and return the literal node
	return &ast.LiteralNode{
		BaseNode: &ast.BaseNode{},
		Start:    literalToken,
		Value:    stringNode,
	}
}

// UpdateFieldWithBlockScalar updates a field to use block scalar format (|-)
func (l *Loader) UpdateFieldWithBlockScalar(yamlContent []byte, path string, newValue string) ([]byte, error) {
	yamlPath, err := yaml.PathString(path)
	if err != nil {
		return nil, fmt.Errorf("creating YAML path %s: %w", path, err)
	}

	// Parse YAML to AST with comments preserved
	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Create the block scalar node
	// For deps field updates, this is typically at indent level 3 (pipeline -> step -> with -> deps)
	blockScalarNode := createBlockScalarNode(newValue, 3)

	// Replace the node at the path with our block scalar node
	err = yamlPath.ReplaceWithNode(file, blockScalarNode)
	if err != nil {
		return nil, fmt.Errorf("replacing field %s with block scalar: %w", path, err)
	}

	// Convert back to bytes with formatting preserved
	return []byte(file.String()), nil
}

// InsertGoBumpPipelineStep inserts a go/bump step with block scalar deps
func (l *Loader) InsertGoBumpPipelineStep(yamlContent []byte, pipelineIndex int, deps []string) ([]byte, error) {
	if len(deps) == 0 {
		// No deps - don't insert anything
		return yamlContent, nil
	}

	// Parse YAML to AST with comments preserved
	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Get the pipeline array
	yamlPath, err := yaml.PathString("$.pipeline")
	if err != nil {
		return nil, fmt.Errorf("creating pipeline path: %w", err)
	}

	node, err := yamlPath.FilterFile(file)
	if err != nil {
		return nil, fmt.Errorf("pipeline not found: %w", err)
	}

	seqNode, ok := node.(*ast.SequenceNode)
	if !ok {
		return nil, fmt.Errorf("pipeline is not a sequence")
	}

	// Check if the original YAML has blank lines between pipeline steps
	hasBlankLinesBetweenSteps := l.detectBlankLinesBetweenPipelineSteps(yamlContent)

	// Create a go/bump step by parsing a template YAML
	stepYaml := `- uses: go/bump
  with:
    deps: |-
      ` + strings.Join(deps, "\n      ")

	// Parse this YAML to get a properly formed AST node
	stepFile, err := parser.ParseBytes([]byte(stepYaml), 0)
	if err != nil {
		return nil, fmt.Errorf("parsing template go/bump step: %w", err)
	}

	// Extract the step node from the parsed YAML
	var stepNode ast.Node
	if len(stepFile.Docs) > 0 {
		if seqNode, ok := stepFile.Docs[0].Body.(*ast.SequenceNode); ok && len(seqNode.Values) > 0 {
			stepNode = seqNode.Values[0]
		} else {
			return nil, fmt.Errorf("unexpected template structure")
		}
	} else {
		return nil, fmt.Errorf("failed to parse template")
	}

	// Insert at the specified position
	if pipelineIndex < 0 {
		pipelineIndex = 0
	}
	if pipelineIndex > len(seqNode.Values) {
		pipelineIndex = len(seqNode.Values)
	}

	// Create new slice with the inserted item
	newValues := make([]ast.Node, 0, len(seqNode.Values)+1)
	newValues = append(newValues, seqNode.Values[:pipelineIndex]...)
	newValues = append(newValues, stepNode)
	newValues = append(newValues, seqNode.Values[pipelineIndex:]...)
	seqNode.Values = newValues

	// Get the AST string representation with formatting preserved
	result := []byte(file.String())

	// If we need to add blank lines, post-process the result to add them
	if hasBlankLinesBetweenSteps {
		result = l.addBlankLineBeforeInsertedStep(result, pipelineIndex)
	}

	return result, nil
}

// detectBlankLinesBetweenPipelineSteps checks if the original YAML has blank lines between pipeline steps
func (l *Loader) detectBlankLinesBetweenPipelineSteps(yamlContent []byte) bool {
	content := string(yamlContent)

	// Look for patterns that indicate blank lines between pipeline steps
	// Pattern: newline, blank line, two spaces, dash, space, "uses:"
	// This matches cases like:
	//   - uses: git-checkout
	//     ...
	//
	//   - uses: go/build
	//     ...

	// Use regex to find blank lines followed by pipeline steps
	// \n\n\s*-\s*uses: matches a blank line followed by a pipeline step
	re := regexp.MustCompile(`\n\n\s*-\s*uses:`)
	return re.MatchString(content)
}

// addBlankLineBeforeInsertedStep adds a blank line before the newly inserted go/bump step
func (l *Loader) addBlankLineBeforeInsertedStep(yamlContent []byte, pipelineIndex int) []byte {
	content := string(yamlContent)

	// Find the newly inserted go/bump step and add a blank line before it
	// Look for the pattern where go/bump follows another step without a blank line
	// We need to find the go/bump step that was just inserted at the specified position

	lines := strings.Split(content, "\n")
	var result []string

	foundGoBump := false
	goBumpLineIndex := -1

	// Find the go/bump step (it should be the first one we encounter after the pipeline start)
	for i, line := range lines {
		if strings.Contains(line, "- uses: go/bump") && !foundGoBump {
			foundGoBump = true
			goBumpLineIndex = i
			break
		}
	}

	if foundGoBump && goBumpLineIndex > 0 {
		// Check if there's already a blank line before the go/bump step
		prevLine := lines[goBumpLineIndex-1]
		if strings.TrimSpace(prevLine) != "" {
			// No blank line before go/bump, so add one
			result = append(result, lines[:goBumpLineIndex]...)
			result = append(result, "") // Add blank line
			result = append(result, lines[goBumpLineIndex:]...)
			return []byte(strings.Join(result, "\n"))
		}
	}

	// No changes needed
	return yamlContent
}
