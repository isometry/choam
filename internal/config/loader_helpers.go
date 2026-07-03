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

// createQuotedStringNode creates a double-quoted string AST node
// This ensures the value is always rendered with quotes, preventing YAML from
// interpreting numeric-looking strings (like "1.0") as numbers
func createQuotedStringNode(value string, indentLevel int) *ast.StringNode {
	pos := &token.Position{
		Line:        1,
		Column:      1,
		Offset:      0,
		IndentNum:   indentLevel * 2, // 2 spaces per indent level
		IndentLevel: indentLevel,
	}
	// Create token with double quotes in the origin
	quotedValue := `"` + value + `"`
	stringToken := token.String(value, quotedValue, pos)
	stringToken.Type = token.DoubleQuoteType
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

// removeSequenceValue removes the value at index from a sequence node, keeping
// ValueHeadComments in sync with Values. goccy/go-yaml's block-style renderer
// only emits head comments when len(ValueHeadComments) == len(Values); letting
// them drift out of sync silently drops every comment (and blank line, which
// is represented the same way) in the whole sequence, not just around index.
func removeSequenceValue(seqNode *ast.SequenceNode, index int) {
	syncComments := len(seqNode.ValueHeadComments) == len(seqNode.Values)

	newValues := make([]ast.Node, 0, len(seqNode.Values)-1)
	var newComments []*ast.CommentGroupNode
	if syncComments {
		newComments = make([]*ast.CommentGroupNode, 0, len(seqNode.ValueHeadComments)-1)
	}
	for i, value := range seqNode.Values {
		if i == index {
			continue
		}
		newValues = append(newValues, value)
		if syncComments {
			newComments = append(newComments, seqNode.ValueHeadComments[i])
		}
	}

	seqNode.Values = newValues
	if syncComments {
		seqNode.ValueHeadComments = newComments
	}
}

// insertSequenceValue inserts value at index into a sequence node, keeping
// ValueHeadComments in sync with Values (see removeSequenceValue). index is
// clamped to [0, len(Values)].
func insertSequenceValue(seqNode *ast.SequenceNode, index int, value ast.Node) {
	if index < 0 {
		index = 0
	}
	if index > len(seqNode.Values) {
		index = len(seqNode.Values)
	}

	syncComments := len(seqNode.ValueHeadComments) == len(seqNode.Values)
	if syncComments {
		newComments := make([]*ast.CommentGroupNode, 0, len(seqNode.ValueHeadComments)+1)
		newComments = append(newComments, seqNode.ValueHeadComments[:index]...)
		newComments = append(newComments, nil)
		newComments = append(newComments, seqNode.ValueHeadComments[index:]...)
		seqNode.ValueHeadComments = newComments
	}

	newValues := make([]ast.Node, 0, len(seqNode.Values)+1)
	newValues = append(newValues, seqNode.Values[:index]...)
	newValues = append(newValues, value)
	newValues = append(newValues, seqNode.Values[index:]...)
	seqNode.Values = newValues
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

// UpsertPipelineWithBlockScalar sets a pipeline step's with.<field> to a
// block scalar (|-) value, creating the field when it doesn't exist yet.
// UpdateFieldWithBlockScalar alone can't create fields (yamlPath.
// ReplaceWithNode fails on a missing path), and goccy's renderer does not
// reliably emit AST nodes appended to an existing mapping - so the append
// case locates the end of the with block via the AST and splices correctly
// indented lines into the source text directly.
func (l *Loader) UpsertPipelineWithBlockScalar(yamlContent []byte, pipelineIndex int, field, value string) ([]byte, error) {
	// ReplaceWithNode is a silent no-op on a missing path, so probe field
	// existence explicitly rather than relying on an error.
	withFields, err := l.GetPipelineWithField(yamlContent, pipelineIndex)
	if err != nil {
		return nil, fmt.Errorf("getting pipeline[%d] with fields: %w", pipelineIndex, err)
	}
	if _, exists := withFields[field]; exists {
		path := fmt.Sprintf("$.pipeline[%d].with.%s", pipelineIndex, field)
		return l.UpdateFieldWithBlockScalar(yamlContent, path, value)
	}

	// Field absent - splice it in after the with block's last line.
	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	withPath, err := yaml.PathString(fmt.Sprintf("$.pipeline[%d].with", pipelineIndex))
	if err != nil {
		return nil, fmt.Errorf("creating with path: %w", err)
	}
	node, err := withPath.FilterFile(file)
	if err != nil {
		return nil, fmt.Errorf("pipeline[%d] has no with block: %w", pipelineIndex, err)
	}
	mapping, ok := node.(*ast.MappingNode)
	if !ok || len(mapping.Values) == 0 {
		return nil, fmt.Errorf("pipeline[%d] with block is not a non-empty mapping", pipelineIndex)
	}

	keyColumn := mapping.Values[0].Key.GetToken().Position.Column // 1-based
	keyIndent := strings.Repeat(" ", keyColumn-1)
	endLine := nodeEndLine(mapping) // 1-based line of the block's last content

	inserted := []string{keyIndent + field + ": |-"}
	for _, line := range strings.Split(value, "\n") {
		inserted = append(inserted, keyIndent+"  "+line)
	}

	lines := strings.Split(string(yamlContent), "\n")
	if endLine > len(lines) {
		endLine = len(lines)
	}
	result := make([]string, 0, len(lines)+len(inserted))
	result = append(result, lines[:endLine]...)
	result = append(result, inserted...)
	result = append(result, lines[endLine:]...)

	return []byte(strings.Join(result, "\n")), nil
}

// nodeEndLine returns the last (1-based) source line covered by node,
// accounting for multi-line token origins (block scalars).
func nodeEndLine(node ast.Node) int {
	visitor := &endLineVisitor{}
	ast.Walk(visitor, node)
	return visitor.maxLine
}

type endLineVisitor struct {
	maxLine int
}

func (v *endLineVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return v
	}
	if tk := node.GetToken(); tk != nil && tk.Position != nil {
		// Token origins can carry trailing blank lines plus the next
		// token's indentation (e.g. "...\n\n  ") - trim all trailing
		// whitespace so only the token's own content lines are counted.
		end := tk.Position.Line + strings.Count(strings.TrimRight(tk.Origin, " \t\n"), "\n")
		if end > v.maxLine {
			v.maxLine = end
		}
	}
	return v
}

// UpdateFieldAsQuotedString updates a field with a double-quoted string value
// This is essential for fields like package.version where values like "1.0" must
// be rendered as strings to prevent YAML from interpreting them as numbers
func (l *Loader) UpdateFieldAsQuotedString(yamlContent []byte, path string, newValue string) ([]byte, error) {
	yamlPath, err := yaml.PathString(path)
	if err != nil {
		return nil, fmt.Errorf("creating YAML path %s: %w", path, err)
	}

	// Parse YAML to AST with comments preserved
	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	// Create a quoted string node
	// For package.version, this is typically at indent level 1 (package -> version)
	quotedStringNode := createQuotedStringNode(newValue, 1)

	// Replace the node at the path with our quoted string node
	err = yamlPath.ReplaceWithNode(file, quotedStringNode)
	if err != nil {
		return nil, fmt.Errorf("replacing field %s with quoted string: %w", path, err)
	}

	// Convert back to bytes with formatting preserved
	return []byte(file.String()), nil
}

// InsertBumpPipelineStep inserts a bump or go/bump step with block-scalar deps
// and replaces lists and, for multi-root bumps, a block-scalar modroot list.
// blankLineBetweenSteps says whether the file's convention separates pipeline
// steps with a blank line (see HasBlankLinesBetweenPipelineSteps) - it's the
// caller's to supply because yamlContent may already have had steps removed,
// leaving nothing to detect the original convention from.
func (l *Loader) InsertBumpPipelineStep(yamlContent []byte, pipelineIndex int, action, language string, modroots, deps, replaces []string, blankLineBetweenSteps bool) ([]byte, error) {
	if len(deps) == 0 && len(replaces) == 0 {
		// Nothing to declare - don't insert anything
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

	// Create the step by parsing a template YAML. A single "." modroot is
	// omitted since it's the pipeline's own default. language is written
	// explicitly (rather than relying on the pipeline's own "auto" detection
	// at build time) since the caller already knows definitively which
	// language it analyzed.
	stepYaml := "- uses: " + action + "\n  with:"
	if len(deps) > 0 {
		stepYaml += "\n    deps: |-\n      " + strings.Join(deps, "\n      ")
	}
	if len(replaces) > 0 {
		stepYaml += "\n    replaces: |-\n      " + strings.Join(replaces, "\n      ")
	}
	if language != "" {
		stepYaml += "\n    language: " + language
	}
	if len(modroots) > 0 && (len(modroots) != 1 || modroots[0] != ".") {
		stepYaml += "\n    modroot: |-\n      " + strings.Join(modroots, "\n      ")
	}

	// Parse this YAML to get a properly formed AST node
	stepFile, err := parser.ParseBytes([]byte(stepYaml), 0)
	if err != nil {
		return nil, fmt.Errorf("parsing template %s step: %w", action, err)
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

	// Insert the new step, keeping any comments on the surrounding steps intact
	insertSequenceValue(seqNode, pipelineIndex, stepNode)

	// Get the AST string representation with formatting preserved
	result := []byte(file.String())

	// If the file's convention separates steps with blank lines, give the
	// freshly inserted step one too
	if blankLineBetweenSteps {
		result = l.ensureBlankLineBeforePipelineStep(result, pipelineIndex)
	}

	return result, nil
}

// HasBlankLinesBetweenPipelineSteps reports whether the YAML separates
// pipeline steps with blank lines. Callers that remove steps before
// re-inserting must capture this from the ORIGINAL content - a stripped
// pipeline may no longer have two adjacent steps to detect the convention from.
func (l *Loader) HasBlankLinesBetweenPipelineSteps(yamlContent []byte) bool {
	// \n\n\s*-\s*uses: matches a blank line followed by a pipeline step
	re := regexp.MustCompile(`\n\n\s*-\s*uses:`)
	return re.MatchString(string(yamlContent))
}

// ensureBlankLineBeforePipelineStep splices one blank line before the
// pipeline step at pipelineIndex when the preceding line is non-blank. The
// step is located by re-parsing yamlContent and reading the node's (1-based)
// source line, so repeated insertions each fix up their own step rather than
// whichever similar-looking step appears first in the file. Formatting is
// cosmetic: any failure returns the input unchanged, never an error.
func (l *Loader) ensureBlankLineBeforePipelineStep(yamlContent []byte, pipelineIndex int) []byte {
	if pipelineIndex <= 0 {
		return yamlContent // first step - nothing above it to separate from
	}

	file, err := parser.ParseBytes(yamlContent, parser.ParseComments)
	if err != nil {
		return yamlContent
	}
	yamlPath, err := yaml.PathString(fmt.Sprintf("$.pipeline[%d]", pipelineIndex))
	if err != nil {
		return yamlContent
	}
	node, err := yamlPath.FilterFile(file)
	if err != nil {
		return yamlContent
	}

	token := node.GetToken()
	if token == nil || token.Position == nil {
		return yamlContent
	}
	line := token.Position.Line // 1-based

	lines := strings.Split(string(yamlContent), "\n")
	if line < 2 || line > len(lines) {
		return yamlContent
	}
	if strings.TrimSpace(lines[line-2]) == "" {
		return yamlContent // already separated
	}

	spliced := make([]string, 0, len(lines)+1)
	spliced = append(spliced, lines[:line-1]...)
	spliced = append(spliced, "")
	spliced = append(spliced, lines[line-1:]...)
	return []byte(strings.Join(spliced, "\n"))
}
