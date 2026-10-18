// Command specpatch reads openapi.yaml on stdin and writes it to stdout with
// the minimum fixes oapi-codegen needs to accept it, printing each fix to
// stderr. Every rule only fires while the spec still has the defect, so a
// fixed spec passes through untouched. Each printed line is a spec bug to
// report to Wavvon-docs.
package main

import (
	"fmt"
	"io"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

var placeholder = regexp.MustCompile(`\{([^}]+)\}`)

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(in, &doc); err != nil {
		fail(err)
	}
	root := doc.Content[0]
	if paths := get(root, "paths"); paths != nil {
		for i := 0; i < len(paths.Content); i += 2 {
			patchPath(paths.Content[i].Value, paths.Content[i+1])
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		fail(err)
	}
	os.Stdout.Write(out)
}

// patchPath drops path parameters the template does not contain: the
// generator refuses a parameter it cannot place.
func patchPath(path string, item *yaml.Node) {
	inTemplate := map[string]bool{}
	for _, m := range placeholder.FindAllStringSubmatch(path, -1) {
		inTemplate[m[1]] = true
	}
	for i := 0; i < len(item.Content); i += 2 {
		method, op := item.Content[i].Value, item.Content[i+1]
		params := get(op, "parameters")
		if params == nil {
			continue
		}
		kept := params.Content[:0]
		for _, p := range params.Content {
			in, name := scalar(p, "in"), scalar(p, "name")
			if in == "path" && !inTemplate[name] {
				fmt.Fprintf(os.Stderr, "specpatch: %s %s declares path parameter %q that the path does not contain; dropped\n", method, path, name)
				continue
			}
			kept = append(kept, p)
		}
		params.Content = kept
	}
}

func get(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(m *yaml.Node, key string) string {
	if n := get(m, key); n != nil {
		return n.Value
	}
	return ""
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "specpatch:", err)
	os.Exit(1)
}
