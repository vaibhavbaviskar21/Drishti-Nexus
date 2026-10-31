package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvidenceOpenedReadOnly enforces the chain-of-custody guarantee statically:
// every file-opening call in the codebase must either go through OpenEvidence or
// be on the allow-list of known non-evidence writes (reports, audit log,
// databases, generated test data). A new os.Open/OpenFile/Create anywhere else
// fails CI until it is reviewed and either routed through OpenEvidence or listed.
func TestEvidenceOpenedReadOnly(t *testing.T) {
	root := filepath.Join("..", "..")

	// "<repo-relative file>:<call>" → why it is not an evidence access.
	allowed := map[string]string{
		"internal/audit/evidence.go:os.OpenFile": "OpenEvidence itself (O_RDONLY)",
		"internal/audit/audit.go:os.OpenFile":    "audit log, O_APPEND|O_CREATE|O_WRONLY",
		"internal/audit/audit.go:os.Open":        "reading the audit log tail / verify",
		"internal/audit/audit.go:os.ReadFile":    "hashing the config file",
		"internal/storage/export.go:os.OpenFile": "report outputs, guarded by CheckOutputPath",
		"internal/config/config.go:os.ReadFile":  "config file",
		"cmd/genbenign/main.go:os.Create":        "generates synthetic test data",
		"cmd/benchmark/main.go:os.Create":        "CPU profile output",
		"cmd/benchmark/main.go:os.WriteFile":     "benchmark report output",
		"internal/pipeline/follow.go:os.Stat":    "size check only",
		"internal/audit/evidence.go:os.Stat":     "metadata only",
	}
	watched := map[string]bool{
		"Open": true, "OpenFile": true, "Create": true, "WriteFile": true, "ReadFile": true,
		"Truncate": true, "Remove": true, "Rename": true, "Chmod": true,
	}

	var violations []string
	scanned := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == "testdata" || name == ".git" || name == "bin" || strings.HasPrefix(name, ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		scanned++

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" || !watched[sel.Sel.Name] {
				return true
			}
			key := rel + ":os." + sel.Sel.Name
			if _, ok := allowed[key]; !ok {
				violations = append(violations, fset.Position(call.Pos()).String()+" "+key)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 20 {
		t.Fatalf("only %d Go files scanned; the walk is not covering the codebase", scanned)
	}
	for _, v := range violations {
		t.Errorf("unreviewed file access (route evidence through audit.OpenEvidence or add to the allow-list): %s", v)
	}
}
