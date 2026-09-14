// Command nestcheck prints each function whose control-flow nesting is deeper
// than a limit, counting if, for, range, switch, type switch and select
// bodies, with an else branch at its if's own level and function literals
// not resetting the count.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const limit = 2

func main() {
	root := os.Args[1]
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range f.Decls {
			report(fset, rel, decl)
		}
		return nil
	})
}

func report(fset *token.FileSet, rel string, decl ast.Decl) {
	fd, ok := decl.(*ast.FuncDecl)
	if !ok || fd.Body == nil {
		return
	}
	depth, at := deepest(fd.Body, 0)
	if depth > limit {
		fmt.Printf("%s\t%s\t%d\t%d\n", rel, funcName(fd), depth, fset.Position(at).Line)
	}
}

func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return fmt.Sprintf("%s.%s", recvName(fd.Recv.List[0].Type), fd.Name.Name)
}

func recvName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

// deepest is the deepest nesting level reached inside n, which sits at level.
func deepest(n ast.Node, level int) (int, token.Pos) {
	best, at := level, n.Pos()
	ast.Inspect(n, func(c ast.Node) bool {
		if c == nil {
			return false
		}
		if c == n {
			return true
		}
		d, p, descend := nested(c, level)
		if d > best {
			best, at = d, p
		}
		return descend
	})
	return best, at
}

// nested is the deepest level reached through c when c is a control
// statement at level, and whether Inspect should go on into c itself.
func nested(c ast.Node, level int) (int, token.Pos, bool) {
	switch s := c.(type) {
	case *ast.IfStmt:
		return ifDepth(s, level)
	case *ast.ForStmt:
		d, p := deepest(s.Body, level+1)
		return d, p, false
	case *ast.RangeStmt:
		d, p := deepest(s.Body, level+1)
		return d, p, false
	case *ast.SwitchStmt:
		d, p := deepest(s.Body, level+1)
		return d, p, false
	case *ast.TypeSwitchStmt:
		d, p := deepest(s.Body, level+1)
		return d, p, false
	case *ast.SelectStmt:
		d, p := deepest(s.Body, level+1)
		return d, p, false
	}
	return level, c.Pos(), true
}

func ifDepth(s *ast.IfStmt, level int) (int, token.Pos, bool) {
	best, at := deepest(s.Body, level+1)
	if s.Else == nil {
		return best, at, false
	}
	d, p := elseDepth(s.Else, level)
	if d > best {
		best, at = d, p
	}
	return best, at, false
}

func elseDepth(e ast.Stmt, level int) (int, token.Pos) {
	if chained, ok := e.(*ast.IfStmt); ok {
		d, p, _ := ifDepth(chained, level)
		return d, p
	}
	return deepest(e, level+1)
}
