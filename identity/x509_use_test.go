package identity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// identity reads no certificate for a provider's authorization: macula 11.0.0's
// realm issues none. crypto/x509 serves only the PKCS #1 encoding of a
// pq_hybrid key's RSA half, and no non-test file imports encoding/pem.
func TestIdentityUsesX509OnlyForRSAKeyEncodings(t *testing.T) {
	keyEncodings := []string{"MarshalPKCS1PublicKey", "MarshalPKCS1PrivateKey", "ParsePKCS1PublicKey", "ParsePKCS1PrivateKey"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the package's files: %v", err)
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		x509Name := ""
		for _, spec := range parsed.Imports {
			switch path, _ := strconv.Unquote(spec.Path.Value); path {
			case "encoding/pem", "crypto/x509/pkix":
				t.Errorf("%s imports %s", file, path)
			case "crypto/x509":
				x509Name = "x509"
				if spec.Name != nil {
					x509Name = spec.Name.Name
				}
			}
		}
		if x509Name != "" {
			ast.Inspect(parsed, func(node ast.Node) bool {
				selector, isSelector := node.(*ast.SelectorExpr)
				if !isSelector {
					return true
				}
				if pkg, isIdent := selector.X.(*ast.Ident); isIdent && pkg.Name == x509Name && !slices.Contains(keyEncodings, selector.Sel.Name) {
					t.Errorf("%s uses x509.%s, which is not an RSA key encoding", fileSet.Position(selector.Pos()), selector.Sel.Name)
				}
				return true
			})
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no non-test file of package identity was examined")
	}
}
