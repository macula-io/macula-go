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
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the package's files: %v", err)
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		for _, refusal := range x509Refusals(t, file, nil) {
			t.Error(refusal)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no non-test file of package identity was examined")
	}
}

// The scan follows crypto/x509 under its own name and under an alias, and
// refuses a dot import, whose uses no selector names.
func TestTheX509ScanSeesEveryWayToImportTheCertificatePackage(t *testing.T) {
	for _, c := range []struct {
		name    string
		source  string
		refused bool
	}{
		{"a PKCS #1 key encoding", "package p\n\nimport \"crypto/x509\"\n\nvar _ = x509.MarshalPKCS1PublicKey\n", false},
		{"a certificate parsed", "package p\n\nimport \"crypto/x509\"\n\nvar _ = x509.ParseCertificate\n", true},
		{"a certificate parsed through an alias", "package p\n\nimport certificates \"crypto/x509\"\n\nvar _ = certificates.ParseCertificate\n", true},
		{"a dot import", "package p\n\nimport . \"crypto/x509\"\n\nvar _ = MarshalPKCS1PublicKey\n", true},
		{"an import of encoding/pem", "package p\n\nimport \"encoding/pem\"\n\nvar _ = pem.Decode\n", true},
	} {
		if refused := len(x509Refusals(t, "source.go", []byte(c.source))) > 0; refused != c.refused {
			t.Errorf("%s: refused %v, want %v", c.name, refused, c.refused)
		}
	}
}

// x509Refusals parses file, or source when it is not nil, and lists each import
// of encoding/pem or crypto/x509/pkix, a dot import of crypto/x509, and each use
// of crypto/x509 that is not an RSA key encoding.
func x509Refusals(t *testing.T, file string, source []byte) []string {
	t.Helper()
	keyEncodings := []string{"MarshalPKCS1PublicKey", "MarshalPKCS1PrivateKey", "ParsePKCS1PublicKey", "ParsePKCS1PrivateKey"}
	var src any
	if source != nil {
		src = source
	}
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var refusals []string
	x509Name := ""
	for _, spec := range parsed.Imports {
		switch path, _ := strconv.Unquote(spec.Path.Value); path {
		case "encoding/pem", "crypto/x509/pkix":
			refusals = append(refusals, file+" imports "+path)
		case "crypto/x509":
			x509Name = "x509"
			if spec.Name != nil {
				x509Name = spec.Name.Name
			}
			if x509Name == "." {
				refusals = append(refusals, file+" imports crypto/x509 into its own scope, where no selector names its uses")
			}
		}
	}
	if x509Name == "" || x509Name == "." {
		return refusals
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, isSelector := node.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		if pkg, isIdent := selector.X.(*ast.Ident); isIdent && pkg.Name == x509Name && !slices.Contains(keyEncodings, selector.Sel.Name) {
			refusals = append(refusals, fileSet.Position(selector.Pos()).String()+" uses x509."+selector.Sel.Name+", which is not an RSA key encoding")
		}
		return true
	})
	return refusals
}
