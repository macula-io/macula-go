package record

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

// macula 11.0.0 authorizes a provider only through an org directory and a
// procedure delegation, and its realm issues no certificates, so nothing in
// package record reads a certificate or a realm CA: no non-test file imports
// crypto/x509, crypto/x509/pkix or encoding/pem.
func TestRecordReadsNoCertificates(t *testing.T) {
	certificatePackages := []string{"crypto/x509", "crypto/x509/pkix", "encoding/pem"}
	checked := 0
	for _, file := range must[[]string](t)(filepath.Glob("*.go")) {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed := must[*ast.File](t)(parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly))
		for _, spec := range parsed.Imports {
			if path, _ := strconv.Unquote(spec.Path.Value); slices.Contains(certificatePackages, path) {
				t.Errorf("%s imports %s", file, path)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no non-test file of package record was examined")
	}
}
