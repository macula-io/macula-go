package record

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// Only Verify makes a Verified: no non-test file of package record builds one,
// converts a value to one or writes the record it holds outside Verify, so a
// record reaches VerifyAuthorization only as Verify returned it.
func TestOnlyVerifyMakesAVerifiedRecord(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the package's files: %v", err)
	}
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		checkFileBuildsNoVerified(t, file)
		checked++
	}
	if checked == 0 {
		t.Fatal("no non-test file of package record was examined")
	}
}

// checkFileBuildsNoVerified reports every place file builds or converts a
// Verified, or writes the record it holds, outside func Verify.
func checkFileBuildsNoVerified(t *testing.T, file string) {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, decl := range parsed.Decls {
		if function, isFunction := decl.(*ast.FuncDecl); isFunction && function.Recv == nil && function.Name.Name == "Verify" {
			continue
		}
		ast.Inspect(decl, func(node ast.Node) bool {
			reportVerifiedOutsideVerify(t, fileSet, node)
			return true
		})
	}
}

// reportVerifiedOutsideVerify reports node where it builds a Verified,
// converts a value to one, or writes a Verified's held record.
func reportVerifiedOutsideVerify(t *testing.T, fileSet *token.FileSet, node ast.Node) {
	t.Helper()
	switch n := node.(type) {
	case *ast.CompositeLit:
		if namesVerified(n.Type) {
			t.Errorf("%s builds a Verified outside Verify", fileSet.Position(n.Pos()))
		}
	case *ast.CallExpr:
		if namesVerified(n.Fun) {
			t.Errorf("%s converts a value to a Verified outside Verify", fileSet.Position(n.Pos()))
		}
	case *ast.AssignStmt:
		reportHeldWrite(t, fileSet, n)
	}
}

// reportHeldWrite reports every assignment target that writes a Verified's
// held record.
func reportHeldWrite(t *testing.T, fileSet *token.FileSet, assign *ast.AssignStmt) {
	t.Helper()
	for _, target := range assign.Lhs {
		if selector, isSelector := target.(*ast.SelectorExpr); isSelector && selector.Sel.Name == "held" {
			t.Errorf("%s writes a Verified's record outside Verify", fileSet.Position(target.Pos()))
		}
	}
}

// namesVerified reports whether expr is the type name Verified.
func namesVerified(expr ast.Expr) bool {
	ident, isIdent := expr.(*ast.Ident)
	return isIdent && ident.Name == "Verified"
}

// Nothing a caller does after Verify returns changes what VerifyAuthorization
// reads: overwriting the wire form Verify read, or the byte strings of a copy
// Record handed out, leaves the verified advertisement authorized and its
// advertiser node as it was.
func TestAVerifiedRecordHoldsNothingItsInputOrItsCopiesCanChange(t *testing.T) {
	wire, trust := delegationBundleWire(t, "acme/get_forecast_v1", delegationOverrides{})
	verified := must[Verified](t)(Verify(wire, profile.PQPure, nowMs()))
	advertiser := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(verified.Record())).AdvertiserNode
	clear(wire)
	copied := verified.Record()
	node, _ := copied.Payload.Get("advertiser_node")
	nodeBytes, _ := node.AsBytes()
	clear(nodeBytes)
	authorization, _ := copied.Payload.Get("authorization")
	entries, _ := authorization.AsMap()
	for _, e := range entries {
		carried, _ := e.Val.AsBytes()
		clear(carried)
	}
	if err := VerifyAuthorization(verified, trust, nowMs()); err != nil {
		t.Errorf("a verified advertisement after its wire form and a copy were overwritten: %v, want it authorized", err)
	}
	if read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(verified.Record())); read.AdvertiserNode != advertiser {
		t.Errorf("the advertiser node reads %x after the overwrites, want %x", read.AdvertiserNode, advertiser)
	}
}
