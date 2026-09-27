// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

// Command ctscan lists comparisons in the module's non-test code that are not
// constant time: == and != on byte arrays or on strings converted from byte
// slices, and bytes.Equal/Compare/HasPrefix. docs/constant-time.md classifies
// every site it reports. Usage, from the repository root:
//
//	go run -C scripts/ctscan . "$PWD"
package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"strings"

	"golang.org/x/tools/go/packages"
)

func isByteArray(t types.Type) bool {
	a, ok := t.Underlying().(*types.Array)
	if !ok {
		return false
	}
	b, ok := a.Elem().Underlying().(*types.Basic)
	return ok && (b.Kind() == types.Byte || b.Kind() == types.Uint8)
}

func isStringOfBytes(info *types.Info, e ast.Expr) bool {
	c, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || len(c.Args) != 1 {
		return false
	}
	tv, ok := info.Types[c.Fun]
	if !ok || !tv.IsType() {
		return false
	}
	if b, ok := tv.Type.Underlying().(*types.Basic); !ok || b.Kind() != types.String {
		return false
	}
	_, isSlice := info.TypeOf(c.Args[0]).Underlying().(*types.Slice)
	return isSlice || isByteArray(info.TypeOf(c.Args[0]))
}

func main() {
	cfg := &packages.Config{Mode: packages.LoadAllSyntax, Dir: os.Args[1]}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		panic(err)
	}
	for _, p := range pkgs {
		for _, f := range p.Syntax {
			name := p.Fset.Position(f.Pos()).Filename
			if strings.HasSuffix(name, "_test.go") || strings.Contains(name, "/proto/") {
				continue
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BinaryExpr:
					if n.Op != token.EQL && n.Op != token.NEQ {
						return true
					}
					if isByteArray(p.TypesInfo.TypeOf(n.X)) || isStringOfBytes(p.TypesInfo, n.X) || isStringOfBytes(p.TypesInfo, n.Y) {
						fmt.Printf("%s: %s\n", rel(p.Fset.Position(n.Pos())), types.ExprString(n))
					}
				case *ast.CallExpr:
					if s, ok := n.Fun.(*ast.SelectorExpr); ok {
						if id, ok := s.X.(*ast.Ident); ok {
							if pn, ok := p.TypesInfo.Uses[id].(*types.PkgName); ok && pn.Imported().Path() == "bytes" && (s.Sel.Name == "Equal" || s.Sel.Name == "Compare" || s.Sel.Name == "HasPrefix") {
								fmt.Printf("%s: %s\n", rel(p.Fset.Position(n.Pos())), types.ExprString(n))
							}
						}
					}
				}
				return true
			})
		}
	}
}

func rel(p token.Position) string {
	return strings.TrimPrefix(p.String(), os.Args[1]+"/")
}
