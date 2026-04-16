package license

import (
	"strings"
	"unicode"
)

// Expression is a parsed SPDX license expression tree.
//
// Grammar (simplified subset of SPDX license-expression):
//
//   expression = term ("OR" term)*
//   term       = factor ("AND" factor)*
//   factor     = identifier ["WITH" identifier] | "(" expression ")"
//
// WITH modifier is preserved in the node but evaluation ignores it for v1.2
// (see README of this package for the known-limitation note).
type Expression interface {
	// isExpression is a marker method — only the unexported types in this
	// file implement it.
	isExpression()
}

type identNode struct {
	id        string
	exception string // WITH clause (ignored during evaluation in v1.2)
}

func (identNode) isExpression() {}

type orNode struct {
	nodes []Expression
}

func (orNode) isExpression() {}

type andNode struct {
	nodes []Expression
}

func (andNode) isExpression() {}

// ParseExpression parses an SPDX license expression. Whitespace is ignored
// outside identifiers; identifiers accept [A-Za-z0-9.+-_].
//
// Non-SPDX strings (e.g. "MIT License") are returned as a single identNode —
// the caller must apply SPDX aliasing upstream via sbom.Parse if normalization
// is needed.
func ParseExpression(s string) (Expression, error) {
	p := &parser{tokens: tokenize(s)}
	expr := p.parseExpression()
	if p.err != nil {
		return identNode{id: strings.TrimSpace(s)}, p.err
	}
	return expr, nil
}

type tokenKind int

const (
	tokIdent tokenKind = iota
	tokOr
	tokAnd
	tokWith
	tokLParen
	tokRParen
	tokEOF
)

type token struct {
	kind tokenKind
	val  string
}

// tokenize scans a license expression into tokens. Keywords are
// case-insensitive per SPDX spec.
func tokenize(s string) []token {
	var out []token
	i := 0
	for i < len(s) {
		c := rune(s[i])
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '(':
			out = append(out, token{kind: tokLParen})
			i++
		case c == ')':
			out = append(out, token{kind: tokRParen})
			i++
		default:
			// Read identifier up to whitespace / paren.
			j := i
			for j < len(s) {
				r := rune(s[j])
				if unicode.IsSpace(r) || r == '(' || r == ')' {
					break
				}
				j++
			}
			word := s[i:j]
			i = j
			switch strings.ToUpper(word) {
			case "OR":
				out = append(out, token{kind: tokOr})
			case "AND":
				out = append(out, token{kind: tokAnd})
			case "WITH":
				out = append(out, token{kind: tokWith})
			default:
				out = append(out, token{kind: tokIdent, val: word})
			}
		}
	}
	out = append(out, token{kind: tokEOF})
	return out
}

type parser struct {
	tokens []token
	pos    int
	err    error
}

func (p *parser) peek() token {
	return p.tokens[p.pos]
}

func (p *parser) advance() token {
	t := p.tokens[p.pos]
	if p.pos < len(p.tokens)-1 {
		p.pos++
	}
	return t
}

func (p *parser) expect(k tokenKind) {
	if p.peek().kind != k {
		p.err = errExpr("unexpected token")
		return
	}
	p.advance()
}

type exprErr struct{ msg string }

func (e exprErr) Error() string { return "license expression: " + e.msg }
func errExpr(msg string) error  { return exprErr{msg: msg} }

func (p *parser) parseExpression() Expression {
	left := p.parseTerm()
	var terms []Expression
	for p.peek().kind == tokOr {
		p.advance()
		terms = append(terms, p.parseTerm())
	}
	if len(terms) == 0 {
		return left
	}
	terms = append([]Expression{left}, terms...)
	return orNode{nodes: terms}
}

func (p *parser) parseTerm() Expression {
	left := p.parseFactor()
	var factors []Expression
	for p.peek().kind == tokAnd {
		p.advance()
		factors = append(factors, p.parseFactor())
	}
	if len(factors) == 0 {
		return left
	}
	factors = append([]Expression{left}, factors...)
	return andNode{nodes: factors}
}

func (p *parser) parseFactor() Expression {
	t := p.peek()
	switch t.kind {
	case tokLParen:
		p.advance()
		inner := p.parseExpression()
		p.expect(tokRParen)
		return inner
	case tokIdent:
		p.advance()
		n := identNode{id: t.val}
		if p.peek().kind == tokWith {
			p.advance()
			if p.peek().kind == tokIdent {
				exc := p.advance()
				n.exception = exc.val
			} else {
				p.err = errExpr("expected identifier after WITH")
			}
		}
		return n
	default:
		p.err = errExpr("expected identifier or '('")
		return identNode{}
	}
}

// evaluateExpression returns true if the expression satisfies the policy (all
// leaves allowed), false otherwise. The or_semantics flag controls OR rules.
func evaluateExpression(expr Expression, isAllowed func(id string) bool, or OrSemantics) bool {
	switch n := expr.(type) {
	case identNode:
		return isAllowed(n.id)
	case andNode:
		for _, c := range n.nodes {
			if !evaluateExpression(c, isAllowed, or) {
				return false
			}
		}
		return true
	case orNode:
		if or == OrAllAllowed {
			for _, c := range n.nodes {
				if !evaluateExpression(c, isAllowed, or) {
					return false
				}
			}
			return true
		}
		// default: any_allowed
		for _, c := range n.nodes {
			if evaluateExpression(c, isAllowed, or) {
				return true
			}
		}
		return false
	}
	return false
}

// collectLeaves walks the expression and returns the flattened list of
// identifiers (used for audit / human-readable reasons).
func collectLeaves(expr Expression) []string {
	var out []string
	var walk func(Expression)
	walk = func(e Expression) {
		switch n := e.(type) {
		case identNode:
			out = append(out, n.id)
		case orNode:
			for _, c := range n.nodes {
				walk(c)
			}
		case andNode:
			for _, c := range n.nodes {
				walk(c)
			}
		}
	}
	walk(expr)
	return out
}
