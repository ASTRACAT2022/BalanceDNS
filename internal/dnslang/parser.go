package dnslang

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadBytes(path, data)
}

func LoadBytes(name string, data []byte) (*Engine, error) {
	return LoadString(name, string(data))
}

func LoadString(name, src string) (*Engine, error) {
	program, err := ParseString(name, src)
	if err != nil {
		return nil, err
	}
	return Compile(program)
}

func ParseString(name, src string) (*Program, error) {
	lines := strings.Split(src, "\n")
	program := &Program{
		Sets:  make([]SetDecl, 0),
		Rules: make([]RuleSpec, 0),
	}

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripInlineComment(lines[i]))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "set ") {
			setDecl, err := parseSetLine(line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", name, i+1, err)
			}
			program.Sets = append(program.Sets, setDecl)
			continue
		}

		if strings.HasPrefix(line, "rule ") {
			rule, next, err := parseRuleBlock(name, lines, i)
			if err != nil {
				return nil, err
			}
			program.Rules = append(program.Rules, rule)
			i = next
			continue
		}

		return nil, fmt.Errorf("%s:%d: expected set or rule declaration", name, i+1)
	}

	return program, nil
}

func parseSetLine(line string) (SetDecl, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "set "))
	name, rhs, ok := strings.Cut(rest, "=")
	if !ok {
		return SetDecl{}, fmt.Errorf("invalid set declaration")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return SetDecl{}, fmt.Errorf("set name is required")
	}

	rhs = strings.TrimSpace(rhs)
	open := strings.IndexByte(rhs, '(')
	close := strings.LastIndexByte(rhs, ')')
	if open <= 0 || close <= open {
		return SetDecl{}, fmt.Errorf("invalid set source")
	}

	kind := SetKind(strings.ToLower(strings.TrimSpace(rhs[:open])))
	arg := strings.TrimSpace(rhs[open+1 : close])

	source, err := parseSetSource(kind, arg)
	if err != nil {
		return SetDecl{}, err
	}

	return SetDecl{Name: name, Source: source}, nil
}

func parseSetSource(kind SetKind, arg string) (SetSource, error) {
	switch kind {
	case SetStrings, SetDomains, SetSuffixes, SetIPSet, SetIPPool, SetHosts:
	default:
		return SetSource{}, fmt.Errorf("unsupported set kind %q", kind)
	}

	if arg == "" {
		return SetSource{}, fmt.Errorf("set source argument is required")
	}

	if strings.HasPrefix(arg, "[") {
		values, err := parseListLiteral(arg)
		if err != nil {
			return SetSource{}, err
		}
		return SetSource{Kind: kind, Values: values}, nil
	}

	val, err := parseScalarLiteral(arg)
	if err != nil {
		return SetSource{}, err
	}
	return SetSource{Kind: kind, Path: val}, nil
}

func parseRuleBlock(name string, lines []string, start int) (RuleSpec, int, error) {
	header := strings.TrimSpace(stripInlineComment(lines[start]))
	if !strings.HasSuffix(header, "{") {
		return RuleSpec{}, start, fmt.Errorf("%s:%d: rule header must end with '{'", name, start+1)
	}
	ruleName := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(header, "rule "), "{"))
	if ruleName == "" {
		return RuleSpec{}, start, fmt.Errorf("%s:%d: rule name is required", name, start+1)
	}

	var phase Phase
	var whenRaw string
	var actionRaw string

	i := start + 1
	for ; i < len(lines); i++ {
		line := strings.TrimSpace(stripInlineComment(lines[i]))
		if line == "" {
			continue
		}
		if line == "}" {
			break
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return RuleSpec{}, start, fmt.Errorf("%s:%d: expected key = value inside rule", name, i+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "phase":
			phase = Phase(strings.ToLower(value))
		case "when":
			whenRaw = value
		case "action":
			actionRaw = value
		default:
			return RuleSpec{}, start, fmt.Errorf("%s:%d: unknown rule key %q", name, i+1, key)
		}
	}

	if i >= len(lines) {
		return RuleSpec{}, start, fmt.Errorf("%s:%d: missing closing } for rule %q", name, start+1, ruleName)
	}
	if phase != PhasePreflight && phase != PhasePolicy {
		return RuleSpec{}, start, fmt.Errorf("%s:%d: rule %q has invalid phase %q", name, start+1, ruleName, phase)
	}
	if whenRaw == "" {
		return RuleSpec{}, start, fmt.Errorf("%s:%d: rule %q is missing when expression", name, start+1, ruleName)
	}
	if actionRaw == "" {
		return RuleSpec{}, start, fmt.Errorf("%s:%d: rule %q is missing action", name, start+1, ruleName)
	}

	whenExpr, err := parseExpression(whenRaw)
	if err != nil {
		return RuleSpec{}, start, fmt.Errorf("%s:%d: invalid when expression: %w", name, start+1, err)
	}
	action, err := parseAction(actionRaw)
	if err != nil {
		return RuleSpec{}, start, fmt.Errorf("%s:%d: invalid action: %w", name, start+1, err)
	}

	return RuleSpec{
		Name:    ruleName,
		Phase:   phase,
		RawWhen: whenRaw,
		When:    whenExpr,
		Action:  action,
	}, i, nil
}

func parseAction(raw string) (ActionSpec, error) {
	tokens, err := scanTokens(raw)
	if err != nil {
		return ActionSpec{}, err
	}
	p := &tokenParser{tokens: tokens}
	actionName, err := p.expectIdent()
	if err != nil {
		return ActionSpec{}, err
	}

	spec := ActionSpec{Kind: ActionKind(strings.ToLower(actionName))}
	switch spec.Kind {
	case ActionDrop, ActionRefuse, ActionNXDOMAIN, ActionEmpty:
	case ActionAnswer:
		if p.consumeIdent("from") {
			spec.SetName, err = p.expectIdent()
			if err != nil {
				return ActionSpec{}, err
			}
		} else {
			typeName, err := p.expectValue()
			if err != nil {
				return ActionSpec{}, err
			}
			spec.Type, err = parseQType(typeName)
			if err != nil {
				return ActionSpec{}, err
			}
			spec.Value, err = p.expectValue()
			if err != nil {
				return ActionSpec{}, err
			}
		}
	case ActionSpoof, ActionLoadBalance:
		if !p.consumeIdent("from") {
			return ActionSpec{}, fmt.Errorf("%s action requires 'from <set>'", spec.Kind)
		}
		spec.SetName, err = p.expectIdent()
		if err != nil {
			return ActionSpec{}, err
		}
	default:
		return ActionSpec{}, fmt.Errorf("unsupported action %q", actionName)
	}

	spec.TTL = 60
	if spec.Kind == ActionLoadBalance {
		spec.TTL = 30
		spec.Strategy = "round_robin"
	}

	for !p.done() {
		switch {
		case p.consumeIdent("ttl"):
			num, err := p.expectValue()
			if err != nil {
				return ActionSpec{}, err
			}
			v, err := strconv.ParseUint(num, 10, 32)
			if err != nil {
				return ActionSpec{}, fmt.Errorf("invalid ttl %q", num)
			}
			spec.TTL = uint32(v)
		case p.consumeIdent("strategy"):
			spec.Strategy, err = p.expectValue()
			if err != nil {
				return ActionSpec{}, err
			}
			spec.Strategy = strings.ToLower(spec.Strategy)
		default:
			return ActionSpec{}, fmt.Errorf("unexpected token %q", p.peek().text)
		}
	}

	return spec, nil
}

func parseExpression(raw string) (Expr, error) {
	tokens, err := scanTokens(raw)
	if err != nil {
		return nil, err
	}
	p := &tokenParser{tokens: tokens}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if !p.done() {
		return nil, fmt.Errorf("unexpected token %q", p.peek().text)
	}
	return expr, nil
}

type tokenKind int

const (
	tokenEOF tokenKind = iota
	tokenIdent
	tokenString
	tokenNumber
	tokenLParen
	tokenRParen
	tokenLBracket
	tokenRBracket
	tokenComma
	tokenEqualEqual
	tokenNotEqual
)

type token struct {
	kind tokenKind
	text string
}

func scanTokens(raw string) ([]token, error) {
	tokens := make([]token, 0)
	for i := 0; i < len(raw); {
		ch := raw[i]
		switch {
		case ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n':
			i++
		case ch == '(':
			tokens = append(tokens, token{kind: tokenLParen, text: "("})
			i++
		case ch == ')':
			tokens = append(tokens, token{kind: tokenRParen, text: ")"})
			i++
		case ch == '[':
			tokens = append(tokens, token{kind: tokenLBracket, text: "["})
			i++
		case ch == ']':
			tokens = append(tokens, token{kind: tokenRBracket, text: "]"})
			i++
		case ch == ',':
			tokens = append(tokens, token{kind: tokenComma, text: ","})
			i++
		case ch == '=' && i+1 < len(raw) && raw[i+1] == '=':
			tokens = append(tokens, token{kind: tokenEqualEqual, text: "=="})
			i += 2
		case ch == '!' && i+1 < len(raw) && raw[i+1] == '=':
			tokens = append(tokens, token{kind: tokenNotEqual, text: "!="})
			i += 2
		case ch == '"':
			j := i + 1
			var b strings.Builder
			for ; j < len(raw); j++ {
				if raw[j] == '\\' && j+1 < len(raw) {
					j++
					b.WriteByte(raw[j])
					continue
				}
				if raw[j] == '"' {
					break
				}
				b.WriteByte(raw[j])
			}
			if j >= len(raw) || raw[j] != '"' {
				return nil, fmt.Errorf("unterminated string literal")
			}
			tokens = append(tokens, token{kind: tokenString, text: b.String()})
			i = j + 1
		case isDigit(ch):
			j := i + 1
			for j < len(raw) && isTokenChar(raw[j]) {
				j++
			}
			tokens = append(tokens, token{kind: tokenNumber, text: raw[i:j]})
			i = j
		default:
			if !isTokenChar(ch) {
				return nil, fmt.Errorf("unexpected character %q", ch)
			}
			j := i + 1
			for j < len(raw) && isTokenChar(raw[j]) {
				j++
			}
			tokens = append(tokens, token{kind: tokenIdent, text: raw[i:j]})
			i = j
		}
	}
	tokens = append(tokens, token{kind: tokenEOF})
	return tokens, nil
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isTokenChar(ch byte) bool {
	return ch == '_' || ch == '.' || ch == '-' || ch == ':' || ch == '/' ||
		(ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9')
}

type tokenParser struct {
	tokens []token
	pos    int
}

func (p *tokenParser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.consumeIdent("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &binaryExpr{Op: "or", Left: left, Right: right}
	}
	return left, nil
}

func (p *tokenParser) parseAnd() (Expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.consumeIdent("and") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &binaryExpr{Op: "and", Left: left, Right: right}
	}
	return left, nil
}

func (p *tokenParser) parseUnary() (Expr, error) {
	if p.consumeIdent("not") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &unaryExpr{Op: "not", Expr: inner}, nil
	}
	return p.parsePrimary()
}

func (p *tokenParser) parsePrimary() (Expr, error) {
	if p.consume(tokenLParen) {
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.consume(tokenRParen) {
			return nil, fmt.Errorf("missing closing )")
		}
		return expr, nil
	}
	return p.parseCondition()
}

func (p *tokenParser) parseCondition() (Expr, error) {
	field, err := p.expectIdent()
	if err != nil {
		return nil, err
	}

	field = strings.ToLower(field)
	if field != "qname" && field != "qtype" && field != "qclass" && field != "transport" && field != "client_ip" {
		return nil, fmt.Errorf("unsupported field %q", field)
	}

	if p.consumeIdent("suffix") {
		if p.consumeIdent("in") {
			val, err := p.parseValue()
			if err != nil {
				return nil, err
			}
			return &conditionExpr{Field: field, Comparator: "suffix_in", Value: val}, nil
		}
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return &conditionExpr{Field: field, Comparator: "suffix", Value: val}, nil
	}

	switch {
	case p.consume(tokenEqualEqual):
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return &conditionExpr{Field: field, Comparator: "==", Value: val}, nil
	case p.consume(tokenNotEqual):
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return &conditionExpr{Field: field, Comparator: "!=", Value: val}, nil
	case p.consumeIdent("in"):
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		return &conditionExpr{Field: field, Comparator: "in", Value: val}, nil
	default:
		return nil, fmt.Errorf("expected comparison operator after %q", field)
	}
}

func (p *tokenParser) parseValue() (valueNode, error) {
	if p.consume(tokenLBracket) {
		items := make([]valueNode, 0)
		for {
			if p.consume(tokenRBracket) {
				break
			}
			item, err := p.parseScalarValue()
			if err != nil {
				return valueNode{}, err
			}
			items = append(items, item)
			if p.consume(tokenComma) {
				continue
			}
			if !p.consume(tokenRBracket) {
				return valueNode{}, fmt.Errorf("missing closing ]")
			}
			break
		}
		return valueNode{Kind: valueList, List: items}, nil
	}
	return p.parseScalarValue()
}

func (p *tokenParser) parseScalarValue() (valueNode, error) {
	tok := p.peek()
	switch tok.kind {
	case tokenIdent, tokenString, tokenNumber:
		p.pos++
		return valueNode{Kind: valueScalar, Text: tok.text}, nil
	default:
		return valueNode{}, fmt.Errorf("expected value, got %q", tok.text)
	}
}

func (p *tokenParser) expectIdent() (string, error) {
	tok := p.peek()
	if tok.kind != tokenIdent {
		return "", fmt.Errorf("expected identifier, got %q", tok.text)
	}
	p.pos++
	return tok.text, nil
}

func (p *tokenParser) expectValue() (string, error) {
	tok := p.peek()
	if tok.kind != tokenIdent && tok.kind != tokenString && tok.kind != tokenNumber {
		return "", fmt.Errorf("expected value, got %q", tok.text)
	}
	p.pos++
	return tok.text, nil
}

func (p *tokenParser) consume(kind tokenKind) bool {
	if p.peek().kind == kind {
		p.pos++
		return true
	}
	return false
}

func (p *tokenParser) consumeIdent(value string) bool {
	tok := p.peek()
	if tok.kind != tokenIdent {
		return false
	}
	if strings.EqualFold(tok.text, value) {
		p.pos++
		return true
	}
	return false
}

func (p *tokenParser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{kind: tokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *tokenParser) done() bool {
	return p.peek().kind == tokenEOF
}

func parseListLiteral(raw string) ([]string, error) {
	tokens, err := scanTokens(raw)
	if err != nil {
		return nil, err
	}
	p := &tokenParser{tokens: tokens}
	value, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	if value.Kind != valueList {
		return nil, fmt.Errorf("expected list literal")
	}
	if !p.done() {
		return nil, fmt.Errorf("unexpected token %q", p.peek().text)
	}

	out := make([]string, 0, len(value.List))
	for _, item := range value.List {
		out = append(out, item.Text)
	}
	return out, nil
}

func parseScalarLiteral(raw string) (string, error) {
	tokens, err := scanTokens(raw)
	if err != nil {
		return "", err
	}
	p := &tokenParser{tokens: tokens}
	value, err := p.parseScalarValue()
	if err != nil {
		return "", err
	}
	if !p.done() {
		return "", fmt.Errorf("unexpected token %q", p.peek().text)
	}
	return value.Text, nil
}

func parseQType(raw string) (uint16, error) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	qtype, ok := dns.StringToType[value]
	if !ok {
		return 0, fmt.Errorf("unsupported qtype %q", raw)
	}
	return qtype, nil
}

func stripInlineComment(line string) string {
	var b strings.Builder
	inString := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '"' && (i == 0 || line[i-1] != '\\') {
			inString = !inString
		}
		if ch == '#' && !inString {
			break
		}
		b.WriteByte(ch)
	}
	return b.String()
}
