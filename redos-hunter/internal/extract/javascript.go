package extract

import "strings"

// ScanJavaScript 抽取 JS/TS/JSX/TSX 中的正则：/pat/flags 与 new RegExp("...")。
func ScanJavaScript(file, src string) []Occurrence {
	s := newScanner(src)
	var out []Occurrence

	// prevToken 记录上一个有意义的 token 文本，用于区分正则字面量与除法。
	prevToken := ""

	for !s.done() {
		c := s.peek()

		// 注释。
		if c == '/' && s.peekAt(1) == '/' {
			s.skipLineComment()
			continue
		}
		if c == '/' && s.peekAt(1) == '*' {
			s.skipBlockComment()
			prevToken = "/*"
			continue
		}
		// 字符串/模板串：跳过，同时尝试识别 RegExp 构造实参。
		if c == '"' || c == '\'' || c == '`' {
			occ, _ := s.scanJSStringForRegex(file, c)
			if occ != nil {
				out = append(out, *occ)
			}
			prevToken = "string"
			continue
		}
		// 正则字面量：/ 出现在"期待表达式"的语境。
		if c == '/' && regexAllowedAfterToken(prevToken) {
			if occ := s.scanRegexLiteral(file); occ != nil {
				out = append(out, *occ)
				prevToken = "regex"
				continue
			}
		}
		if isIdentStart(c) {
			ident := s.readIdentifier()
			prevToken = ident
			continue
		}
		// 数字。
		if c >= '0' && c <= '9' {
			for !s.done() && (isIdentPart(s.peek()) || s.peek() == '.') {
				s.advance()
			}
			prevToken = "number"
			continue
		}
		s.advance()
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			prevToken = string(c)
		}
	}
	return out
}

// jsExprKeywords 这些关键字之后必然期待一个表达式，故 / 是正则开头。
var jsExprKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true,
	"new": true, "delete": true, "void": true, "else": true, "do": true,
	"case": true, "yield": true, "await": true, "throw": true,
}

// regexAllowedAfterToken 判断 / 在给定前驱 token 后是否为正则字面量。
func regexAllowedAfterToken(tok string) bool {
	if tok == "" {
		return true
	}
	if jsExprKeywords[tok] {
		return true
	}
	switch tok {
	case ")", "]", "string", "number", "regex":
		return false // 多为除法语境
	}
	// 标识符（非关键字）后是除法；单字符运算符/标点后期待表达式。
	if len(tok) == 1 {
		switch tok[0] {
		case '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';',
			'+', '-', '*', '%', '<', '>', '~', '^':
			return true
		}
	}
	return false
}

// scanRegexLiteral 解析 /pat/flags，正确处理字符类内的 / 与转义。
func (s *scanner) scanRegexLiteral(file string) *Occurrence {
	startLine, startCol := s.location()
	startPos := s.pos
	s.advance() // 开头 /
	patStart := s.pos
	inClass := false
	closed := false
	for !s.done() {
		c := s.peek()
		if c == '\\' {
			s.advance()
			if !s.done() {
				s.advance()
			}
			continue
		}
		if c == '\n' { // 正则不能跨行（除非 ES2018+，保守终止）
			break
		}
		if c == '[' {
			inClass = true
		}
		if c == ']' {
			inClass = false
		}
		if c == '/' && !inClass {
			closed = true
			break
		}
		s.advance()
	}
	if !closed {
		s.pos = startPos + 1 // 回退，按除法等其它结构处理
		return nil
	}
	pattern := s.src[patStart:s.pos]
	s.advance() // 结尾 /
	flagStart := s.pos
	for !s.done() && isIdentPart(s.peek()) {
		s.advance()
	}
	flags := s.src[flagStart:s.pos]
	raw := s.src[startPos:s.pos]
	return &Occurrence{
		Language: langFromFile(file), File: file, Pattern: pattern, Flags: flags,
		Line: startLine, Col: startCol, Kind: "literal", Confidence: "high", Raw: raw,
	}
}

// scanJSStringForRegex 跳过一个字符串；若它是 RegExp(...) 的首个实参则产出构造式出现。
func (s *scanner) scanJSStringForRegex(file string, quote byte) (*Occurrence, string) {
	line, col := s.location()
	startPos := s.pos
	content, closed := s.readQuotedString(quote)
	raw := s.src[startPos:s.pos]
	if !closed {
		return nil, raw
	}
	// 向前回看：跳过空白后是否为 RegExp 标识符 + 可选 new + (
	if s.isRegexConstructorArg(startPos) {
		// 读取可能存在的第二个实参（flags 字符串）。
		flags := s.lookForFlagsArg()
		return &Occurrence{
			Language: langFromFile(file), File: file, Pattern: unescapeJS(content), Flags: flags,
			Line: line, Col: col, Kind: "constructor", Confidence: "high",
			Raw: raw, FromString: true, Quote: quote,
		}, raw
	}
	return nil, raw
}

// readQuotedString 读取引号字符串，处理转义；返回（内容, 是否闭合）。
func (s *scanner) readQuotedString(quote byte) (string, bool) {
	s.advance() // 开引号
	contentStart := s.pos
	for !s.done() {
		c := s.peek()
		if c == '\\' {
			s.advance()
			if !s.done() {
				s.advance()
			}
			continue
		}
		if c == quote {
			content := s.src[contentStart:s.pos]
			s.advance() // 闭引号
			return content, true
		}
		if quote != '`' && c == '\n' {
			return s.src[contentStart:s.pos], false
		}
		s.advance()
	}
	return s.src[contentStart:s.pos], false
}

// isRegexConstructorArg 回看字符串起点之前是否处于 new RegExp( / RegExp( 的首实参位置。
func (s *scanner) isRegexConstructorArg(strStart int) bool {
	i := strStart - 1
	// 跳过前导空白。
	for i >= 0 && (s.src[i] == ' ' || s.src[i] == '\t' || s.src[i] == '\n' || s.src[i] == '\r') {
		i--
	}
	if i < 0 || s.src[i] != '(' {
		return false
	}
	i--
	for i >= 0 && (s.src[i] == ' ' || s.src[i] == '\t' || s.src[i] == '\n' || s.src[i] == '\r') {
		i--
	}
	// 读标识符。
	end := i + 1
	for i >= 0 && isIdentPart(s.src[i]) {
		i--
	}
	ident := s.src[i+1 : end]
	if !strings.EqualFold(ident, "RegExp") {
		return false
	}
	// 再往前可选 new。
	j := i
	for j >= 0 && (s.src[j] == ' ' || s.src[j] == '\t' || s.src[j] == '\n' || s.src[j] == '\r') {
		j--
	}
	if j >= 2 {
		kw := s.src[j-2 : j+1]
		if kw == "new" {
			return true
		}
	}
	return true // RegExp(...) 直接调用也算
}

// lookForFlagsArg 当前位于首参闭引号之后，尝试读取 , "flags"。
func (s *scanner) lookForFlagsArg() string {
	save := s.pos
	s.skipWhitespace()
	if s.peek() != ',' {
		s.pos = save
		return ""
	}
	s.advance()
	s.skipWhitespace()
	if s.peek() != '"' && s.peek() != '\'' {
		s.pos = save
		return ""
	}
	q := s.peek()
	content, closed := s.readQuotedString(q)
	if !closed {
		s.pos = save
		return ""
	}
	return content
}

func unescapeJS(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func langFromFile(file string) string {
	switch {
	case strings.HasSuffix(file, ".js") || strings.HasSuffix(file, ".jsx") ||
		strings.HasSuffix(file, ".mjs") || strings.HasSuffix(file, ".cjs"):
		return "javascript"
	case strings.HasSuffix(file, ".ts") || strings.HasSuffix(file, ".tsx"):
		return "typescript"
	}
	return "javascript"
}
