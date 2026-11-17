package extract

import "strings"

// ScanPython 抽取 re 模块调用中的 pattern 实参。
func ScanPython(file, src string) []Occurrence {
	s := newScanner(src)
	var out []Occurrence

	for !s.done() {
		c := s.peek()
		if c == '#' {
			s.skipLineComment()
			continue
		}
		// 字符串（含 r/b/u/f 前缀开头）。
		if c == '"' || c == '\'' || s.atPythonStringPrefix() {
			if occ := s.scanPythonString(file); occ != nil {
				out = append(out, *occ)
			}
			continue
		}
		if isIdentStart(c) {
			s.readIdentifier()
			continue
		}
		s.advance()
	}
	return out
}

// atPythonStringPrefix 判断当前是否为 r" / b' / fr" 等字符串前缀。
func (s *scanner) atPythonStringPrefix() bool {
	i, n := s.pos, 0
	for i < len(s.src) && n < 2 && isStringPrefixStart(s.src[i]) {
		i++
		n++
	}
	return i < len(s.src) && (s.src[i] == '"' || s.src[i] == '\'')
}

// pyLiteral 一个 Python 字符串字面量片段。
type pyLiteral struct {
	content string
	raw     bool
	rawText string
	q       byte
}

// scanPythonString 读取一个字符串起点：合并相邻拼接，并判断是否为 re 调用首参。
func (s *scanner) scanPythonString(file string) *Occurrence {
	startLine, startCol := s.location()
	startPos := s.pos

	first, ok := s.readPythonLiteral()
	if !ok {
		return nil
	}
	content, raw, rawText := first.content, first.raw, first.rawText

	// 相邻字符串拼接（可跨行，仅跳空白与换行）。
	for {
		save := s.pos
		s.skipBlankLines()
		if s.peek() == '"' || s.peek() == '\'' || s.atPythonStringPrefix() {
			if next, ok2 := s.readPythonLiteral(); ok2 {
				content += next.content
				rawText += " " + next.rawText
				raw = raw || next.raw
				continue
			}
		}
		s.pos = save
		break
	}

	if !s.isReCallArg(startPos) {
		return nil
	}
	pattern := content
	if !raw {
		pattern = unescapePython(content)
	}
	return &Occurrence{
		Language: "python", File: file, Pattern: pattern, Flags: "",
		Line: startLine, Col: startCol, Kind: "call-arg", Confidence: "high",
		Raw: rawText, FromString: true, Quote: first.q, RawString: raw,
	}
}

// readPythonLiteral 读取单个字符串字面量（含前缀），不做调用语境判断。
func (s *scanner) readPythonLiteral() (pyLiteral, bool) {
	startPos := s.pos
	prefix := ""
	for !s.done() && len(prefix) < 2 && isStringPrefixStart(s.peek()) {
		prefix += string(s.advance())
	}
	if s.peek() != '"' && s.peek() != '\'' {
		s.pos = startPos
		return pyLiteral{}, false
	}
	raw := strings.ContainsAny(prefix, "rR")
	quote := s.peek()
	triple := s.peekAt(1) == quote && s.peekAt(2) == quote

	var content string
	var closed bool
	if triple {
		content, closed = s.readTripleString(quote)
	} else {
		content, closed = s.readPythonSingleString(quote)
	}
	if !closed {
		return pyLiteral{}, false
	}
	return pyLiteral{content: content, raw: raw, rawText: s.src[startPos:s.pos], q: quote}, true
}

func isStringPrefixStart(c byte) bool {
	switch c {
	case 'r', 'R', 'b', 'B', 'u', 'U', 'f', 'F':
		return true
	}
	return false
}

func (s *scanner) readPythonSingleString(quote byte) (string, bool) {
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
			s.advance()
			return content, true
		}
		if c == '\n' {
			return s.src[contentStart:s.pos], false
		}
		s.advance()
	}
	return s.src[contentStart:s.pos], false
}

func (s *scanner) readTripleString(quote byte) (string, bool) {
	s.advance()
	s.advance()
	s.advance()
	contentStart := s.pos
	for !s.done() {
		if s.peek() == quote && s.peekAt(1) == quote && s.peekAt(2) == quote {
			content := s.src[contentStart:s.pos]
			s.advance()
			s.advance()
			s.advance()
			return content, true
		}
		if s.peek() == '\\' {
			s.advance()
		}
		if !s.done() {
			s.advance()
		}
	}
	return s.src[contentStart:s.pos], false
}

// skipBlankLines 跳过空格、制表符与换行（用于相邻字符串拼接）。
func (s *scanner) skipBlankLines() {
	for !s.done() {
		switch s.peek() {
		case ' ', '\t', '\n', '\r':
			s.advance()
		default:
			return
		}
	}
}

// isReCallArg 回看字符串起点之前是否为 re.<func>( 的首实参位置。
func (s *scanner) isReCallArg(strStart int) bool {
	i := strStart - 1
	for i >= 0 && (s.src[i] == ' ' || s.src[i] == '\t' || s.src[i] == '\n' || s.src[i] == '\r') {
		i--
	}
	if i < 0 || s.src[i] != '(' {
		return false
	}
	i--
	for i >= 0 && (s.src[i] == ' ' || s.src[i] == '\t') {
		i--
	}
	end := i + 1
	for i >= 0 && isIdentPart(s.src[i]) {
		i--
	}
	funcName := strings.ToLower(s.src[i+1 : end])
	if !regexFuncNames[funcName] {
		return false
	}
	for i >= 0 && (s.src[i] == ' ' || s.src[i] == '\t') {
		i--
	}
	if i < 0 || s.src[i] != '.' {
		return false
	}
	i--
	modEnd := i + 1
	for i >= 0 && isIdentPart(s.src[i]) {
		i--
	}
	mod := strings.ToLower(s.src[i+1:modEnd])
	return mod == "re" || mod == "regex"
}

func unescapePython(s string) string {
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
