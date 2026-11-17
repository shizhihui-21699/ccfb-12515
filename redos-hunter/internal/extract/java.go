package extract

import "strings"

// ScanJava 抽取 Pattern.compile / Pattern.matches 等的字符串实参。
func ScanJava(file, src string) []Occurrence {
	s := newScanner(src)
	var out []Occurrence
	for !s.done() {
		c := s.peek()
		if c == '/' && s.peekAt(1) == '/' {
			s.skipLineComment()
			continue
		}
		if c == '/' && s.peekAt(1) == '*' {
			s.skipBlockComment()
			continue
		}
		if c == '"' {
			if occ := s.scanJavaString(file); occ != nil {
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

func (s *scanner) scanJavaString(file string) *Occurrence {
	startLine, startCol := s.location()
	startPos := s.pos
	content, closed := s.readQuotedString('"')
	rawText := s.src[startPos:s.pos]
	if !closed || !s.isJavaPatternArg(startPos) {
		return nil
	}
	// Java 文本块 """...""" 由 readQuotedString 按普通串处理会提前闭合，这里足够覆盖主流写法。
	return &Occurrence{
		Language: "java", File: file, Pattern: unescapeJava(content), Flags: "",
		Line: startLine, Col: startCol, Kind: "call-arg", Confidence: "high",
		Raw: rawText, FromString: true, Quote: '"',
	}
}

func (s *scanner) isJavaPatternArg(strStart int) bool {
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
	return strings.ToLower(s.src[i+1:modEnd]) == "pattern"
}

func unescapeJava(s string) string {
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
