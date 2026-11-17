package extract

import "strings"

// ScanGo 抽取 regexp.Compile/MustCompile 等的字符串实参（含反引号原始串）。
func ScanGo(file, src string) []Occurrence {
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
		if c == '`' || c == '"' {
			if occ := s.scanGoString(file); occ != nil {
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

func (s *scanner) scanGoString(file string) *Occurrence {
	startLine, startCol := s.location()
	startPos := s.pos
	quote := s.peek()
	raw := quote == '`'

	var content string
	var closed bool
	if raw {
		s.advance()
		cStart := s.pos
		for !s.done() && s.peek() != '`' {
			s.advance()
		}
		content = s.src[cStart:s.pos]
		if s.peek() == '`' {
			closed = true
			s.advance()
		}
	} else {
		content, closed = s.readQuotedString('"')
	}
	rawText := s.src[startPos:s.pos]
	if !closed || !s.isGoRegexpArg(startPos) {
		return nil
	}
	pattern := content
	if !raw {
		pattern = unescapeJS(content) // Go 双引号转义规则与 JS 子集一致
	}
	return &Occurrence{
		Language: "go", File: file, Pattern: pattern, Flags: "",
		Line: startLine, Col: startCol, Kind: "call-arg", Confidence: "high",
		Raw: rawText, FromString: true, Quote: quote, RawString: raw,
	}
}

func (s *scanner) isGoRegexpArg(strStart int) bool {
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
	return strings.ToLower(s.src[i+1:modEnd]) == "regexp"
}
