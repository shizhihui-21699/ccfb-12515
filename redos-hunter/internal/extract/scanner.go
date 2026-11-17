package extract

// pos 跟踪扫描器，提供行/列计算与基础词法判断。
type scanner struct {
	src  string
	pos  int
	line int
	col  int
}

func newScanner(src string) *scanner {
	return &scanner{src: src, line: 1, col: 1}
}

func (s *scanner) done() bool { return s.pos >= len(s.src) }

func (s *scanner) peek() byte {
	if s.done() {
		return 0
	}
	return s.src[s.pos]
}

func (s *scanner) peekAt(off int) byte {
	if s.pos+off >= len(s.src) {
		return 0
	}
	return s.src[s.pos+off]
}

// advance 消费一个字节并维护行/列。
func (s *scanner) advance() byte {
	c := s.src[s.pos]
	s.pos++
	if c == '\n' {
		s.line++
		s.col = 1
	} else {
		s.col++
	}
	return c
}

func (s *scanner) location() (line, col int) { return s.line, s.col }

// isIdentStart 标识符起始（ASCII；含 $ _ 以支持 JS）。
func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

// readIdentifier 读取当前位置起的标识符。
func (s *scanner) readIdentifier() string {
	start := s.pos
	for !s.done() && isIdentPart(s.peek()) {
		s.advance()
	}
	return s.src[start:s.pos]
}

// skipWhitespace 跳过空白（不跨注释，注释由专门函数处理）。
func (s *scanner) skipWhitespace() {
	for !s.done() {
		c := s.peek()
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			s.advance()
			continue
		}
		break
	}
}

// skipLineComment 跳过 // 或 # 行注释（假定已确认前缀）。
func (s *scanner) skipLineComment() {
	for !s.done() && s.peek() != '\n' {
		s.advance()
	}
}

// skipBlockComment 跳过 /* ... */（假定已确认 /*）。
func (s *scanner) skipBlockComment() {
	s.advance() // /
	s.advance() // *
	for !s.done() {
		if s.peek() == '*' && s.peekAt(1) == '/' {
			s.advance()
			s.advance()
			return
		}
		s.advance()
	}
}
