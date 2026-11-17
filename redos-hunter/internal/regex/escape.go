package regex

import (
	"fmt"
	"strconv"

	"redos-hunter/internal/regex/charset"
)

// parseEscape 处理反斜杠转义（字符类外）。
func (ps *parser) parseEscape() (*Node, error) {
	start := ps.pos
	ps.pos++ // 反斜杠
	if ps.pos >= len(ps.src) {
		return nil, fmt.Errorf("regex: 结尾的裸反斜杠 (偏移 %d)", start)
	}
	c := ps.src[ps.pos]

	// 反向引用 \1 ... \9（\0 走八进制）。
	if c >= '1' && c <= '9' {
		digits := ps.readDecimal(2)
		id, _ := strconv.Atoi(digits)
		n := ps.newNode(KBackref)
		n.Pos = start
		n.RefID = id
		ps.p.warn(start, "backref", fmt.Sprintf("反向引用 \\%d 无法 NFA 建模，结论降级", id))
		return n, nil
	}

	// 预置类与边界。
	switch c {
	case 'd', 'D', 'w', 'W', 's', 'S':
		ps.pos++
		n := ps.newNode(KClass)
		n.Pos = start
		n.Set = ps.presetClass(c)
		return n, nil
	case 'b', 'B':
		ps.pos++
		n := ps.newNode(KBoundary)
		n.Pos = start
		n.Boundary = c
		return n, nil
	}

	r, err := ps.readEscapeValue()
	if err != nil {
		if err == errUnicodeProp {
			// \p{...}/\P{...} 在类外：保守当作不透明字符类，按可能匹配多字符处理（可能误报）。
			n := ps.newNode(KClass)
			n.Pos = start
			n.Set = charset.Universe()
			return n, nil
		}
		return nil, err
	}
	n := ps.newNode(KChar)
	n.Pos = start
	if ps.flags.I {
		n.Chars = foldRune(r)
	} else {
		n.Chars = []rune{r}
	}
	return n, nil
}

func (ps *parser) readDecimal(max int) string {
	start := ps.pos
	for k := 0; k < max && ps.pos < len(ps.src) && ps.src[ps.pos] >= '0' && ps.src[ps.pos] <= '9'; k++ {
		ps.pos++
	}
	return ps.src[start:ps.pos]
}

func (ps *parser) presetClass(c byte) *charset.CharSet {
	var set *charset.CharSet
	switch c {
	case 'd':
		set = charset.Digit()
	case 'D':
		set = charset.Complement(charset.Digit())
	case 'w':
		set = charset.Word()
	case 'W':
		set = charset.Complement(charset.Word())
	case 's':
		set = charset.Space()
	case 'S':
		set = charset.Complement(charset.Space())
	}
	if ps.flags.I {
		// 预置类不受 i 影响，保持原样。
	}
	return set
}

// readEscapeValue 解析出一个具体码点（消费对应字符）。
func (ps *parser) readEscapeValue() (rune, error) {
	c := ps.src[ps.pos]
	switch {
	case c == 'n':
		ps.pos++
		return '\n', nil
	case c == 'r':
		ps.pos++
		return '\r', nil
	case c == 't':
		ps.pos++
		return '\t', nil
	case c == 'f':
		ps.pos++
		return '\f', nil
	case c == 'v':
		ps.pos++
		return '\v', nil
	case c == 'a':
		ps.pos++
		return 0x07, nil
	case c == 'e':
		ps.pos++
		return 0x1B, nil
	case c == '0':
		return ps.readOctalOrNull()
	case c >= '1' && c <= '7':
		return ps.readOctal(3)
	case c == 'x':
		return ps.readHexEscape()
	case c == 'u':
		return ps.readUnicodeEscape()
	case c == 'c':
		return ps.readControlEscape()
	case c == 'p' || c == 'P':
		return 0, ps.readUnicodeProp(c)
	default:
		// 普通转义字面量：\( \. \\ \/ 等。
		ps.pos++
		return rune(c), nil
	}
}

func (ps *parser) readOctalOrNull() (rune, error) {
	save := ps.pos
	ps.pos++ // 0
	if ps.pos < len(ps.src) && ps.src[ps.pos] >= '0' && ps.src[ps.pos] <= '7' {
		ps.pos = save
		return ps.readOctal(3)
	}
	return 0, nil
}

func (ps *parser) readOctal(max int) (rune, error) {
	start := ps.pos
	for k := 0; k < max && ps.pos < len(ps.src) && ps.src[ps.pos] >= '0' && ps.src[ps.pos] <= '7'; k++ {
		ps.pos++
	}
	v, err := strconv.ParseInt(ps.src[start:ps.pos], 8, 32)
	if err != nil {
		return 0, fmt.Errorf("regex: 非法八进制转义 (偏移 %d)", start)
	}
	return rune(v), nil
}

func (ps *parser) readHexEscape() (rune, error) {
	start := ps.pos
	ps.pos++ // x
	if ps.eat('{') {
		lo := ps.pos
		for isHex(ps.peek()) {
			ps.pos++
		}
		if ps.pos == lo || !ps.eat('}') {
			return 0, fmt.Errorf("regex: 非法 \\x{{}} 转义 (偏移 %d)", start)
		}
		v, err := strconv.ParseInt(ps.src[lo:ps.pos], 16, 32)
		if err != nil {
			return 0, err
		}
		return rune(v), nil
	}
	if ps.pos+2 > len(ps.src) {
		return 0, fmt.Errorf("regex: 截断的 \\x 转义 (偏移 %d)", start)
	}
	v, err := strconv.ParseInt(ps.src[ps.pos:ps.pos+2], 16, 32)
	ps.pos += 2
	if err != nil {
		return 0, fmt.Errorf("regex: 非法 \\xHH 转义 (偏移 %d)", start)
	}
	return rune(v), nil
}

func (ps *parser) readUnicodeEscape() (rune, error) {
	start := ps.pos
	ps.pos++ // u
	if ps.eat('{') {
		lo := ps.pos
		for isHex(ps.peek()) {
			ps.pos++
		}
		if ps.pos == lo || !ps.eat('}') {
			return 0, fmt.Errorf("regex: 非法 \\u{{}} 转义 (偏移 %d)", start)
		}
		v, err := strconv.ParseInt(ps.src[lo:ps.pos], 16, 32)
		if err != nil {
			return 0, err
		}
		return rune(v), nil
	}
	if ps.pos+4 > len(ps.src) {
		return 0, fmt.Errorf("regex: 截断的 \\u 转义 (偏移 %d)", start)
	}
	v, err := strconv.ParseInt(ps.src[ps.pos:ps.pos+4], 16, 32)
	ps.pos += 4
	if err != nil {
		return 0, fmt.Errorf("regex: 非法 \\uHHHH 转义 (偏移 %d)", start)
	}
	return rune(v), nil
}

func (ps *parser) readControlEscape() (rune, error) {
	start := ps.pos
	ps.pos++ // c
	if ps.pos >= len(ps.src) {
		return 0, fmt.Errorf("regex: 截断的 \\c 转义 (偏移 %d)", start)
	}
	c := ps.src[ps.pos]
	ps.pos++
	return rune(c % 32), nil
}

// readUnicodeProp 消费 \p{...}/\P{...}，登记告警并返回一个不透明码点占位策略。
func (ps *parser) readUnicodeProp(c byte) error {
	start := ps.pos
	ps.pos++ // p/P
	negated := c == 'P'
	if !ps.eat('{') {
		// 单字母形式 \pL
		if ps.pos < len(ps.src) {
			ps.pos++
		}
	} else {
		for ps.pos < len(ps.src) && ps.src[ps.pos] != '}' {
			ps.pos++
		}
		ps.eat('}')
	}
	ps.p.warn(start, "unicode-prop",
		fmt.Sprintf("Unicode 属性 %s 按不透明字符类保守处理，可能误报", ps.src[start:ps.pos]))
	_ = negated
	return errUnicodeProp
}

var errUnicodeProp = fmt.Errorf("unicode property escape")

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
