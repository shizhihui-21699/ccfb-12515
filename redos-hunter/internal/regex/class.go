package regex

import (
	"fmt"

	"redos-hunter/internal/regex/charset"
)

// parseClass 解析 [...]。
func (ps *parser) parseClass() (*Node, error) {
	start := ps.pos
	ps.pos++ // [
	n := ps.newNode(KClass)
	n.Pos = start
	negated := false
	if ps.eat('^') {
		negated = true
	}
	var parts []*charset.CharSet
	first := true
	for {
		c := ps.peek()
		if c == 0 {
			return nil, fmt.Errorf("regex: 字符类未闭合 (偏移 %d)", start)
		}
		if c == ']' && !first {
			ps.pos++
			break
		}
		first = false
		set, err := ps.parseClassAtom()
		if err != nil {
			return nil, err
		}
		// 区间 a-z
		if ps.peek() == '-' && ps.pos+1 < len(ps.src) && ps.src[ps.pos+1] != ']' {
			ps.pos++ // -
			hiSet, err := ps.parseClassAtom()
			if err != nil {
				return nil, err
			}
			lo, loOK := set.ExampleRune()
			hi, hiOK := hiSet.ExampleRune()
			if !loOK || !hiOK {
				return nil, fmt.Errorf("regex: 非法字符区间 (偏移 %d)", start)
			}
			if hi < lo {
				return nil, fmt.Errorf("regex: 字符区间逆序 %q-%q (偏移 %d)", string(lo), string(hi), start)
			}
			var rs []charset.Range
			rs = append(rs, charset.Range{Lo: lo, Hi: hi})
			if ps.flags.I {
				for _, r := range foldRange(lo, hi) {
					rs = append(rs, charset.Range{Lo: r, Hi: r})
				}
			}
			parts = append(parts, charset.New(rs...))
			continue
		}
		parts = append(parts, set)
	}
	union := charset.Union(parts...)
	if negated {
		union = charset.Complement(union)
	}
	n.Set = union
	return n, nil
}

func (ps *parser) parseClassAtom() (*charset.CharSet, error) {
	c := ps.peek()
	if c == '\\' {
		return ps.parseClassEscape()
	}
	ps.pos++
	if c == '[' {
		// 嵌套 [ 按字面量处理（POSIX 风格类的开头由 parsePosix 兜底）。
		return charset.Singleton('['), nil
	}
	var rs []rune
	if ps.flags.I {
		rs = foldRune(rune(c))
	} else {
		rs = []rune{rune(c)}
	}
	out := charset.Empty()
	for _, r := range rs {
		out = charset.Union(out, charset.Singleton(r))
	}
	return out, nil
}

func (ps *parser) parseClassEscape() (*charset.CharSet, error) {
	start := ps.pos
	ps.pos++ // 反斜杠
	if ps.pos >= len(ps.src) {
		return nil, fmt.Errorf("regex: 字符类内裸反斜杠 (偏移 %d)", start)
	}
	c := ps.src[ps.pos]
	switch c {
	case 'd', 'D', 'w', 'W', 's', 'S':
		ps.pos++
		return ps.presetClass(c), nil
	}
	r, err := ps.readEscapeValue()
	if err != nil {
		if err == errUnicodeProp {
			// \p{...} 在类内：保守当作匹配任意字符的不透明类。
			return charset.Universe(), nil
		}
		return nil, err
	}
	out := charset.Empty()
	rs := []rune{r}
	if ps.flags.I {
		rs = foldRune(r)
	}
	for _, x := range rs {
		out = charset.Union(out, charset.Singleton(x))
	}
	return out, nil
}
