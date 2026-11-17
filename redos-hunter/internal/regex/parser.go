package regex

import (
	"fmt"
	"strconv"
	"strings"

	"redos-hunter/internal/regex/charset"
)

type parser struct {
	src      string
	pos      int
	flags    Flags
	p        *Pattern
	nextID   int
	nextCap  int
	inClass  bool
}

// Parse 解析一个正则（不含外层 / / 分隔符；分隔符与语言标志由 extract 层处理）。
// initialFlags 用于承接 JS 字面量尾部 flags 或 Python re.XXX。
func Parse(src string, initialFlags Flags) (*Pattern, error) {
	ps := &parser{
		src:     src,
		flags:   initialFlags,
		nextCap: 1,
	}
	p := &Pattern{Source: src, Flags: initialFlags, Caps: map[int]*Node{}}
	ps.p = p
	root, err := ps.parseDisjunction()
	if err != nil {
		return nil, err
	}
	if ps.pos != len(src) {
		return nil, fmt.Errorf("regex: 无法解析的尾部字符 %q (偏移 %d)", string(src[ps.pos]), ps.pos)
	}
	if root == nil {
		root = ps.newNode(KEmpty)
	}
	p.Root = root
	p.Flags = ps.flags
	return p, nil
}

func (ps *parser) newNode(k NodeKind) *Node {
	n := &Node{Kind: k, ID: ps.nextID, Max: -1}
	ps.nextID++
	return n
}

func (ps *parser) peek() byte {
	if ps.pos >= len(ps.src) {
		return 0
	}
	return ps.src[ps.pos]
}

func (ps *parser) eat(c byte) bool {
	if ps.peek() == c {
		ps.pos++
		return true
	}
	return false
}

func (ps *parser) expect(c byte) error {
	if !ps.eat(c) {
		return fmt.Errorf("regex: 期望 %q 但得到 %q (偏移 %d)", c, string(ps.peek()), ps.pos)
	}
	return nil
}

// ---- 文法 ----

func (ps *parser) parseDisjunction() (*Node, error) {
	var alts [][]*Node
	var seq []*Node
	for {
		if ps.peek() == 0 || ps.peek() == ')' {
			alts = append(alts, seq)
			break
		}
		if ps.peek() == '|' {
			alts = append(alts, seq)
			seq = nil
			ps.pos++
			continue
		}
		atom, err := ps.parseSequenceItem()
		if err != nil {
			return nil, err
		}
		if atom != nil {
			seq = append(seq, atom)
		}
	}
	var branches []*Node
	for _, s := range alts {
		branches = append(branches, ps.makeConcat(s))
	}
	if len(branches) == 1 {
		return branches[0], nil
	}
	n := ps.newNode(KAlt)
	n.Sub = branches
	return n, nil
}

func (ps *parser) makeConcat(items []*Node) *Node {
	items = compactEmpties(items)
	if len(items) == 0 {
		return ps.newNode(KEmpty)
	}
	if len(items) == 1 {
		return items[0]
	}
	n := ps.newNode(KConcat)
	n.Sub = items
	return n
}

func compactEmpties(items []*Node) []*Node {
	out := items[:0]
	for _, it := range items {
		if it != nil && it.Kind != KEmpty {
			out = append(out, it)
		}
	}
	return out
}

func (ps *parser) parseSequenceItem() (*Node, error) {
	atom, err := ps.parseAtom()
	if err != nil {
		return nil, err
	}
	// 量词（不能作用于断言与锚点）。
	if atom != nil && atom.Kind != KBoundary && atom.Kind != KLook {
		if q := ps.peek(); q == '*' || q == '+' || q == '?' || q == '{' {
			atom, err = ps.parseQuantifier(atom)
			if err != nil {
				return nil, err
			}
		}
	}
	return atom, nil
}

func (ps *parser) parseQuantifier(target *Node) (*Node, error) {
	start := ps.pos
	rep := ps.newNode(KRepeat)
	rep.Pos = start
	rep.Child = target
	switch ps.peek() {
	case '*':
		ps.pos++
		rep.Min, rep.Max = 0, -1
	case '+':
		ps.pos++
		rep.Min, rep.Max = 1, -1
	case '?':
		ps.pos++
		rep.Min, rep.Max = 0, 1
	case '{':
		lo, hi, ok, err := ps.parseBrace()
		if err != nil {
			return nil, err
		}
		if !ok {
			// { 不是量词：按字面量处理（JS 行为）。
			rep.ID = -1 // 回收编号（简化处理：保持编号空洞也无害）
			return target, nil
		}
		rep.Min, rep.Max = lo, hi
	default:
		rep.ID = -1
		return target, nil
	}
	rep.Greedy = RGreedy
	switch ps.peek() {
	case '?':
		rep.Greedy = RLazy
		ps.pos++
	case '+':
		rep.Greedy = RPossessive
		ps.pos++
		ps.p.warn(start, "possessive", "占有量词，回溯屏障内的子表达式不参与 ReDoS 分析")
	}
	// {0} / 定死次数且为 0 时退化为空。
	if rep.Max == 0 {
		return ps.newNode(KEmpty), nil
	}
	return rep, nil
}

// parseBrace 解析 {n} {n,} {n,m}；若不是合法量词返回 ok=false 且回退位置。
func (ps *parser) parseBrace() (lo, hi int, ok bool, err error) {
	save := ps.pos
	ps.pos++ // {
	readNum := func() (int, bool) {
		start := ps.pos
		for ps.peek() >= '0' && ps.peek() <= '9' {
			ps.pos++
		}
		if ps.pos == start {
			return 0, false
		}
		v, e := strconv.Atoi(ps.src[start:ps.pos])
		return v, e == nil
	}
	lo, ok = readNum()
	if !ok {
		ps.pos = save
		return 0, 0, false, nil
	}
	hi = lo
	if ps.eat(',') {
		if ps.peek() == '}' {
			hi = -1
		} else {
			hi, ok = readNum()
			if !ok {
				ps.pos = save
				return 0, 0, false, nil
			}
		}
	}
	if !ps.eat('}') {
		ps.pos = save
		return 0, 0, false, nil
	}
	if hi != -1 && hi < lo {
		ps.pos = save
		return 0, 0, false, fmt.Errorf("regex: 量词上界小于下界 (偏移 %d)", save)
	}
	return lo, hi, true, nil
}

func (ps *parser) parseAtom() (*Node, error) {
	c := ps.peek()
	switch {
	case c == 0:
		return nil, nil
	case c == '(':
		return ps.parseGroup()
	case c == '[':
		return ps.parseClass()
	case c == '.':
		ps.pos++
		n := ps.newNode(KAny)
		n.Set = charset.Dot(ps.flags.S)
		return n, nil
	case c == '^' || c == '$':
		ps.pos++
		n := ps.newNode(KBoundary)
		n.Boundary = c
		return n, nil
	case c == '\\':
		return ps.parseEscape()
	case c == '*' || c == '+' || c == '?':
		return nil, fmt.Errorf("regex: 量词 %q 没有可作用的对象 (偏移 %d)", string(c), ps.pos)
	case c == '|' || c == ')':
		return nil, nil
	default:
		ps.pos++
		n := ps.newNode(KChar)
		n.Pos = ps.pos - 1
		n.Chars = ps.fold(c)
		return n, nil
	}
}

func (ps *parser) parseGroup() (*Node, error) {
	start := ps.pos
	ps.pos++ // (
	g := ps.newNode(KGroup)
	g.Pos = start

	if ps.eat('?') {
		switch {
		case ps.eat(':'):
			g.Group = GNonCap
		case ps.eat('>'):
			g.Group = GAtomic
			ps.p.warn(start, "atomic", "原子组 (?>...) 为回溯屏障")
		case ps.peek() == '=' || ps.peek() == '!' ||
			ps.peek() == '<' && ps.pos+1 < len(ps.src) &&
				(ps.src[ps.pos+1] == '=' || ps.src[ps.pos+1] == '!'):
			return ps.parseLook(start)
		case ps.peek() == '<':
			// 命名组 (?<name>...) 或 (?P<name>...)
			if ps.pos+1 < len(ps.src) && ps.src[ps.pos+1] == 'P' {
				ps.pos += 2 // <P
			} else {
				ps.pos++ // <
			}
			name, err := ps.readName()
			if err != nil {
				return nil, err
			}
			if err := ps.expect('>'); err != nil {
				return nil, err
			}
			g.Group, g.Name = GNamed, name
		case ps.peek() == 'P':
			// Python (?P=name) 反向引用
			ps.pos += 2
			name, err := ps.readName()
			if err != nil {
				return nil, err
			}
			if err := ps.expect(')'); err != nil {
				return nil, err
			}
			return ps.makeBackrefName(start, name), nil
		case isFlagByte(ps.peek()) || ps.peek() == '-':
			return ps.parseFlagGroup(g, start)
		case ps.peek() == 'R' || ps.peek() >= '1' && ps.peek() <= '9':
			ps.p.warn(start, "recursion", "递归/子模式调用 (?R)/(?n) 无法静态分析，跳过该子树")
			if err := ps.skipToGroupEnd(); err != nil {
				return nil, err
			}
			return ps.newNode(KEmpty), nil
		case ps.peek() == '(':
			ps.p.warn(start, "conditional", "条件分组无法静态分析，跳过该子树")
			if err := ps.skipToGroupEnd(); err != nil {
				return nil, err
			}
			return ps.newNode(KEmpty), nil
		default:
			return nil, fmt.Errorf("regex: 不支持的分组语法 (偏移 %d)", start)
		}
	} else {
		g.Group = GCapture
		g.CapID = ps.nextCap
		ps.nextCap++
	}

	body, err := ps.parseDisjunction()
	if err != nil {
		return nil, err
	}
	if err := ps.expect(')'); err != nil {
		return nil, err
	}
	g.Sub = []*Node{body}
	if g.Group == GCapture || g.Group == GNamed {
		if g.Group == GNamed {
			g.CapID = ps.nextCap
		}
		ps.p.Caps[g.CapID] = g
	}
	return g, nil
}

func (ps *parser) parseLook(start int) (*Node, error) {
	lk := ps.newNode(KLook)
	lk.Pos = start
	behind := false
	if ps.eat('<') {
		behind = true
	}
	positive := ps.eat('=')
	if !positive {
		if !ps.eat('!') {
			return nil, fmt.Errorf("regex: 环视语法错误 (偏移 %d)", start)
		}
	}
	switch {
	case behind && positive:
		lk.Look = LookBehind
	case behind && !positive:
		lk.Look = LookNotBehind
	case !behind && positive:
		lk.Look = LookAhead
	default:
		lk.Look = LookNotAhead
	}
	body, err := ps.parseDisjunction()
	if err != nil {
		return nil, err
	}
	if err := ps.expect(')'); err != nil {
		return nil, err
	}
	lk.Sub = []*Node{body}
	return lk, nil
}

// parseFlagGroup 处理 (?i)、(?i:...)、(?i-m:...)。
func (ps *parser) parseFlagGroup(g *Node, start int) (*Node, error) {
	saved := ps.flags
	on, off, hasColon := ps.readFlagSpec()
	apply := func(f Flags) Flags {
		if on.I {
			f.I = true
		}
		if on.M {
			f.M = true
		}
		if on.S {
			f.S = true
		}
		if on.U {
			f.U = true
		}
		if off.I {
			f.I = false
		}
		if off.M {
			f.M = false
		}
		if off.S {
			f.S = false
		}
		if off.U {
			f.U = false
		}
		return f
	}
	ps.flags = apply(ps.flags)
	if !hasColon {
		if err := ps.expect(')'); err != nil {
			return nil, err
		}
		ps.flags = saved // 裸标志 (?i) 影响到所在组剩余部分，这里近似按作用到组尾处理
		_ = start
		return ps.newNode(KEmpty), nil
	}
	g.Group = GNonCap
	body, err := ps.parseDisjunction()
	if err != nil {
		return nil, err
	}
	if err := ps.expect(')'); err != nil {
		return nil, err
	}
	ps.flags = saved
	g.Sub = []*Node{body}
	return g, nil
}

func (ps *parser) readFlagSpec() (on, off Flags, hasColon bool) {
	cur := &on
	for {
		switch ps.peek() {
		case 'i':
			cur.I = true
		case 'm':
			cur.M = true
		case 's':
			cur.S = true
		case 'u':
			cur.U = true
		case '-':
			cur = &off
		case ':':
			ps.pos++
			return on, off, true
		case ')':
			return on, off, false
		default:
			return on, off, ps.peek() == ':'
		}
		ps.pos++
	}
}

func isFlagByte(c byte) bool { return c == 'i' || c == 'm' || c == 's' || c == 'u' }

func (ps *parser) readName() (string, error) {
	start := ps.pos
	for {
		c := ps.peek()
		if c == 0 || c == '>' {
			break
		}
		ps.pos++
	}
	name := ps.src[start:ps.pos]
	if name == "" {
		return "", fmt.Errorf("regex: 命名组名称为空 (偏移 %d)", start)
	}
	return name, nil
}

func (ps *parser) makeBackrefName(start int, name string) *Node {
	n := ps.newNode(KBackref)
	n.Pos = start
	n.RefName = name
	ps.p.warn(start, "backref", fmt.Sprintf("反向引用 (?P=%s) 无法 NFA 建模，结论降级", name))
	return n
}

func (ps *parser) skipToGroupEnd() error {
	depth := 1
	for depth > 0 {
		c := ps.peek()
		if c == 0 {
			return fmt.Errorf("regex: 分组未闭合 (偏移 %d)", ps.pos)
		}
		if c == '\\' {
			ps.pos += 2
			continue
		}
		if c == '(' {
			depth++
		}
		if c == ')' {
			depth--
		}
		ps.pos++
	}
	return nil
}

func (ps *parser) fold(c byte) []rune {
	r := rune(c)
	if !ps.flags.I || !isASCIIAlpha(c) {
		return []rune{r}
	}
	if c >= 'a' && c <= 'z' {
		return []rune{r, r - 32}
	}
	return []rune{r, r + 32}
}

func isASCIIAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// foldRune 返回 ASCII 大小写折叠后的全部码点。
func foldRune(r rune) []rune {
	if r >= 'a' && r <= 'z' {
		return []rune{r, r - 32}
	}
	if r >= 'A' && r <= 'Z' {
		return []rune{r, r + 32}
	}
	return []rune{r}
}

func foldRange(lo, hi rune) []rune {
	var out []rune
	for r := lo; r <= hi && r <= 0x7E; r++ {
		out = append(out, foldRune(r)...)
	}
	return out
}

// 避免未使用导入（strings 在 escape/name 解析中使用）。
var _ = strings.TrimSpace
