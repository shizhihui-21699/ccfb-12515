// Package charset 是正则分析的字符抽象层。
// 字符集用排序、不相交、已合并的 rune 区间表示，支持交并补与见证字符选取。
package charset

import (
	"sort"
)

const (
	MaxRune  = rune(0x10FFFF)
	SurLo    = rune(0xD800)
	SurHi    = rune(0xDFFF)
)

// Range 闭区间 [Lo, Hi]。
type Range struct {
	Lo, Hi rune
}

// CharSet 一个具体的字符集合（不含"否定"语义，否定在构造时通过 Complement 落地）。
type CharSet struct {
	Ranges []Range
}

func New(rs ...Range) *CharSet {
	c := &CharSet{}
	for _, r := range rs {
		if r.Lo <= r.Hi {
			c.Ranges = append(c.Ranges, r)
		}
	}
	c.normalize()
	return c
}

func Empty() *CharSet { return &CharSet{} }

func Singleton(r rune) *CharSet { return New(Range{r, r}) }

// Universe 返回 Unicode 全部合法码点（剔除代理区）。
func Universe() *CharSet {
	return New(Range{0, SurLo - 1}, Range{SurHi + 1, MaxRune})
}

func (c *CharSet) IsEmpty() bool { return len(c.Ranges) == 0 }

func (c *CharSet) Clone() *CharSet {
	if c == nil {
		return Empty()
	}
	out := &CharSet{Ranges: make([]Range, len(c.Ranges))}
	copy(out.Ranges, c.Ranges)
	return out
}

func (c *CharSet) normalize() {
	if len(c.Ranges) <= 1 {
		return
	}
	sort.Slice(c.Ranges, func(i, j int) bool { return c.Ranges[i].Lo < c.Ranges[j].Lo })
	merged := c.Ranges[:1]
	for _, r := range c.Ranges[1:] {
		last := &merged[len(merged)-1]
		// 相邻也合并：[a-b]+[b-c] 与 [a-b]+[c] 对集合语义等价。
		if r.Lo <= last.Hi+1 && r.Lo >= SurLo && last.Hi <= SurHi {
			// 跨越代理区时不合并，交给下方统一处理。
		}
		if r.Lo <= last.Hi+1 {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		merged = append(merged, r)
	}
	c.Ranges = merged
	c.dropSurrogates()
}

// dropSurrogates 从所有区间里剔除 UTF-16 代理码点。
func (c *CharSet) dropSurrogates() {
	var out []Range
	for _, r := range c.Ranges {
		switch {
		case r.Hi < SurLo || r.Lo > SurHi:
			out = append(out, r)
		case r.Lo < SurLo && r.Hi > SurHi:
			out = append(out, Range{r.Lo, SurLo - 1}, Range{SurHi + 1, r.Hi})
		case r.Lo < SurLo:
			out = append(out, Range{r.Lo, SurLo - 1})
		case r.Hi > SurHi:
			out = append(out, Range{SurHi + 1, r.Hi})
		}
	}
	c.Ranges = out
}

func (c *CharSet) Contains(r rune) bool {
	i := sort.Search(len(c.Ranges), func(i int) bool { return c.Ranges[i].Hi >= r })
	return i < len(c.Ranges) && c.Ranges[i].Lo <= r && r <= c.Ranges[i].Hi
}

// Intersects 两集合是否有交集。
func (c *CharSet) Intersects(o *CharSet) bool {
	i, j := 0, 0
	for i < len(c.Ranges) && j < len(o.Ranges) {
		a, b := c.Ranges[i], o.Ranges[j]
		if a.Lo <= b.Hi && b.Lo <= a.Hi {
			return true
		}
		if a.Hi < b.Hi {
			i++
		} else {
			j++
		}
	}
	return false
}

// Intersect 交集。
func Intersect(a, b *CharSet) *CharSet {
	out := Empty()
	i, j := 0, 0
	for i < len(a.Ranges) && j < len(b.Ranges) {
		x, y := a.Ranges[i], b.Ranges[j]
		lo := maxRune(x.Lo, y.Lo)
		hi := minRune(x.Hi, y.Hi)
		if lo <= hi {
			out.Ranges = append(out.Ranges, Range{lo, hi})
		}
		if x.Hi < y.Hi {
			i++
		} else {
			j++
		}
	}
	return out
}

// Union 并集。
func Union(parts ...*CharSet) *CharSet {
	out := Empty()
	for _, p := range parts {
		if p == nil {
			continue
		}
		out.Ranges = append(out.Ranges, p.Ranges...)
	}
	out.normalize()
	return out
}

// Subtract 返回 c - o。
func Subtract(c, o *CharSet) *CharSet {
	out := c.Clone()
	for _, b := range o.Ranges {
		var nxt []Range
		for _, a := range out.Ranges {
			switch {
			case b.Hi < a.Lo || b.Lo > a.Hi:
				nxt = append(nxt, a) // 不相交
			case b.Lo <= a.Lo && b.Hi >= a.Hi:
				// 整段被吃掉
			case b.Lo > a.Lo && b.Hi < a.Hi:
				nxt = append(nxt, Range{a.Lo, b.Lo - 1}, Range{b.Hi + 1, a.Hi})
			case b.Lo <= a.Lo:
				nxt = append(nxt, Range{b.Hi + 1, a.Hi})
			default:
				nxt = append(nxt, Range{a.Lo, b.Lo - 1})
			}
		}
		out.Ranges = nxt
	}
	out.normalize()
	return out
}

// Complement 对 Unicode 合法码点全集取补。
func Complement(c *CharSet) *CharSet {
	return Subtract(Universe(), c)
}

func Equals(a, b *CharSet) bool {
	if len(a.Ranges) != len(b.Ranges) {
		return false
	}
	for i := range a.Ranges {
		if a.Ranges[i] != b.Ranges[i] {
			return false
		}
	}
	return true
}

// ExampleRune 返回集合中一个尽量可读的 ASCII 码点；没有 ASCII 则取最小码点。
func (c *CharSet) ExampleRune() (rune, bool) {
	if c.IsEmpty() {
		return 0, false
	}
	for _, r := range c.Ranges {
		if r.Lo <= '~' && r.Hi >= ' ' {
			lo := maxRune(r.Lo, ' ')
			return lo, true
		}
	}
	return c.Ranges[0].Lo, true
}

// RuneInIntersect 返回同时属于两集合的一个码点（优先 ASCII）。
func RuneInIntersect(a, b *CharSet) (rune, bool) {
	return Intersect(a, b).ExampleRune()
}

// RuneInSubtract 返回属于 a 但不属于 b 的一个码点（优先 ASCII）。
func RuneInSubtract(a, b *CharSet) (rune, bool) {
	return Subtract(a, b).ExampleRune()
}

func minRune(a, b rune) rune {
	if a < b {
		return a
	}
	return b
}
func maxRune(a, b rune) rune {
	if a > b {
		return a
	}
	return b
}

// ---- 预置类（ASCII 语义，对齐 JS/Python re 的默认 ASCII 类） ----

var (
	cachedDigit = New(Range{'0', '9'})
	cachedWord  = Union(
		New(Range{'0', '9'}, Range{'A', 'Z'}, Range{'a', 'z'}),
		Singleton('_'),
	)
	cachedSpace = New(
		Range{'\t', '\r'}, // \t \n \v \f \r
		Range{' ', ' '},
	)
)

func Digit() *CharSet { return cachedDigit.Clone() }
func Word() *CharSet  { return cachedWord.Clone() }
func Space() *CharSet { return cachedSpace.Clone() }

// Dot dotAll=false 时匹配除 \n \r 外任意字符；dotAll=true 时匹配全集。
func Dot(dotAll bool) *CharSet {
	if dotAll {
		return Universe()
	}
	return Subtract(Universe(), New(Range{'\n', '\n'}, Range{'\r', '\r'}))
}
