// Package attack 根据静态发现构造攻击串候选，并用回溯 VM 实测筛选。
package attack

import (
	"errors"
	"strings"

	"redos-hunter/internal/analyze"
	"redos-hunter/internal/regex"
	"redos-hunter/internal/regex/charset"
	"redos-hunter/internal/sandbox"
)

// Candidate 一个攻击串候选。
type Candidate struct {
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	Pump   string `json:"pump"`
	Suffix string `json:"suffix"`
	// At(n) 返回第 n 级攻击串。
}

func (c Candidate) At(n int) string {
	return c.Prefix + strings.Repeat(c.Pump, n) + c.Suffix
}

// BuildCandidates 依据发现生成多组候选（不同 killer、不同结构），提高命中率。
func BuildCandidates(p *regex.Pattern, f *analyze.Finding) []Candidate {
	pump := f.PumpWord
	if pump == "" && f.PumpRune != 0 {
		pump = string(f.PumpRune)
	}
	if pump == "" {
		pump = "a"
	}

	// killer：重复体吞不掉、但后继/锚点会拒绝的字符。
	killers := killerCandidates(p, f)

	var out []Candidate
	// 1) 纯 pump + killer（最经典的失败串）。
	for _, k := range killers {
		out = append(out, Candidate{
			Name:   "pump-then-killer:" + k,
			Pump:   pump,
			Suffix: k,
		})
	}
	// 2) pump + 一个重复体可吞字符再加 killer（覆盖后继需要先匹配的情形）。
	if r, ok := f.InnerSet.ExampleRune(); ok {
		for _, k := range killers {
			out = append(out, Candidate{
				Name:   "pump-inner-killer:" + k,
				Pump:   pump,
				Suffix: string(r) + k,
			})
		}
	}
	// 3) 全 pump 无后缀（命中 ^...$ 之外的搜索语义，靠重复自身歧义）。
	out = append(out, Candidate{Name: "pure-pump", Pump: pump})
	// 4) pump 后接换行（针对 $ / 行尾锚点）。
	out = append(out, Candidate{Name: "pump-newline", Pump: pump, Suffix: "\n"})
	// 5) 指数型常见特例：奇数长度 pump（(a|aa)* 类）。
	if f.Exponential {
		out = append(out, Candidate{Name: "odd-pump-killer", Pump: pump, Suffix: "!"})
	}
	return dedup(out)
}

func killerCandidates(p *regex.Pattern, f *analyze.Finding) []string {
	inner := f.InnerSet
	if inner == nil || inner.IsEmpty() {
		inner = charset.Universe()
	}
	var picked []rune
	prefer := []rune{'!', 'x', ' ', ';', '0', '\n', '\t', '#', '@'}
	for _, r := range prefer {
		if !inner.Contains(r) {
			picked = append(picked, r)
		}
	}
	if r, ok := charset.RuneInSubtract(charset.Universe(), inner); ok {
		picked = append(picked, r)
	}
	// 重叠字符本身有时也是有效 killer（如 a*a$ 用 a 触发重叠分裂）。
	if f.OverlapSet != nil {
		if r, ok := f.OverlapSet.ExampleRune(); ok {
			picked = append([]rune{r}, picked...)
		}
	}
	seen := map[rune]bool{}
	var out []string
	for _, r := range picked {
		if seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, string(r))
	}
	if len(out) == 0 {
		out = []string{"!"}
	}
	return out
}

func dedup(cs []Candidate) []Candidate {
	seen := map[string]bool{}
	var out []Candidate
	for _, c := range cs {
		key := c.Pump + "|" + c.Suffix + "|" + c.Prefix
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

// Point 单个规模下的实测点。
type Point struct {
	N        int   `json:"n"`
	Length   int   `json:"length"`
	Steps    int64 `json:"steps"`
	Capped   bool  `json:"capped"`
	Matched  bool  `json:"matched"`
}

// Probe 用回溯 VM 在 n=1..maxN 上测候选，返回全部数据点与是否超线性。
func Probe(p *regex.Pattern, c Candidate, stepCap int64, maxN int) ([]Point, bool) {
	m := sandbox.NewMatcher(p, stepCap)
	var pts []Point
	superLinear := false
	var prevSteps int64 = 1
	for n := 1; n <= maxN; n++ {
		s := c.At(n)
		res, err := m.Search(s)
		pt := Point{N: n, Length: len(s), Steps: res.Steps, Capped: res.Capped, Matched: res.Matched}
		if errors.Is(err, sandbox.ErrStepCap) {
			pt.Capped = true
			pt.Steps = stepCap
		}
		pts = append(pts, pt)
		// 相邻规模步数翻倍以上 ⇒ 强超线性信号。
		if n >= 3 && pt.Steps >= 2*prevSteps && pt.Steps > 100 {
			superLinear = true
		}
		prevSteps = pt.Steps
		if pt.Capped {
			break
		}
	}
	return pts, superLinear
}
