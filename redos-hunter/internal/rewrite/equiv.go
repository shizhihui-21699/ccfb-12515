package rewrite

import (
	"math/rand"

	"redos-hunter/internal/regex"
	"redos-hunter/internal/sandbox"
)

// EquivCheck 改写前后等价性检验结果。
type EquivCheck struct {
	Equivalent   bool     `json:"equivalent"`
	Tested       int      `json:"tested"`
	Countercases []string `json:"countercases"` // 改写前后结果不一致的输入
	Note         string   `json:"note"`
}

// CheckEquivalence 在有限样本上检验两条模式的匹配行为是否一致。
// 样本 = 定向边界串 + 基于模式字符集生成的随机串。返回的 Equivalent 仅在样本范围内成立。
func CheckEquivalence(before, after *regex.Pattern, stepCap int64, samples int) EquivCheck {
	res := EquivCheck{Equivalent: true}
	if samples <= 0 {
		samples = 200
	}

	alphabet := buildAlphabet(before)
	inputs := targetedInputs(before)
	rng := rand.New(rand.NewSource(1))
	for len(inputs) < samples {
		n := rng.Intn(12) + 1
		b := make([]rune, n)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		inputs = append(inputs, string(b))
	}

	mb := sandbox.NewMatcher(before, stepCap)
	ma := sandbox.NewMatcher(after, stepCap)
	for _, in := range inputs {
		rb, errB := mb.Fullmatch(in)
		ra, errA := ma.Fullmatch(in)
		// 触发步数上限的样本跳过（两边都可能因复杂度无法在预算内完成）。
		if errB != nil || errA != nil {
			continue
		}
		res.Tested++
		if rb.Matched != ra.Matched {
			res.Equivalent = false
			if len(res.Countercases) < 10 {
				res.Countercases = append(res.Countercases, in)
			}
		}
	}
	if !res.Equivalent {
		res.Note = "发现改写前后匹配结果不一致的输入，改写不等价，需人工修正"
	} else {
		res.Note = "在 " + itoa(res.Tested) + " 个样本上匹配行为一致（不构成严格证明，建议结合业务用例复核）"
	}
	return res
}

func buildAlphabet(p *regex.Pattern) []rune {
	seen := map[rune]bool{}
	var out []rune
	add := func(r rune) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	regex.Walk(p.Root, func(n *regex.Node) bool {
		switch n.Kind {
		case regex.KChar:
			for _, r := range n.Chars {
				add(r)
			}
		case regex.KClass:
			for _, rg := range n.Set.Ranges {
				if r, ok := n.Set.ExampleRune(); ok {
					add(r)
				}
				_ = rg
			}
		}
		return true
	})
	// 保证有常见"越界"字符用于触发否定分支。
	for _, r := range []rune{'a', 'b', '!', ' ', '0', '\n'} {
		add(r)
	}
	return out
}

func targetedInputs(p *regex.Pattern) []string {
	var out []string
	out = append(out, "", "a", "aa", "aaa", "!", "a!", "aa!", " ", "0", "\n", "ab", "ba")
	regex.Walk(p.Root, func(n *regex.Node) bool {
		if n.Kind == regex.KChar && len(n.Chars) > 0 {
			out = append(out, string(n.Chars[0]), repeat(n.Chars[0], 4))
		}
		return true
	})
	return out
}

func repeat(r rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = r
	}
	return string(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
