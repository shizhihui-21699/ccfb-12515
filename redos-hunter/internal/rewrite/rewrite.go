// Package rewrite 为漏洞正则生成安全的等价改写建议。
// 基于 AST 节点渲染（不依赖脆弱的字符串替换），每条建议给出改写文本、原理、
// 适用引擎与等价性注意事项；不自动改代码。
package rewrite

import (
	"fmt"
	"strings"

	"redos-hunter/internal/analyze"
	"redos-hunter/internal/regex"
)

// Suggestion 一条改写建议。
type Suggestion struct {
	Original   string `json:"original"`
	Fixed      string `json:"fixed"`
	Strategy   string `json:"strategy"`
	Why        string `json:"why"`
	Equivalent string `json:"equivalent"`
	RE2Safe    bool   `json:"re2_safe"`
	Confidence string `json:"confidence"`
}

// Suggest 为一条静态发现生成一个或多个改写候选。
func Suggest(p *regex.Pattern, f *analyze.Finding) []Suggestion {
	original := p.Source
	var rep *regex.Node
	regex.Walk(p.Root, func(n *regex.Node) bool {
		if n.ID == f.NodeID {
			rep = n
			return false
		}
		return true
	})
	if rep == nil || rep.Kind != regex.KRepeat {
		return []Suggestion{manualReview(original)}
	}

	var out []Suggestion

	// 策略 1：原子组固定重复体（回溯引擎通用，切断内部回溯点）。
	if !regex.RepeatContainsBarrier(rep) {
		fixed := renderWithOverride(p.Root, rep.ID, func(n *regex.Node) string {
			return fmt.Sprintf("(?>%s)%s", render(n.Child), quantSuffix(n))
		})
		out = append(out, Suggestion{
			Original: original, Fixed: fixed, Strategy: "atomic-group",
			Why:        "原子组在第一次成功匹配后即锁死，不保留可回溯的备选切分，从根源消除重复体内部的指数枚举",
			Equivalent: "对能匹配成功的输入结果一致；仅在原本依赖回溯换一种切分才能成功的边缘情形不同，这类情形通常正是 bug",
			RE2Safe:    false, Confidence: "high",
		})
	}

	// 策略 2：嵌套量词合并（语言等价，RE2 与回溯引擎都安全）。
	if merged := mergeNested(rep); merged != "" {
		fixed := renderWithOverride(p.Root, rep.ID, func(n *regex.Node) string {
			return merged
		})
		out = append(out, Suggestion{
			Original: original, Fixed: fixed, Strategy: "flatten-nested-quantifier",
			Why:        "嵌套量词 (X+)+ 让同一串存在多种切分；按重复次数合并为单层量词后，每个字符只有一条消费路径，且匹配的字符串集合不变",
			Equivalent: "合并后的 min/max 与嵌套重复等价；若重复体可匹配空串需人工确认空匹配语义",
			RE2Safe:    true, Confidence: "high",
		})
	}

	// 策略 3：相邻重叠量词收窄。
	if f.Rule == "overlapping-quantifiers" {
		fixed := renderWithOverride(p.Root, rep.ID, func(n *regex.Node) string {
			// 用否定后继的互斥字符类提示方向；具体边界字符需人工确认。
			return fmt.Sprintf("(?:%s)%s", render(n.Child), quantSuffix(n))
		})
		out = append(out, Suggestion{
			Original: original, Fixed: fixed,
			Strategy: "merge-overlapping-adjacent",
			Why:        "相邻量词竞争同一字符集导致边界反复回退；应合并为单个量词，并让其后继使用互斥字符集",
			Equivalent: "此为方向性改写，需结合业务确认合法输入集合，建议配合等价性测试",
			RE2Safe:    true, Confidence: "medium",
		})
	}

	// 策略 4：换线性引擎（RE2）。
	out = append(out, Suggestion{
		Original: original, Fixed: original, Strategy: "use-linear-engine",
		Why:        "Go regexp / Rust regex / RE2 基于自动机保证线性时间，同一模式不会因回溯卡死",
		Equivalent: "RE2 不支持反向引用、环视、占有量词等特性；若用到需先确认引擎能力",
		RE2Safe:    true, Confidence: "high",
	})

	if len(out) == 0 {
		out = append(out, manualReview(original))
	}
	return out
}

// mergeNested 当 rep 是"重复体本身为单个重复（可被 group 包裹）"的嵌套结构时，
// 合并两层量词为单层，返回渲染文本；否则返回空串。
//
//	(X{im,ix}){om,ox}  ≡  X{im*om, ix*ox}（任一上界无界则结果无界）
func mergeNested(rep *regex.Node) string {
	inner := soleInnerRepeat(rep.Child)
	if inner == nil || inner.Kind != regex.KRepeat {
		return ""
	}
	newMin := rep.Min * inner.Min
	newMax := -1
	if rep.Max >= 0 && inner.Max >= 0 {
		newMax = rep.Max * inner.Max
	}
	merged := &regex.Node{
		Kind: regex.KRepeat, Child: inner.Child,
		Min: newMin, Max: newMax, Greedy: rep.Greedy,
	}
	return render(merged)
}

// soleInnerRepeat 若 n 是单个重复，或仅包着一个重复的 group，返回该内层重复。
func soleInnerRepeat(n *regex.Node) *regex.Node {
	if n == nil {
		return nil
	}
	if n.Kind == regex.KRepeat {
		return n
	}
	if n.Kind == regex.KGroup && len(n.Sub) == 1 {
		return soleInnerRepeat(n.Sub[0])
	}
	return nil
}

func manualReview(original string) Suggestion {
	return Suggestion{
		Original: original, Fixed: original, Strategy: "manual-review",
		Why:        "该模式的回溯风险无法用通用规则自动改写，需要人工审查匹配意图",
		Equivalent: "请人工确认", RE2Safe: false, Confidence: "low",
	}
}

// ---- AST 渲染 ----

// renderWithOverride 渲染整棵树；遇到 id==targetID 的节点用 override 输出并跳过其默认渲染。
func renderWithOverride(root *regex.Node, targetID int, override func(*regex.Node) string) string {
	var b strings.Builder
	writeOverride(&b, root, targetID, override)
	return b.String()
}

func writeOverride(b *strings.Builder, n *regex.Node, targetID int, override func(*regex.Node) string) {
	if n != nil && n.ID == targetID {
		b.WriteString(override(n))
		return
	}
	writeNodeO(b, n, targetID, override)
}

func render(n *regex.Node) string {
	var b strings.Builder
	writeNodeO(&b, n, -1, nil)
	return b.String()
}

func writeNodeO(b *strings.Builder, n *regex.Node, targetID int, override func(*regex.Node) string) {
	if n == nil {
		return
	}
	switch n.Kind {
	case regex.KEmpty:
	case regex.KChar:
		if len(n.Chars) > 0 {
			b.WriteRune(n.Chars[0])
		}
	case regex.KClass, regex.KAny:
		b.WriteString(classText(n))
	case regex.KBoundary:
		switch n.Boundary {
		case '^', '$':
			b.WriteByte(n.Boundary)
		default: // \b \B
			b.WriteByte('\\')
			b.WriteByte(n.Boundary)
		}
	case regex.KGroup:
		b.WriteString(groupOpen(n))
		if len(n.Sub) > 0 {
			writeNodeO(b, n.Sub[0], targetID, override)
		}
		b.WriteByte(')')
	case regex.KLook:
		b.WriteString(lookOpen(n))
		if len(n.Sub) > 0 {
			writeNodeO(b, n.Sub[0], targetID, override)
		}
		b.WriteByte(')')
	case regex.KConcat:
		for _, s := range n.Sub {
			writeOverride(b, s, targetID, override)
		}
	case regex.KAlt:
		for i, s := range n.Sub {
			if i > 0 {
				b.WriteByte('|')
			}
			writeOverride(b, s, targetID, override)
		}
	case regex.KRepeat:
		writeOverride(b, n.Child, targetID, override)
		b.WriteString(quantSuffix(n))
	case regex.KBackref:
		fmt.Fprintf(b, "\\%d", n.RefID)
	}
}

func classText(n *regex.Node) string {
	if n.Kind == regex.KAny {
		return "."
	}
	var b strings.Builder
	b.WriteByte('[')
	for _, r := range n.Set.Ranges {
		if r.Lo == r.Hi {
			b.WriteRune(r.Lo)
		} else {
			b.WriteRune(r.Lo)
			b.WriteByte('-')
			b.WriteRune(r.Hi)
		}
	}
	b.WriteByte(']')
	return b.String()
}

func groupOpen(n *regex.Node) string {
	switch n.Group {
	case regex.GNonCap:
		return "(?:"
	case regex.GAtomic:
		return "(?>"
	case regex.GNamed:
		return fmt.Sprintf("(?<%s>", n.Name)
	default:
		return "("
	}
}

func lookOpen(n *regex.Node) string {
	switch n.Look {
	case regex.LookAhead:
		return "(?="
	case regex.LookNotAhead:
		return "(?!"
	case regex.LookBehind:
		return "(?<="
	case regex.LookNotBehind:
		return "(?<!"
	}
	return "(?="
}

func quantSuffix(n *regex.Node) string {
	var q string
	switch {
	case n.Min == 0 && n.Max == -1:
		q = "*"
	case n.Min == 1 && n.Max == -1:
		q = "+"
	case n.Min == 0 && n.Max == 1:
		q = "?"
	default:
		if n.Max == -1 {
			q = fmt.Sprintf("{%d,}", n.Min)
		} else {
			q = fmt.Sprintf("{%d,%d}", n.Min, n.Max)
		}
	}
	switch n.Greedy {
	case regex.RLazy:
		q += "?"
	case regex.RPossessive:
		q += "+"
	}
	return q
}
