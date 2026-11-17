// Package analyze 对解析后的正则做静态 ReDoS 判定：指数级（NFA 配对自动机 + 歧义重复结构规则）
// 与多项式级（重叠量词层，排除有明确分隔字面量的情形）。
package analyze

import (
	"fmt"

	"redos-hunter/internal/nfa"
	"redos-hunter/internal/regex"
	"redos-hunter/internal/regex/charset"
)

// Severity 静态风险等级。
type Severity string

const (
	SevExponential Severity = "exponential" // 指数级回溯
	SevPolynomial  Severity = "polynomial"  // 多项式级回溯
	SevSafe        Severity = "safe"
	SevUnknown     Severity = "unknown" // 含不可建模特性或分析被截断
)

// Finding 一条静态发现（实测证据由 attack/sandbox 回填）。
type Finding struct {
	ID         string `json:"id"`
	PatternID  string `json:"pattern_id"`
	Severity   Severity `json:"severity"`
	Confidence string   `json:"confidence"` // high | medium | low
	NodeID     int      `json:"node_id"`
	Quantifier string   `json:"quantifier"`
	Reason     string   `json:"reason"`
	// 攻击构造原料（attack 包据此生成具体串）。
	PumpRune    rune             `json:"-"`
	PumpWord    string           `json:"pump_word"`
	OverlapSet  *charset.CharSet `json:"-"`
	InnerSet    *charset.CharSet `json:"-"`
	FollowSet   *charset.CharSet `json:"-"`
	Exponential bool             `json:"exponential"`
	Degree      int              `json:"degree"` // 多项式估计次数（指数为 -1）
	PairCount   int              `json:"pair_count"`
	Capped      bool             `json:"capped"`
	Rule        string           `json:"rule"` // 触发的判定规则名
}

// Result 一条正则的完整静态分析结果。
type Result struct {
	PatternID string
	Pattern   *regex.Pattern
	Findings  []*Finding
	Notes     []string
}

// Analyze 分析一条已解析正则。
func Analyze(patternID string, p *regex.Pattern) *Result {
	res := &Result{PatternID: patternID, Pattern: p}

	barrierNodes := map[int]bool{}
	regex.Walk(p.Root, func(n *regex.Node) bool {
		if n.IsBacktrackBarrier() {
			for _, sub := range barrierSubtree(n) {
				barrierNodes[sub.ID] = true
			}
		}
		return true
	})

	for idx, rep := range regex.FindRepeats(p.Root) {
		if barrierNodes[rep.ID] || regex.RepeatContainsBarrier(rep) {
			res.Notes = append(res.Notes, fmt.Sprintf("重复节点 #%d 位于回溯屏障内，跳过", rep.ID))
			continue
		}
		if f := analyzeRepeat(p, rep, idx); f != nil {
			f.PatternID = patternID
			res.Findings = append(res.Findings, f)
		}
	}

	if p.Root.HasUnsupportedFeature() {
		res.Notes = append(res.Notes, "含反向引用等不可 NFA 建模特性，静态结论已降级，以沙箱实测为准")
	}
	return res
}

func barrierSubtree(n *regex.Node) []*regex.Node {
	var out []*regex.Node
	regex.Walk(n, func(x *regex.Node) bool {
		out = append(out, x)
		return true
	})
	return out
}

func analyzeRepeat(p *regex.Pattern, rep *regex.Node, idx int) *Finding {
	f := &Finding{
		ID:         fmt.Sprintf("%s-f%d", p.Source, rep.ID),
		NodeID:     rep.ID,
		Degree:     -1,
		Quantifier: describeQuantifier(rep),
	}
	inner := consumeSet(rep.Child)
	f.InnerSet = inner

	// ---- 1) 配对自动机：重复体内部的歧义 pump（如 (a|aa)*）----
	sub := nfa.BuildSub(rep)
	amb := nfa.AnalyzeAmbiguity(sub)
	f.PairCount, f.Capped = amb.PairCount, amb.Capped
	if amb.Exponential {
		f.Severity = SevExponential
		f.Exponential = true
		f.Confidence = "high"
		f.Rule = "pair-automaton-pump"
		f.Reason = "配对自动机发现重复体内存在歧义泵：同一串可在重复边界产生 ≥2^k 条 NFA 路径"
		f.PumpWord = amb.Pump
		if r, ok := firstRune(amb.Pump); ok {
			f.PumpRune = r
		}
		if f.PumpRune == 0 {
			f.PumpRune = pickInnerRune(rep)
		}
		f.OverlapSet = inner
		return f
	}

	// ---- 2) 歧义重复结构规则（AST）：覆盖配对自动机丢失迭代身份的情形 ----
	if rule, detail := ambiguousRepetitionRule(rep); rule != "" {
		f.Severity = SevExponential
		f.Exponential = true
		f.Confidence = "high"
		f.Rule = rule
		f.Reason = detail
		f.PumpRune = pickInnerRune(rep)
		f.PumpWord = string(f.PumpRune)
		f.OverlapSet = inner
		return f
	}

	// ---- 3) 多项式级：≥2 层在重叠字符集上、且无明确分隔字面量的量词 ----
	if degree, ov := polynomialDegree(p.Root, rep, inner); degree >= 2 {
		f.Severity = SevPolynomial
		f.OverlapSet = ov
		f.Confidence = "medium"
		f.Rule = "overlapping-quantifiers"
		if r, ok := ov.ExampleRune(); ok {
			f.PumpRune = r
			f.PumpWord = string(r)
		}
		f.Degree = degree
		f.Reason = fmt.Sprintf("存在 %d 层在重叠字符集（如 %s）上且无明确分隔的量词，失败输入下回溯约 O(n^%d)",
			degree, describeSet(ov), degree)
		return f
	}

	if amb.Capped {
		f.Severity = SevUnknown
		f.Confidence = "low"
		f.Rule = "analysis-capped"
		f.Reason = "配对状态空间达到上限且未命中结构规则，建议人工复核或依赖沙箱实测"
		return f
	}
	_ = idx
	return nil
}

// ambiguousRepetitionRule 检测"歧义重复"的经典 AST 模式。
// 返回规则名与说明；不命中返回空串。
func ambiguousRepetitionRule(rep *regex.Node) (string, string) {
	body := rep.Child

	// 规则 A：重复体内部包含量词（量词套量词），且内层量词可消费字符与外层重复体字符集相交。
	// 覆盖 (a+)+、(a*)*、(\d+)+ 等。
	innerQuant := findFirstQuantifier(body)
	if innerQuant != nil {
		ov := charset.Intersect(consumeSet(innerQuant.Child), consumeSet(body))
		if !ov.IsEmpty() {
			return "nested-quantifier-overlap",
				"外层量词重复一个本身含量词的子表达式，内层量词可匹配的字符能在多次外层迭代间产生不同切分，路径数指数增长"
		}
	}

	// 规则 B：重复体是含重叠分支的 alternation，分支首字符集两两相交（如 (a|a)*、(a|ab)*）。
	if body.Kind == regex.KAlt {
		if branchesOverlap(body) {
			return "overlapping-alternation",
				"重复体的多个分支能匹配同一前缀字符，每次迭代都可在分支间选择，组合出指数级路径"
		}
	}

	// 规则 C：重复体顶层是多个相邻、字符集重叠且无分隔的量词/原子（如 a*a* 被整体重复）。
	if body.Kind == regex.KConcat && adjacentOverlappingQuantifiers(body) {
		return "adjacent-overlap-in-repeat",
			"重复体内部相邻量词在同一字符集上竞争，叠加外层重复后形成指数级回溯"
	}
	return "", ""
}

func findFirstQuantifier(n *regex.Node) *regex.Node {
	var found *regex.Node
	regex.Walk(n, func(x *regex.Node) bool {
		if x == n {
			return true
		}
		if x.Kind == regex.KRepeat {
			found = x
			return false
		}
		return true
	})
	return found
}

func branchesOverlap(alt *regex.Node) bool {
	for i := 0; i < len(alt.Sub); i++ {
		si := consumeSet(alt.Sub[i])
		for j := i + 1; j < len(alt.Sub); j++ {
			sj := consumeSet(alt.Sub[j])
			if !charset.Intersect(si, sj).IsEmpty() {
				return true
			}
		}
	}
	return false
}

// adjacentOverlappingQuantifiers concat 中是否存在两个相邻量词，字符集重叠且中间无分隔原子。
func adjacentOverlappingQuantifiers(cat *regex.Node) bool {
	var prev *regex.Node
	for _, sub := range cat.Sub {
		if sub.Kind == regex.KRepeat {
			if prev != nil && prev.Kind == regex.KRepeat {
				if !charset.Intersect(consumeSet(prev.Child), consumeSet(sub.Child)).IsEmpty() {
					return true
				}
			}
			prev = sub
			continue
		}
		// 出现必须消费且不与量词字符集重叠的分隔原子，打断相邻关系。
		if !isNullable(sub) {
			prev = nil
			continue
		}
	}
	return false
}

// polynomialDegree 统计与 rep 构成多项式回溯的量词层数（基数 1）。
func polynomialDegree(root, rep *regex.Node, inner *charset.CharSet) (int, *charset.CharSet) {
	degree := 1
	overlap := inner.Clone()

	// 嵌套祖先量词。
	regex.Walk(root, func(n *regex.Node) bool {
		if n.Kind == regex.KRepeat && n != rep && n.AncestorOf(rep) {
			ov := charset.Intersect(consumeSet(n.Child), inner)
			if !ov.IsEmpty() {
				degree++
				overlap = charset.Union(overlap, ov)
			}
		}
		return true
	})

	// 同 concat 相邻量词，仅当中间没有明确分隔字面量；rep 自身或其邻居都计入。
	regex.Walk(root, func(n *regex.Node) bool {
		if n.Kind != regex.KConcat {
			return true
		}
		var prevRepeat *regex.Node
		for _, sub := range n.Sub {
			if sub.Kind == regex.KRepeat {
				if prevRepeat != nil {
					ov := charset.Intersect(consumeSet(prevRepeat.Child), consumeSet(sub.Child))
					if !ov.IsEmpty() {
						degree++
						overlap = charset.Union(overlap, ov)
					}
				}
				prevRepeat = sub
				continue
			}
			// 强制消费且不与量词字符集重叠的原子作为分隔符，打断相邻关系。
			if !isNullable(sub) {
				prevRepeat = nil
			}
		}
		return true
	})
	return degree, overlap
}

// consumeSet 子树能消费的首字符集合（锚点/环视跳过，反向引用返回全集以保守处理）。
func consumeSet(n *regex.Node) *charset.CharSet {
	if n == nil {
		return charset.Empty()
	}
	switch n.Kind {
	case regex.KChar:
		s := charset.Empty()
		for _, r := range n.Chars {
			s = charset.Union(s, charset.Singleton(r))
		}
		return s
	case regex.KClass, regex.KAny:
		return n.Set.Clone()
	case regex.KBoundary:
		return charset.Empty()
	case regex.KBackref:
		return charset.Universe()
	case regex.KGroup, regex.KLook:
		return consumeSet(n.Sub[0])
	case regex.KConcat:
		for _, sub := range n.Sub {
			s := consumeSet(sub)
			if !s.IsEmpty() {
				return s
			}
			if !isNullable(sub) {
				return s
			}
		}
		return charset.Empty()
	case regex.KAlt:
		s := charset.Empty()
		for _, sub := range n.Sub {
			s = charset.Union(s, consumeSet(sub))
		}
		return s
	case regex.KRepeat:
		return consumeSet(n.Child)
	}
	return charset.Empty()
}

// isNullable 子树能否匹配空串（保守近似）。
func isNullable(n *regex.Node) bool {
	if n == nil {
		return true
	}
	switch n.Kind {
	case regex.KEmpty, regex.KBoundary:
		return true
	case regex.KChar, regex.KClass, regex.KAny, regex.KBackref:
		return false
	case regex.KGroup, regex.KLook:
		return isNullable(n.Sub[0])
	case regex.KConcat:
		for _, s := range n.Sub {
			if !isNullable(s) {
				return false
			}
		}
		return true
	case regex.KAlt:
		for _, s := range n.Sub {
			if isNullable(s) {
				return true
			}
		}
		return false
	case regex.KRepeat:
		return n.Min == 0 || isNullable(n.Child)
	}
	return false
}

// firstSetAfterRepeat 保留供攻击串构造使用：rep 后继首字符集。
func firstSetAfterRepeat(root, rep *regex.Node) *charset.CharSet {
	var found bool
	var result *charset.CharSet
	var visit func(n *regex.Node)
	visit = func(n *regex.Node) {
		if n == nil || found {
			return
		}
		if n.Kind == regex.KConcat {
			for i, sub := range n.Sub {
				if containsNode(sub, rep) {
					if sub != rep {
						visit(sub)
						if found {
							return
						}
					}
					for j := i + 1; j < len(n.Sub); j++ {
						s := consumeSet(n.Sub[j])
						if !s.IsEmpty() || !isNullable(n.Sub[j]) {
							result = s
							found = true
							return
						}
					}
					result = charset.Universe()
					found = true
					return
				}
			}
		}
		if n.Child != nil {
			visit(n.Child)
		}
		for _, s := range n.Sub {
			visit(s)
		}
	}
	visit(root)
	return result
}

func containsNode(tree, target *regex.Node) bool {
	found := false
	regex.Walk(tree, func(n *regex.Node) bool {
		if n == target {
			found = true
			return false
		}
		return true
	})
	return found
}

func pickInnerRune(rep *regex.Node) rune {
	if r, ok := consumeSet(rep.Child).ExampleRune(); ok {
		return r
	}
	return 'a'
}

func firstRune(s string) (rune, bool) {
	for _, r := range s {
		return r, true
	}
	return 0, false
}

func describeQuantifier(n *regex.Node) string {
	max := "∞"
	if n.Max >= 0 {
		max = fmt.Sprintf("%d", n.Max)
	}
	mod := ""
	switch n.Greedy {
	case regex.RLazy:
		mod = "?"
	case regex.RPossessive:
		mod = "+"
	}
	return fmt.Sprintf("{%d,%s}%s", n.Min, max, mod)
}

func describeSet(s *charset.CharSet) string {
	if r, ok := s.ExampleRune(); ok {
		return fmt.Sprintf("%q", string(r))
	}
	return "∅"
}
