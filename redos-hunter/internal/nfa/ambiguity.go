package nfa

import (
	"redos-hunter/internal/regex/charset"
)

// AmbiguityResult 配对自动机（pair automaton）歧义分析结果。
//
// 原理（经典 ReDoS 判据）：NFA 上若同一个词存在两条不同接受路径，回溯引擎就要枚举它们。
// 配对自动机同时模拟"两条路径"，且配对的每一步必须取自【两条不同的 NFA 边】——
// 沿同一条边的状态自循环（如 a* 的单一 a 边）是同一条路径，不算歧义。
//   - 到达 (accept, accept) ⇒ 该词有两条不同接受路径（歧义确认）；
//   - 经非空串到达对角配对 (s,s) ⇒ 该串是 pump，其 k 次重复产生 ≥2^k 条路径（指数）。
type AmbiguityResult struct {
	Ambiguous   bool
	Exponential bool   // 经不同边到达对角配对 (s,s)
	Pump        string // 触发指数分裂的泵串
	Witness     string // 完整见证串
	PairCount   int
	Capped      bool // 达到配对上限，结论可能不完整
}

const defaultPairCap = 200_000

type pair struct{ a, b int }

type pairParent struct {
	from pair
	r    rune // 上一步消费的字符；0 表示仅 ε 步
	eps  bool
}

// edgeID 唯一标识一条 NFA 边：源状态 + 该状态转移表中的下标。
type edgeID struct {
	src int
	idx int
}

type move struct {
	id  edgeID
	set *charset.CharSet
	to  int
}

// AnalyzeAmbiguity 在给定 NFA 上做配对歧义分析。
func AnalyzeAmbiguity(n *NFA) AmbiguityResult {
	return analyzeWithCap(n, defaultPairCap)
}

func analyzeWithCap(n *NFA, pairCap int) AmbiguityResult {
	res := AmbiguityResult{}

	// 带多重度的 ε 闭包：值 ≥2 表示该状态可由 ≥2 条 ε 路径到达。
	closure := func(seed map[int]int) map[int]int {
		out := map[int]int{}
		type ent struct{ s, m int }
		stack := make([]ent, 0, len(seed))
		for s, m := range seed {
			stack = append(stack, ent{s, m})
			out[s] = m
		}
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for i, t := range n.States[top.s].Trans {
				if t.Set != nil {
					continue
				}
				nm := top.m
				if nm > 1 {
					nm = 2
				}
				if prev, ok := out[t.To]; !ok || nm > prev {
					out[t.To] = nm
					stack = append(stack, ent{t.To, nm})
				}
				_ = i
			}
		}
		return out
	}

	// charMoves 收集闭包内所有【带字符】边，保留边身份，用于"不同边"约束。
	charMoves := func(clos map[int]int) []move {
		var out []move
		for s := range clos {
			for i, t := range n.States[s].Trans {
				if t.Set != nil {
					out = append(out, move{edgeID{s, i}, t.Set, t.To})
				}
			}
		}
		return out
	}

	root := pair{n.Start, n.Start}
	parents := map[pair]pairParent{root: {}}
	queue := []pair{root}

	// ε 闭包中的天然分叉（同一状态经多条 ε 路径、或两个不同分支起点）作为初始配对。
	startClos := closure(map[int]int{n.Start: 1})
	var sl []int
	for s, m := range startClos {
		if m >= 2 && s != n.Start {
			np := pair{s, s}
			if _, seen := parents[np]; !seen {
				parents[np] = pairParent{from: root, eps: true}
				queue = append(queue, np)
			}
		}
		sl = append(sl, s)
	}
	for i := 0; i < len(sl); i++ {
		for j := i + 1; j < len(sl); j++ {
			np := pair{sl[i], sl[j]}
			if _, seen := parents[np]; !seen {
				parents[np] = pairParent{from: root, eps: true}
				queue = append(queue, np)
			}
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		res.PairCount++
		if res.PairCount > pairCap {
			res.Capped = true
			break
		}

		if cur.a == n.Accept && cur.b == n.Accept {
			res.Ambiguous = true
		}

		closA := closure(map[int]int{cur.a: 1})
		closB := closure(map[int]int{cur.b: 1})
		movesA := charMoves(closA)
		movesB := charMoves(closB)

		for _, ma := range movesA {
			for _, mb := range movesB {
				// 核心约束：两条路径必须走不同的边，否则只是同一条路径的复制。
				if ma.id == mb.id {
					continue
				}
				r, ok := charset.RuneInIntersect(ma.set, mb.set)
				if !ok {
					continue
				}
				nextA := closure(map[int]int{ma.to: 1})
				nextB := closure(map[int]int{mb.to: 1})
				for x := range nextA {
					for y := range nextB {
						np := pair{x, y}
						// 经不同边、消费非空串后到达对角配对 ⇒ 指数 pump。
						if x == y {
							res.Ambiguous = true
							res.Exponential = true
							res.Pump = pathString(parents, cur, r)
							res.Witness = res.Pump
							return res
						}
						if _, seen := parents[np]; seen {
							continue
						}
						parents[np] = pairParent{from: cur, r: r}
						queue = append(queue, np)
					}
				}
			}
		}
	}

	if res.Ambiguous {
		for p := range parents {
			if p.a == n.Accept && p.b == n.Accept {
				res.Witness = pathString(parents, p, 0)
				break
			}
		}
	}
	return res
}

// pathString 还原从 root 到 cur 的消费串，再追加一个 lastR（可为 0）。
func pathString(parents map[pair]pairParent, cur pair, lastR rune) string {
	var rev []rune
	if lastR != 0 {
		rev = append(rev, lastR)
	}
	root := pair{}
	for p := cur; p != root; {
		pp, ok := parents[p]
		if !ok {
			break
		}
		if !pp.eps && pp.r != 0 {
			rev = append(rev, pp.r)
		}
		p = pp.from
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return string(rev)
}
