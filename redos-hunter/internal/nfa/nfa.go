package nfa

import (
	"redos-hunter/internal/regex"
	"redos-hunter/internal/regex/charset"
)

// Trans 一条转移；Set==nil 表示 ε 转移。
type Trans struct {
	Set *charset.CharSet
	To  int
}

type State struct {
	Trans []Trans
}

// RepeatSpan 重复节点在 NFA 中的入口/出口。
type RepeatSpan struct {
	NodeID int
	Entry  int
	Exit   int
}

type NFA struct {
	States    []*State
	Start     int
	Accept    int
	Spans     map[int]*RepeatSpan // Node.ID -> span
	NodeStart map[int]int         // 节点 ID -> 片段起点
}

type builder struct {
	nfa *NFA
}

func Build(p *regex.Pattern) *NFA {
	b := &builder{nfa: &NFA{Spans: map[int]*RepeatSpan{}, NodeStart: map[int]int{}}}
	b.newState() // 0 号状态占位，避免状态 0 与"无"混淆
	start, end := b.build(p.Root)
	accept := b.newState()
	b.epsilon(end, accept)
	b.nfa.Start = start
	b.nfa.Accept = accept
	return b.nfa
}

// BuildSub 只构建某个子节点（用于重复体的独立歧义分析）。
func BuildSub(n *regex.Node) *NFA {
	b := &builder{nfa: &NFA{Spans: map[int]*RepeatSpan{}, NodeStart: map[int]int{}}}
	b.newState()
	start, end := b.build(n)
	accept := b.newState()
	b.epsilon(end, accept)
	b.nfa.Start = start
	b.nfa.Accept = accept
	return b.nfa
}

func (b *builder) newState() int {
	id := len(b.nfa.States)
	b.nfa.States = append(b.nfa.States, &State{})
	return id
}

func (b *builder) epsilon(from, to int) {
	b.nfa.States[from].Trans = append(b.nfa.States[from].Trans, Trans{To: to})
}

func (b *builder) edge(from int, set *charset.CharSet, to int) {
	b.nfa.States[from].Trans = append(b.nfa.States[from].Trans, Trans{Set: set, To: to})
}

// build 返回子片段的 (起点, 终点)，终点是无出边的悬挂状态。
func (b *builder) build(n *regex.Node) (int, int) {
	if n == nil || n.Kind == regex.KEmpty {
		s, e := b.newState(), b.newState()
		b.epsilon(s, e)
		return s, e
	}
	switch n.Kind {
	case regex.KChar:
		s, e := b.newState(), b.newState()
		set := charset.Empty()
		for _, r := range n.Chars {
			set = charset.Union(set, charset.Singleton(r))
		}
		b.edge(s, set, e)
		b.nfa.NodeStart[n.ID] = s
		return s, e

	case regex.KClass, regex.KAny:
		s, e := b.newState(), b.newState()
		b.edge(s, n.Set, e)
		b.nfa.NodeStart[n.ID] = s
		return s, e

	case regex.KBoundary:
		s, e := b.newState(), b.newState()
		b.epsilon(s, e)
		b.nfa.NodeStart[n.ID] = s
		return s, e

	case regex.KBackref:
		// Tier2：无法 NFA 建模，退化为 ε；分析器依据 AST 告警降级。
		s, e := b.newState(), b.newState()
		b.epsilon(s, e)
		b.nfa.NodeStart[n.ID] = s
		return s, e

	case regex.KGroup, regex.KLook:
		s, e := b.build(n.Sub[0])
		b.nfa.NodeStart[n.ID] = s
		return s, e

	case regex.KConcat:
		s := b.newState()
		b.nfa.NodeStart[n.ID] = s
		prev := s
		for _, sub := range n.Sub {
			cs, ce := b.build(sub)
			b.epsilon(prev, cs)
			prev = ce
		}
		return s, prev

	case regex.KAlt:
		s, e := b.newState(), b.newState()
		b.nfa.NodeStart[n.ID] = s
		for _, sub := range n.Sub {
			cs, ce := b.build(sub)
			b.epsilon(s, cs)
			b.epsilon(ce, e)
		}
		return s, e

	case regex.KRepeat:
		return b.buildRepeat(n)
	}
	s, e := b.newState(), b.newState()
	return s, e
}

// buildRepeat 通用量词构造。
// 结构：entry → [min 份串联的 child] → tail；tail 上每一份可选 child 都是 ε 进/ε 出且带回环，
// 直到 max 份（max=-1 表示无界，尾状态自循环）。
func (b *builder) buildRepeat(n *regex.Node) (int, int) {
	entry := b.newState()
	b.nfa.NodeStart[n.ID] = entry
	exit := b.newState()

	// min 份强制拷贝。
	prev := entry
	for k := 0; k < n.Min; k++ {
		cs, ce := b.build(n.Child)
		b.epsilon(prev, cs)
		prev = ce
	}

	// 可选部分。
	optional := n.Max - n.Min // -1(无界) 时为负数
	if n.Max == -1 {
		// 无界：tail 状态上 child 可重复任意次，也可 ε 离开。
		tail := b.newState()
		b.epsilon(prev, tail)
		cs, ce := b.build(n.Child)
		b.epsilon(tail, cs)
		b.epsilon(ce, tail)
		b.epsilon(tail, exit)
	} else if optional > 0 {
		tail := prev
		for k := 0; k < optional; k++ {
			cs, ce := b.build(n.Child)
			b.epsilon(tail, cs) // 选择消费一份
			b.epsilon(tail, exit) // 或提前结束（在最后一份上多余但无害）
			tail = ce
		}
		b.epsilon(tail, exit)
	} else {
		b.epsilon(prev, exit)
	}

	b.nfa.Spans[n.ID] = &RepeatSpan{NodeID: n.ID, Entry: entry, Exit: exit}
	return entry, exit
}
