// Package regex 定义正则 AST 与递归下降解析器（JS/Python/PCRE/Java 公共子集 + 可降级扩展）。
package regex

import (
	"redos-hunter/internal/regex/charset"
)

// NodeKind AST 节点种类。
type NodeKind int

const (
	KEmpty NodeKind = iota
	KChar          // 单字符（Flags.i 折叠后可能对应多个码点，Chars 存折叠结果）
	KClass         // 字符类
	KAny           // .
	KBoundary      // ^ $ \b \B（零宽，不消耗字符）
	KGroup         // 普通/非捕获/命名/原子 组
	KLook          // 环视
	KConcat
	KAlt
	KRepeat
	KBackref // Tier 2：反向引用
)

// GroupKind 分组类型。
type GroupKind int

const (
	GCapture GroupKind = iota
	GNonCap
	GNamed
	GAtomic // (?>...) 回溯屏障
)

// LookKind 环视方向与极性。
type LookKind int

const (
	LookAhead  LookKind = iota // (?=
	LookNotAhead               // (?!
	LookBehind                 // (?<=
	LookNotBehind              // (?<!
)

// RepeatKind 量词的贪婪性。
type RepeatKind int

const (
	RGreedy RepeatKind = iota
	RLazy
	RPossessive // 占有量词，回溯屏障
)

type Node struct {
	Kind NodeKind
	ID   int // 全树唯一编号，解析时顺序分配

	// KChar：折叠后的全部码点（无 i 标志时只有一个）
	Chars []rune
	// KClass
	Set *charset.CharSet
	// KBoundary: '^' '$' 'b' 'B'
	Boundary byte
	// KGroup
	Group GroupKind
	Name  string
	CapID int // 捕获组编号（0 表示非捕获）
	// KLook
	Look LookKind
	// KBackref
	RefID   int
	RefName string
	// KRepeat
	Child *Node
	Min   int
	Max   int // -1 表示无界（* + {n,}）
	Greedy RepeatKind
	// KConcat / KAlt / KGroup / KLook
	Sub []*Node

	Pos int // 在源串中的起始字节偏移
}

// Flags 正则标志。
type Flags struct {
	I bool // 忽略大小写（ASCII 折叠）
	M bool // 多行
	S bool // dotall
	U bool // unicode 类语义（Python re.U/默认，影响 \w 等，本工具按 ASCII 处理，仅记录）
}

// Pattern 解析结果。
type Pattern struct {
	Source string
	Flags  Flags
	Root   *Node
	// 降级与不可分析特性记录，会原样进入报告。
	Warnings []Warning
	// 捕获组编号 -> 节点 ID，供反向引用/匹配器使用。
	Caps map[int]*Node
}

type Warning struct {
	Pos     int
	Code    string // "backref" | "atomic" | "possessive" | "unicode-prop" | "recursion" | "conditional" | ...
	Message string
}

func (p *Pattern) warn(pos int, code, msg string) {
	p.Warnings = append(p.Warnings, Warning{Pos: pos, Code: code, Message: msg})
}

// ---- 节点上的便捷谓词 ----

// IsBacktrackBarrier 原子组 / 占有量词内部不回溯。
func (n *Node) IsBacktrackBarrier() bool {
	return n.Kind == KGroup && n.Group == GAtomic ||
		n.Kind == KRepeat && n.Greedy == RPossessive
}

// HasUnsupportedFeature 子树是否含 Tier2 中无法 NFA 建模的特性。
func (n *Node) HasUnsupportedFeature() bool {
	if n == nil {
		return false
	}
	switch n.Kind {
	case KBackref:
		return true
	}
	if n.Child != nil && n.Child.HasUnsupportedFeature() {
		return true
	}
	for _, s := range n.Sub {
		if s.HasUnsupportedFeature() {
			return true
		}
	}
	return false
}

// RepeatContainsBarrier 重复体内部是否被原子组/占有量词保护（则该重复不构成 ReDoS）。
func RepeatContainsBarrier(n *Node) bool {
	barrier := false
	walk(n, func(x *Node) bool {
		if x != n && x.IsBacktrackBarrier() {
			barrier = true
			return false
		}
		return true
	})
	return barrier
}

func walk(n *Node, fn func(*Node) bool) {
	if n == nil {
		return
	}
	if !fn(n) {
		return
	}
	if n.Child != nil {
		walk(n.Child, fn)
	}
	for _, s := range n.Sub {
		walk(s, fn)
	}
}

// Walk 前序遍历；fn 返回 false 剪枝。
func Walk(n *Node, fn func(*Node) bool) { walk(n, fn) }

// AncestorOf 判断 n 是否为 target 的祖先节点。
func (n *Node) AncestorOf(target *Node) bool {
	found := false
	walk(n, func(x *Node) bool {
		if x == n {
			return true
		}
		if x == target {
			found = true
			return false
		}
		return true
	})
	return found
}

// FindRepeats 收集全树所有重复节点。
func FindRepeats(root *Node) []*Node {
	var out []*Node
	walk(root, func(n *Node) bool {
		if n.Kind == KRepeat {
			out = append(out, n)
		}
		return true
	})
	return out
}
