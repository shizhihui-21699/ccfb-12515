package sandbox

import (
	"errors"
	"time"

	"redos-hunter/internal/regex"
)

// ErrStepCap 达到步数上限（等价于"这串真的会炸"的工程信号）。
var ErrStepCap = errors.New("step cap reached")

// cont 是续体类型：在 end 位置继续匹配，返回 (是否成功, 错误)。
// 错误（如 ErrStepCap）沿整条 CPS 链无条件传播，不被回溯的 false 吞掉。
type cont func(end int) (bool, error)

// MatchResult 一次匹配测量。
type MatchResult struct {
	Matched     bool          `json:"matched"`
	Steps       int64         `json:"steps"`
	Depth       int           `json:"max_depth"`
	Duration    time.Duration `json:"duration_ns"`
	Capped      bool          `json:"capped"`
	BackrefUsed bool          `json:"backref_used"`
}

// Matcher 回溯型 VM，精确模拟 Perl/PCRE/JS 风格的递归回溯（不做记忆化）。
type Matcher struct {
	pat         *regex.Pattern
	input       []rune
	stepCap     int64
	steps       int64
	depth       int
	maxDepth    int
	caps        map[int]string
	BackrefUsed bool
}

func NewMatcher(p *regex.Pattern, stepCap int64) *Matcher {
	return &Matcher{pat: p, stepCap: stepCap, caps: map[int]string{}}
}

// Search 模拟搜索语义：从每个起点尝试，任一处成功即成功。
func (m *Matcher) Search(input string) (MatchResult, error) {
	m.input = []rune(input)
	m.reset()
	start := time.Now()
	res := MatchResult{}
	for pos := 0; pos <= len(m.input); pos++ {
		caps := map[int]string{}
		ok, err := m.matchNode(m.pat.Root, pos, func(int) (bool, error) { return true, nil }, caps)
		if err != nil {
			return m.finish(res, start, err)
		}
		if ok {
			res.Matched = true
			break
		}
	}
	return m.finish(res, start, nil)
}

// Match 从固定起点锚定匹配（不做多起点搜索），测量纯回溯成本。
func (m *Matcher) Match(input string, pos int) (MatchResult, error) {
	m.input = []rune(input)
	m.reset()
	start := time.Now()
	res := MatchResult{}
	caps := map[int]string{}
	ok, err := m.matchNode(m.pat.Root, pos, func(int) (bool, error) { return true, nil }, caps)
	res.Matched = ok
	return m.finish(res, start, err)
}

// Fullmatch 锚定整串（供等价性检验）。
func (m *Matcher) Fullmatch(input string) (MatchResult, error) {
	m.input = []rune(input)
	m.reset()
	start := time.Now()
	res := MatchResult{}
	caps := map[int]string{}
	ok, err := m.matchNode(m.pat.Root, 0, func(end int) (bool, error) {
		return end == len(m.input), nil
	}, caps)
	res.Matched = ok
	return m.finish(res, start, err)
}

func (m *Matcher) reset() {
	m.steps = 0
	m.depth = 0
	m.maxDepth = 0
	m.caps = map[int]string{}
	m.BackrefUsed = false
}

func (m *Matcher) finish(res MatchResult, start time.Time, err error) (MatchResult, error) {
	res.Duration = time.Since(start)
	res.Steps, res.Depth = m.steps, m.maxDepth
	res.BackrefUsed = m.BackrefUsed
	if err != nil {
		res.Capped = errors.Is(err, ErrStepCap)
	}
	return res, err
}

// matchNode 从 pos 匹配 n，成功则调用续体；续体返回 false 触发回溯尝试备选路径。
func (m *Matcher) matchNode(n *regex.Node, pos int, k cont, caps map[int]string) (bool, error) {
	if err := m.tick(); err != nil {
		return false, err
	}
	m.enter()
	defer m.leave()

	switch n.Kind {
	case regex.KEmpty:
		return k(pos)

	case regex.KBoundary:
		if !m.checkBoundary(n, pos) {
			return false, nil
		}
		return k(pos)

	case regex.KChar:
		if pos >= len(m.input) {
			return false, nil
		}
		for _, r := range n.Chars {
			if m.input[pos] == r {
				return k(pos + 1)
			}
		}
		return false, nil

	case regex.KClass, regex.KAny:
		if pos >= len(m.input) || !n.Set.Contains(m.input[pos]) {
			return false, nil
		}
		return k(pos + 1)

	case regex.KBackref:
		return m.matchBackref(n, pos, k, caps)

	case regex.KGroup:
		return m.matchGroup(n, pos, k, caps)

	case regex.KLook:
		return m.matchLook(n, pos, k, caps)

	case regex.KConcat:
		return m.matchConcat(n.Sub, 0, pos, k, caps)

	case regex.KAlt:
		for _, branch := range n.Sub {
			ok, err := m.matchNode(branch, pos, k, caps)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil

	case regex.KRepeat:
		return m.matchRepeat(n, pos, k, caps)
	}
	return false, nil
}

func (m *Matcher) matchConcat(seq []*regex.Node, idx, pos int, k cont, caps map[int]string) (bool, error) {
	if idx == len(seq) {
		return k(pos)
	}
	return m.matchNode(seq[idx], pos, func(next int) (bool, error) {
		return m.matchConcat(seq, idx+1, next, k, caps)
	}, caps)
}

func (m *Matcher) matchGroup(n *regex.Node, pos int, k cont, caps map[int]string) (bool, error) {
	// 原子组：只取第一个成功端点并锁死，不暴露组内其它备选路径。
	if n.Group == regex.GAtomic {
		saved := snapshot(caps)
		matched := false
		contOK := false
		ok, err := m.matchNode(n.Sub[0], pos, func(end int) (bool, error) {
			matched = true
			c, err := k(end)
			if err != nil {
				return false, err
			}
			contOK = c
			return true, nil // 立即终止组内后续端点枚举
		}, caps)
		if err != nil {
			return false, err
		}
		if !ok || !matched {
			restore(caps, saved)
			return false, nil
		}
		return contOK, nil
	}
	if n.CapID > 0 {
		saved := snapshot(caps)
		ok, err := m.matchNode(n.Sub[0], pos, func(end int) (bool, error) {
			caps[n.CapID] = string(m.input[pos:end])
			c, err := k(end)
			if err != nil {
				return false, err
			}
			if !c {
				restore(caps, saved)
			}
			return c, nil
		}, caps)
		if err != nil {
			return false, err
		}
		if !ok {
			restore(caps, saved)
		}
		return ok, nil
	}
	return m.matchNode(n.Sub[0], pos, k, caps)
}

// matchRepeat 精确量词回溯。
func (m *Matcher) matchRepeat(n *regex.Node, pos int, k cont, caps map[int]string) (bool, error) {
	possessive := n.Greedy == regex.RPossessive
	lazy := n.Greedy == regex.RLazy

	var loop func(pos, count int, committed bool) (bool, error)
	loop = func(pos, count int, committed bool) (bool, error) {
		canConsume := n.Max == -1 || count < n.Max
		meetsMin := count >= n.Min

		if lazy && meetsMin {
			ok, err := k(pos)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}

		if canConsume {
			succeeded := false
			ok, err := m.matchNode(n.Child, pos, func(end int) (bool, error) {
				if end == pos {
					return false, nil // 零宽不前进
				}
				c, e := loop(end, count+1, possessive || committed)
				if e != nil {
					return false, e
				}
				if c {
					succeeded = true
					return true, nil
				}
				return false, nil
			}, caps)
			if err != nil {
				return false, err
			}
			if ok && succeeded {
				return true, nil
			}
		}

		if committed {
			return false, nil // 占有量词锁死后不回退
		}
		if meetsMin {
			return k(pos)
		}
		return false, nil
	}
	return loop(pos, 0, false)
}

func (m *Matcher) matchLook(n *regex.Node, pos int, k cont, caps map[int]string) (bool, error) {
	saved := snapshot(caps)
	var ok bool
	var err error
	switch n.Look {
	case regex.LookAhead:
		ok, err = m.matchNode(n.Sub[0], pos, func(int) (bool, error) { return true, nil }, caps)
	case regex.LookNotAhead:
		ok, err = m.matchNode(n.Sub[0], pos, func(int) (bool, error) { return true, nil }, caps)
		ok = !ok
	case regex.LookBehind:
		ok = m.matchBehind(n.Sub[0], pos)
	case regex.LookNotBehind:
		ok = !m.matchBehind(n.Sub[0], pos)
	}
	if err != nil {
		return false, err
	}
	if !ok {
		restore(caps, saved)
		return false, nil
	}
	return k(pos)
}

func (m *Matcher) matchBehind(n *regex.Node, pos int) bool {
	for start := 0; start <= pos; start++ {
		ok, err := m.matchNode(n, start, func(end int) (bool, error) {
			return end == pos, nil
		}, map[int]string{})
		if err != nil {
			return false
		}
		if ok {
			return true
		}
	}
	return false
}

func (m *Matcher) matchBackref(n *regex.Node, pos int, k cont, caps map[int]string) (bool, error) {
	text := caps[n.RefID]
	tr := []rune(text)
	if pos+len(tr) > len(m.input) {
		return false, nil
	}
	for i, r := range tr {
		if m.input[pos+i] != r {
			return false, nil
		}
	}
	m.BackrefUsed = true
	return k(pos + len(tr))
}

func (m *Matcher) checkBoundary(n *regex.Node, pos int) bool {
	switch n.Boundary {
	case '^':
		if m.pat.Flags.M {
			return pos == 0 || pos > 0 && m.input[pos-1] == '\n'
		}
		return pos == 0
	case '$':
		if m.pat.Flags.M {
			return pos == len(m.input) || pos < len(m.input) && m.input[pos] == '\n'
		}
		return pos == len(m.input)
	case 'b', 'B':
		left := pos > 0 && isWordRune(m.input[pos-1])
		right := pos < len(m.input) && isWordRune(m.input[pos])
		isB := left != right
		if n.Boundary == 'b' {
			return isB
		}
		return !isB
	}
	return true
}

func (m *Matcher) enter() {
	m.depth++
	if m.depth > m.maxDepth {
		m.maxDepth = m.depth
	}
}
func (m *Matcher) leave() { m.depth-- }

func (m *Matcher) tick() error {
	m.steps++
	if m.steps > m.stepCap {
		return ErrStepCap
	}
	return nil
}

func isWordRune(r rune) bool {
	return r == '_' ||
		r >= '0' && r <= '9' ||
		r >= 'a' && r <= 'z' ||
		r >= 'A' && r <= 'Z'
}

func snapshot(caps map[int]string) map[int]string {
	out := make(map[int]string, len(caps))
	for k, v := range caps {
		out[k] = v
	}
	return out
}

func restore(dst, saved map[int]string) {
	for k := range dst {
		delete(dst, k)
	}
	for k, v := range saved {
		dst[k] = v
	}
}
