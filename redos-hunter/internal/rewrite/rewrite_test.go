package rewrite_test

import (
	"strings"
	"testing"

	"redos-hunter/internal/analyze"
	"redos-hunter/internal/regex"
	"redos-hunter/internal/rewrite"
)

func analyzeOne(t *testing.T, src string) (*regex.Pattern, *analyze.Finding) {
	t.Helper()
	p, err := regex.Parse(src, regex.Flags{})
	if err != nil {
		t.Fatalf("解析 %q: %v", src, err)
	}
	res := analyze.Analyze("t", p)
	if len(res.Findings) == 0 {
		t.Fatalf("%q 预期有发现但为空", src)
	}
	// 取最严重。
	var worst *analyze.Finding
	for _, f := range res.Findings {
		if worst == nil || f.Severity == analyze.SevExponential {
			worst = f
		}
	}
	return p, worst
}

func findStrategy(sugs []rewrite.Suggestion, name string) *rewrite.Suggestion {
	for i := range sugs {
		if sugs[i].Strategy == name {
			return &sugs[i]
		}
	}
	return nil
}

func TestFlattenNestedQuantifier(t *testing.T) {
	cases := map[string]string{
		"(a+)+$":   "a+$",
		"(a*)+$":   "a*$",
		"(\\d+)+-":  "[0-9]+-",
		"a(b+)+c":  "ab+c",
	}
	for src, want := range cases {
		p, f := analyzeOne(t, src)
		sugs := rewrite.Suggest(p, f)
		s := findStrategy(sugs, "flatten-nested-quantifier")
		if s == nil {
			t.Errorf("%q 缺少 flatten 建议，实际 %+v", src, strategies(sugs))
			continue
		}
		if !s.RE2Safe {
			t.Errorf("%q flatten 建议应 RE2 安全", src)
		}
		if s.Fixed != want {
			t.Errorf("%q flatten 结果 %q，期望 %q", src, s.Fixed, want)
		}
	}
}

func TestAtomicGroupSuggestion(t *testing.T) {
	// (a|aa)* 无法用单层量词合并（重复体是 alternation），应给原子组建议。
	p, f := analyzeOne(t, "(a|aa)*$")
	sugs := rewrite.Suggest(p, f)
	s := findStrategy(sugs, "atomic-group")
	if s == nil {
		t.Fatalf("(a|aa)*$ 缺少 atomic-group 建议: %+v", strategies(sugs))
	}
	if !strings.Contains(s.Fixed, "(?>") {
		t.Errorf("原子组建议未含 (?> 语法: %q", s.Fixed)
	}
	if s.RE2Safe {
		t.Errorf("原子组语法不应标记为 RE2 安全")
	}
}

func TestAtomicGroupNested(t *testing.T) {
	// (a+)+ 的原子组写法应正确包裹外层重复体。
	p, f := analyzeOne(t, "(a+)+$")
	s := findStrategy(rewrite.Suggest(p, f), "atomic-group")
	if s == nil || s.Fixed != "(?>(a+))+$" {
		t.Errorf("原子组包裹错误，得到 %+v", s)
	}
}

func TestEquivalenceAfterFlatten(t *testing.T) {
	p, f := analyzeOne(t, "(a+)+$")
	s := findStrategy(rewrite.Suggest(p, f), "flatten-nested-quantifier")
	if s == nil {
		t.Fatal("缺少 flatten 建议")
	}
	after, err := regex.Parse(s.Fixed, p.Flags)
	if err != nil {
		t.Fatalf("改写结果无法解析 %q: %v", s.Fixed, err)
	}
	ec := rewrite.CheckEquivalence(p, after, 5_000_000, 300)
	if !ec.Equivalent {
		t.Errorf("量词合并应语言等价，但发现反例: %v（%s）", ec.Countercases, ec.Note)
	}
}

func strategies(s []rewrite.Suggestion) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.Strategy
	}
	return out
}
