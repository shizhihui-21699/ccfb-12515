package analyze_test

import (
	"testing"

	"redos-hunter/internal/analyze"
	"redos-hunter/internal/regex"
)

func mustParse(t *testing.T, src string) *regex.Pattern {
	t.Helper()
	p, err := regex.Parse(src, regex.Flags{})
	if err != nil {
		t.Fatalf("解析 %q 失败: %v", src, err)
	}
	return p
}

func severityOf(t *testing.T, src string) analyze.Severity {
	t.Helper()
	p := mustParse(t, src)
	res := analyze.Analyze("t", p)
	if len(res.Findings) == 0 {
		return analyze.SevSafe
	}
	// 取最高等级。
	worst := analyze.SevSafe
	for _, f := range res.Findings {
		if f.Severity == analyze.SevExponential {
			return analyze.SevExponential
		}
		if f.Severity == analyze.SevPolynomial && worst != analyze.SevExponential {
			worst = analyze.SevPolynomial
		}
	}
	return worst
}

func TestExponentialPatterns(t *testing.T) {
	cases := []string{
		"(a+)+$",
		"(a|aa)*$",
		"(a*)*",
		"(a|a)*$",
		"([a-zA-Z]+)*$",
		"(\\d+)+$",
	}
	for _, src := range cases {
		if got := severityOf(t, src); got != analyze.SevExponential {
			t.Errorf("%q 期望 exponential，得到 %q", src, got)
		}
	}
}

func TestPolynomialPatterns(t *testing.T) {
	// 真正的 ≥2 层量词重叠（二次）。a*a*$ 无歧义泵、仅二次增长，属多项式而非指数。
	cases := []string{
		"a*a*$",
		"\\d*\\d*$",
	}
	for _, src := range cases {
		got := severityOf(t, src)
		if got != analyze.SevPolynomial && got != analyze.SevExponential {
			t.Errorf("%q 期望 polynomial/exponential，得到 %q", src, got)
		}
	}
}

func TestLinearOverlapIsSafe(t *testing.T) {
	// 单层量词 + 后继字面量重叠：仅线性回溯，不应报 ReDoS。
	cases := []string{
		"a*a$",
		"a*aa$",
		"\\d*\\d$",
	}
	for _, src := range cases {
		if got := severityOf(t, src); got == analyze.SevExponential || got == analyze.SevPolynomial {
			t.Errorf("%q 单层重叠应为 safe（线性），得到 %q", src, got)
		}
	}
}

func TestSafePatterns(t *testing.T) {
	cases := []string{
		"a+$",          // 重复体与后继（行尾）无字符重叠
		"[a-z]+@",      // inner 字母，后继 @，不相交
		"abc*def",      // c* 后继 d，不相交
		"\\d+-\\d+",    // 数字重复后继 -
		"foo|bar|baz",  // 无重复
		"a{3}b",        // 定界重复，后继不相交
		"[0-9a-f]{8}",  // 定界，无后继
	}
	for _, src := range cases {
		if got := severityOf(t, src); got == analyze.SevExponential || got == analyze.SevPolynomial {
			t.Errorf("%q 期望 safe，得到 %q（误报）", src, got)
		}
	}
}

func TestBarriers(t *testing.T) {
	// 原子组与占有量词应阻断 ReDoS 结论。
	cases := []string{
		"(?>a+)+$",
	}
	for _, src := range cases {
		if got := severityOf(t, src); got == analyze.SevExponential {
			t.Errorf("%q 屏障内应非 exponential，得到 %q", src, got)
		}
	}
}

func TestLazyQuantifier(t *testing.T) {
	// 懒惰量词在 aaa...! 上通常不爆炸，但配对自动机仍可能报歧义；
	// 这里只确保不崩溃且能给出结论。
	p := mustParse(t, "(a+)+?$")
	res := analyze.Analyze("t", p)
	t.Logf("(a+)+? findings=%d notes=%v", len(res.Findings), res.Notes)
}
