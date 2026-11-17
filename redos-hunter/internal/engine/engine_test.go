package engine_test

import (
	"testing"

	"redos-hunter/internal/analyze"
	"redos-hunter/internal/engine"
	"redos-hunter/internal/extract"
	"redos-hunter/internal/regex"
)

// 确保 Tier2 语法（反向引用/原子组/占有量词/环视/Unicode 属性）不导致崩溃，并正确降级或屏蔽。
func TestTier2SyntaxDoesNotCrash(t *testing.T) {
	cases := []struct {
		src      string
		wantNote string // 期望出现的告警 code（空表示不强制）
	}{
		{`(a+)\1`, "backref"},
		{`(?>a+)+$`, "atomic"},
		{`a++b`, "possessive"},
		{`a+(?=b)`, ""},
		{`(?!abc)a+`, ""},
		{`(?<=ab)c+`, ""},
		{`\p{L}+$`, "unicode-prop"},
		{`a*?b+?`, ""}, // 懒惰量词
		{`(?i:ab)+c`, ""},
	}
	for _, c := range cases {
		p, err := regex.Parse(c.src, regex.Flags{})
		if err != nil {
			t.Errorf("解析 %q 失败: %v", c.src, err)
			continue
		}
		// 分析不应 panic。
		res := analyze.Analyze("t", p)
		if c.wantNote != "" {
			found := false
			for _, w := range p.Warnings {
				if w.Code == c.wantNote {
					found = true
				}
			}
			if !found {
				t.Errorf("%q 期望告警 %s，实际 %+v", c.src, c.wantNote, p.Warnings)
			}
		}
		_ = res
	}
}

// 原子组/占有量词保护下的嵌套量词不应报指数级。
func TestBarriersSuppressFindings(t *testing.T) {
	safe := []string{`(?>a+)+$`, `a++b`, `(?:(?>a+))+`}
	for _, src := range safe {
		p, err := regex.Parse(src, regex.Flags{})
		if err != nil {
			t.Fatalf("解析 %q: %v", src, err)
		}
		res := analyze.Analyze("t", p)
		for _, f := range res.Findings {
			if f.Severity == analyze.SevExponential {
				t.Errorf("%q 屏障内不应报指数级，得到 finding rule=%s", src, f.Rule)
			}
		}
	}
}

// 完整引擎流水线在含 Tier2 的混合输入上产出结构完整的报告。
func TestEnginePipelineWithMixedSyntax(t *testing.T) {
	occs := []extract.Occurrence{
		{Language: "javascript", File: "x.js", Pattern: "(a+)+$", Kind: "literal", Confidence: "high"},
		{Language: "python", File: "y.py", Pattern: `(a+)\1`, Kind: "call-arg", Confidence: "high"},
		{Language: "go", File: "z.go", Pattern: `(?>a+)+$`, Kind: "call-arg", Confidence: "high"},
	}
	cfg := engine.DefaultConfig()
	cfg.EnableExternal = false
	cfg.MaxN = 14
	rep := engine.Run("/tmp/fake", occs, cfg)
	if len(rep.Patterns) != 3 {
		t.Fatalf("报告模式数 %d，期望 3", len(rep.Patterns))
	}
	if rep.Summary.Exponential < 1 {
		t.Error("至少应识别 1 条指数级")
	}
	// 每条漏洞发现都必须带实测证据。
	for _, pr := range rep.Patterns {
		for _, f := range pr.Findings {
			if f.Evidence == nil || len(f.Evidence.Points) == 0 {
				t.Errorf("%s 的发现缺少实测证据", pr.ID)
			}
		}
	}
}
