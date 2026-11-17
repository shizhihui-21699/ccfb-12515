package attack_test

import (
	"strings"
	"testing"

	"redos-hunter/internal/analyze"
	"redos-hunter/internal/attack"
	"redos-hunter/internal/regex"
)

func firstFinding(t *testing.T, src string) (*regex.Pattern, *analyze.Finding) {
	t.Helper()
	p, err := regex.Parse(src, regex.Flags{})
	if err != nil {
		t.Fatalf("解析 %q: %v", src, err)
	}
	res := analyze.Analyze("t", p)
	if len(res.Findings) == 0 {
		t.Fatalf("%q 无发现", src)
	}
	return p, res.Findings[0]
}

func TestBuildCandidates(t *testing.T) {
	p, f := firstFinding(t, "(a+)+$")
	cands := attack.BuildCandidates(p, f)
	if len(cands) < 3 {
		t.Fatalf("候选过少: %d", len(cands))
	}
	// 至少有一个 pump-then-killer 候选，且其攻击串随 n 增长。
	var killer attack.Candidate
	for _, c := range cands {
		if strings.HasPrefix(c.Name, "pump-then-killer") {
			killer = c
			break
		}
	}
	if killer.Pump == "" {
		t.Fatal("未找到带 pump 的候选")
	}
	s5 := killer.At(5)
	if !strings.HasPrefix(s5, strings.Repeat(killer.Pump, 5)) {
		t.Errorf("攻击串构造错误: %q", s5)
	}
}

func TestProbeFindsSuperLinear(t *testing.T) {
	p, f := firstFinding(t, "(a+)+$")
	cands := attack.BuildCandidates(p, f)
	hit := false
	for _, c := range cands {
		pts, super := attack.Probe(p, c, 2_000_000, 18)
		if super {
			hit = true
			fit := attack.FitGrowth(pts)
			if fit.Kind != "exponential" {
				t.Errorf("指数模式拟合为 %s（应 exponential）", fit.Kind)
			}
			break
		}
	}
	if !hit {
		t.Error("所有候选都未测出超线性增长")
	}
}

func TestProbeSafePatternLinear(t *testing.T) {
	// 安全模式 a+$ 不应被判为超线性。
	p, err := regex.Parse("a+$", regex.Flags{})
	if err != nil {
		t.Fatal(err)
	}
	// 手工构造一个简单候选。
	c := attack.Candidate{Name: "x", Pump: "a", Suffix: "!"}
	pts, super := attack.Probe(p, c, 2_000_000, 18)
	fit := attack.FitGrowth(pts)
	if super {
		t.Errorf("安全模式误判超线性，fit=%s", fit.Kind)
	}
}
