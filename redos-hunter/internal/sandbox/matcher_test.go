package sandbox_test

import (
	"strings"
	"testing"

	"redos-hunter/internal/regex"
	"redos-hunter/internal/sandbox"
)

// stepsAt 锚定从位置 0 匹配，测量纯回溯成本（不含多起点搜索噪声）。
func stepsAt(t *testing.T, pattern, input string, cap int64) int64 {
	t.Helper()
	p, err := regex.Parse(pattern, regex.Flags{})
	if err != nil {
		t.Fatalf("解析 %q: %v", pattern, err)
	}
	m := sandbox.NewMatcher(p, cap)
	res, err := m.Match(input, 0)
	if err != nil && err != sandbox.ErrStepCap {
		t.Fatalf("匹配 %q 出错: %v", pattern, err)
	}
	return res.Steps
}

func TestExponentialGrowth(t *testing.T) {
	for _, n := range []int{12, 14, 16, 18} {
		s := stepsAt(t, "(a+)+$", strings.Repeat("a", n)+"!", 200_000_000)
		t.Logf("n=%d steps=%d", n, s)
	}
	s16 := stepsAt(t, "(a+)+$", strings.Repeat("a", 16)+"!", 200_000_000)
	s18 := stepsAt(t, "(a+)+$", strings.Repeat("a", 18)+"!", 200_000_000)
	ratio := float64(s18) / float64(s16)
	t.Logf("exponential ratio n+2: %.2f（应≈4）", ratio)
	if ratio < 3.0 {
		t.Errorf("指数曲线步数比过小: %.2f", ratio)
	}
}

func TestQuadraticGrowth(t *testing.T) {
	// a*a*$ 对 a^n + "!"：锚定匹配下主导项 O(n^2)。
	// 含线性常数项，小 n 比值偏低，故取较大 n 并放宽下界。
	s20 := stepsAt(t, "a*a*$", strings.Repeat("a", 20)+"!", 200_000_000)
	s80 := stepsAt(t, "a*a*$", strings.Repeat("a", 80)+"!", 200_000_000)
	r := float64(s80) / float64(s20)
	t.Logf("quadratic x4 ratio (n=20→80): %.2f (理想16，含线性项偏低)", r)
	if r < 10 || r > 20 {
		t.Errorf("二次曲线比值异常: %.2f（应在 10~20）", r)
	}
	// 与指数对照：同样 n+2，二次比值应远小于指数的 ~4。
	s30 := stepsAt(t, "a*a*$", strings.Repeat("a", 30)+"!", 200_000_000)
	s32 := stepsAt(t, "a*a*$", strings.Repeat("a", 32)+"!", 200_000_000)
	t.Logf("quadratic n+2 ratio: %.2f（指数为≈4）", float64(s32)/float64(s30))
}

func TestLinearSafe(t *testing.T) {
	// a+$ 锚定匹配：线性，n 翻 4 倍步数约 ×4，且绝对值有界。
	s10 := stepsAt(t, "a+$", strings.Repeat("a", 10)+"!", 200_000_000)
	s40 := stepsAt(t, "a+$", strings.Repeat("a", 40)+"!", 200_000_000)
	r := float64(s40) / float64(s10)
	t.Logf("linear x4 ratio: %.2f (s10=%d s40=%d)", r, s10, s40)
	if r > 6 {
		t.Errorf("安全模式步数比异常（疑似非线性）: %.2f", r)
	}
	if s40 > 3000 {
		t.Errorf("线性模式绝对步数过高: %d", s40)
	}
}

func TestStepCapTriggers(t *testing.T) {
	// n=20 的指数输入实测约 5×2^20 ≈ 520 万步，10 万上限必然触发。
	p, _ := regex.Parse("(a+)+$", regex.Flags{})
	m := sandbox.NewMatcher(p, 100_000)
	_, err := m.Match(strings.Repeat("a", 20)+"!", 0)
	if err != sandbox.ErrStepCap {
		t.Fatalf("期望 ErrStepCap，得到 %v", err)
	}
}

func TestAtomicGroupNoExplosion(t *testing.T) {
	// (?>a+)+ 原子组消除回溯，长失败输入也应快速完成且步数有界。
	p, _ := regex.Parse("(?>a+)+$", regex.Flags{})
	m := sandbox.NewMatcher(p, 50_000_000)
	res, err := m.Match(strings.Repeat("a", 500)+"!", 0)
	if err != nil {
		t.Fatalf("原子组不应触发 cap: %v", err)
	}
	t.Logf("atomic group steps=%d matched=%v", res.Steps, res.Matched)
	if res.Steps > 100_000 {
		t.Errorf("原子组步数异常高: %d", res.Steps)
	}
}
