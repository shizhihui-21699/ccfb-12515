// Package engine 编排完整 ReDoS 分析流水线并产出统一报告。
package engine

import (
	"fmt"
	"time"

	"redos-hunter/internal/analyze"
	"redos-hunter/internal/attack"
	"redos-hunter/internal/extract"
	"redos-hunter/internal/regex"
	"redos-hunter/internal/rewrite"
	"redos-hunter/internal/sandbox"
)

// Config 引擎配置。
type Config struct {
	StepCap        int64         // 回溯 VM 步数上限
	MaxN           int           // 攻击串规模上界
	ExternalTimeout time.Duration // 外部引擎超时
	EnableExternal bool          // 是否调用 Node/Python 真实引擎
	Samples        int           // 等价性检验样本数
}

// DefaultConfig 默认配置。
func DefaultConfig() Config {
	return Config{
		StepCap:         2_000_000,
		MaxN:            26,
		ExternalTimeout: 3 * time.Second,
		EnableExternal:  true,
		Samples:         200,
	}
}

// Point 曲线数据点（对外报告用）。
type Point = attack.Point

// Evidence 一条发现的实测证据。
type Evidence struct {
	CandidateName string             `json:"candidate_name"`
	Pump          string             `json:"pump"`
	Suffix        string             `json:"suffix"`
	Points        []Point            `json:"points"`
	Fit           attack.GrowthFit   `json:"fit"`
	Empirical     string             `json:"empirical"` // exponential | polynomial | linear | inconclusive
	Node          sandbox.MatchResult `json:"vm_result_at_cap"`
	External      []sandbox.ExternalResult `json:"external,omitempty"`
}

// PatternReport 一条正则的完整报告。
type PatternReport struct {
	ID         string                 `json:"id"`
	Occurrence extract.Occurrence     `json:"occurrence"`
	ParseError string                 `json:"parse_error,omitempty"`
	Warnings   []regex.Warning        `json:"warnings"`
	Findings   []FindingReport        `json:"findings"`
	Suggestions []rewrite.Suggestion  `json:"suggestions"`
	EquivCheck *rewrite.EquivCheck   `json:"equiv_check,omitempty"`
}

// FindingReport 静态发现 + 实测证据。
type FindingReport struct {
	*analyze.Finding
	Evidence *Evidence `json:"evidence"`
}

// Report 整个扫描的汇总。
type Report struct {
	GeneratedAt   string          `json:"generated_at"`
	Root          string          `json:"root"`
	Config        Config          `json:"config"`
	Summary       Summary         `json:"summary"`
	Patterns      []PatternReport `json:"patterns"`
	EngineAck     EngineAck       `json:"engine_ack"`
}

type Summary struct {
	TotalPatterns   int `json:"total_patterns"`
	ParseFailed     int `json:"parse_failed"`
	Exponential     int `json:"exponential"`
	Polynomial      int `json:"polynomial"`
	Unknown         int `json:"unknown"`
	EmpiricallyConfirmed int `json:"empirically_confirmed"`
}

type EngineAck struct {
	NodeAvailable   bool `json:"node_available"`
	PythonAvailable bool `json:"python_available"`
}

// Run 对一组抽取结果执行完整流水线。
func Run(root string, occs []extract.Occurrence, cfg Config) *Report {
	rep := &Report{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Root:        root,
		Config:      cfg,
		EngineAck: EngineAck{
			NodeAvailable:   sandbox.NodeAvailable(),
			PythonAvailable: sandbox.PythonAvailable(),
		},
	}

	for i, occ := range occs {
		pid := fmt.Sprintf("p%d", i+1)
		pr := PatternReport{ID: pid, Occurrence: occ}
		p, err := regex.Parse(occ.Pattern, flagsFromOccurrence(occ))
		if err != nil {
			pr.ParseError = err.Error()
			rep.Summary.ParseFailed++
			rep.Patterns = append(rep.Patterns, pr)
			continue
		}
		pr.Warnings = p.Warnings

		res := analyze.Analyze(pid, p)
		best := pickWorstFinding(res.Findings)
		if best != nil {
			fr := FindingReport{Finding: best}
			fr.Evidence = gatherEvidence(p, best, cfg, occ)
			classifyFinding(&fr, &rep.Summary)
			pr.Findings = append(pr.Findings, fr)
		}
		for _, note := range res.Notes {
			_ = note
		}

		// 改写建议基于最严重发现生成。
		if len(pr.Findings) > 0 {
			pr.Suggestions = rewrite.Suggest(p, pr.Findings[0].Finding)
			pr.EquivCheck = checkFirstSuggestion(p, pr.Suggestions, cfg)
		}

		rep.Patterns = append(rep.Patterns, pr)
	}
	rep.Summary.TotalPatterns = len(occs)
	return rep
}

// pickWorstFinding 同一模式可能命中多条规则，只保留最严重的一条（指数 > 多项式 > 未知）。
func pickWorstFinding(fs []*analyze.Finding) *analyze.Finding {
	var best *analyze.Finding
	bestRank := 0
	for _, f := range fs {
		r := sevRank(f.Severity)
		if r > bestRank {
			best, bestRank = f, r
		}
	}
	return best
}

func sevRank(s analyze.Severity) int {
	switch s {
	case analyze.SevExponential:
		return 3
	case analyze.SevPolynomial:
		return 2
	case analyze.SevUnknown:
		return 1
	}
	return 0
}

func classifyFinding(fr *FindingReport, sum *Summary) {
	switch fr.Severity {
	case analyze.SevExponential:
		sum.Exponential++
	case analyze.SevPolynomial:
		sum.Polynomial++
	case analyze.SevUnknown:
		sum.Unknown++
	}
	if fr.Evidence != nil && (fr.Evidence.Empirical == "exponential" || fr.Evidence.Empirical == "polynomial") {
		sum.EmpiricallyConfirmed++
	}
}

func gatherEvidence(p *regex.Pattern, f *analyze.Finding, cfg Config, occ extract.Occurrence) *Evidence {
	cands := attack.BuildCandidates(p, f)
	var best *Evidence
	for _, c := range cands {
		pts, _ := attack.Probe(p, c, cfg.StepCap, cfg.MaxN)
		fit := attack.FitGrowth(pts)
		emp := empiricalClass(fit, pts)
		// 选最严重的候选作为代表证据。
		if best == nil || rank(emp) > rank(best.Empirical) {
			ev := &Evidence{
				CandidateName: c.Name, Pump: c.Pump, Suffix: c.Suffix,
				Points: pts, Fit: fit, Empirical: emp,
			}
			// 外部真实引擎佐证（仅对超线性且最严重候选，控制子进程数量）。
			if cfg.EnableExternal && rank(emp) >= rank("polynomial") {
				ev.External = runExternal(p, c, cfg, occ)
			}
			best = ev
		}
	}
	if best == nil {
		return &Evidence{Empirical: "inconclusive"}
	}
	return best
}

func runExternal(p *regex.Pattern, c attack.Candidate, cfg Config, occ extract.Occurrence) []sandbox.ExternalResult {
	var out []sandbox.ExternalResult
	// 取一个会触发但不会让外部引擎挂太久的中等规模输入。
	n := cfg.MaxN
	if n > 24 {
		n = 24
	}
	input := c.At(n)
	flags := translateFlags(occ)
	if sandbox.NodeAvailable() {
		out = append(out, sandbox.RunNode(p.Source, flags, input, cfg.ExternalTimeout))
	}
	if sandbox.PythonAvailable() && occ.Language != "javascript" && occ.Language != "typescript" {
		out = append(out, sandbox.RunPython(p.Source, input, cfg.ExternalTimeout))
	}
	return out
}

func empiricalClass(fit attack.GrowthFit, pts []Point) string {
	// 有任何点撞到步数上限，直接按对应静态强度判超线性。
	for _, pt := range pts {
		if pt.Capped {
			if fit.Kind == "polynomial" {
				return "polynomial"
			}
			return "exponential"
		}
	}
	switch fit.Kind {
	case "exponential":
		return "exponential"
	case "polynomial":
		return "polynomial"
	case "linear":
		return "linear"
	default:
		return "inconclusive"
	}
}

func rank(s string) int {
	switch s {
	case "exponential":
		return 3
	case "polynomial":
		return 2
	case "linear":
		return 1
	}
	return 0
}

// checkFirstSuggestion 选第一条真正改写了模式且 RE2 安全的建议做有限样本等价检验。
// "use-linear-engine" 建议的模式就是原串，无需检验，跳过。
func checkFirstSuggestion(p *regex.Pattern, sugs []rewrite.Suggestion, cfg Config) *rewrite.EquivCheck {
	for _, s := range sugs {
		if !s.RE2Safe || s.Strategy == "use-linear-engine" {
			continue
		}
		after, err := regex.Parse(stripHint(s.Fixed), p.Flags)
		if err != nil {
			continue
		}
		ec := rewrite.CheckEquivalence(p, after, cfg.StepCap, cfg.Samples)
		return &ec
	}
	return nil
}

// stripHint 去掉 fixed 文本里附加的中文说明（// 之后），仅保留正则本体。
func stripHint(s string) string {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '/' && s[i+1] == '/' {
			return trimSpace(s[:i])
		}
	}
	return trimSpace(s)
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func flagsFromOccurrence(occ extract.Occurrence) regex.Flags {
	var f regex.Flags
	for _, c := range occ.Flags {
		switch c {
		case 'i':
			f.I = true
		case 'm':
			f.M = true
		case 's':
			f.S = true
		case 'u':
			f.U = true
		}
	}
	return f
}

func translateFlags(occ extract.Occurrence) string {
	// 外部引擎只接受其支持的标志；JS 用原 flags，Python 用空（在 pattern 内联标志）。
	return occ.Flags
}
