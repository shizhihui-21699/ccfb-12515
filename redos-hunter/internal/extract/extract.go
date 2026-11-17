// Package extract 从多语言源码中静态抽取正则字面量。
// 采用"逐语言扫描器"而非完整语法分析：对正则出现位置做词法级精确识别，
// 在保证字面量与标志准确的同时避免引入重型解析器依赖。
package extract

// Occurrence 一处正则字面量在源码中的出现。
type Occurrence struct {
	Language  string `json:"language"`   // javascript | typescript | python | go | java | generic
	File      string `json:"file"`       // 相对扫描根的路径
	Pattern   string `json:"pattern"`    // 正则正文（不含分隔符）
	Flags     string `json:"flags"`      // 原始标志串
	Line      int    `json:"line"`       // 1 基行号
	Col       int    `json:"col"`        // 1 基列号（字节）
	Kind      string `json:"kind"`       // literal | constructor | call-arg
	Confidence string `json:"confidence"` // high | medium | low（generic 兜底为 low）
	Raw       string `json:"raw"`        // 源码原文片段，供前端展示
	// 字符串来源标记：Python/Go 字符串实参需要反转义。
	FromString bool   `json:"from_string"`
	Quote      byte   `json:"quote"`
	RawString  bool   `json:"raw_string"` // Python r"..." / Go `...`
}

// Registry 已知的"接收正则"函数/方法名（generic 兜底与各语言共用）。
var regexFuncNames = map[string]bool{
	"compile": true, "mustcompile": true, "compileposix": true, "mustcompileposix": true,
	"match": true, "search": true, "fullmatch": true, "findall": true, "finditer": true,
	"sub": true, "subn": true, "split": true, "regexec": true, "regcomp": true,
	"regexp": true, "pattern": true, "matches": true, "replaceall": true,
}
