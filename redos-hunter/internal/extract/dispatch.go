package extract

import (
	"os"
	"path/filepath"
	"strings"
)

// ScanFile 按扩展名选择扫描器。
func ScanFile(path string) ([]Occurrence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	src := string(data)
	rel := path
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return ScanJavaScript(rel, src), nil
	case ".py", ".pyi":
		return ScanPython(rel, src), nil
	case ".go":
		return ScanGo(rel, src), nil
	case ".java":
		return ScanJava(rel, src), nil
	default:
		// 通用兜底：低置信度，仅识别明显的 regex 调用实参。
		return scanGeneric(rel, src), nil
	}
}

// ScanDir 递归扫描目录，跳过常见无关目录。
func ScanDir(root string) ([]Occurrence, error) {
	var all []Occurrence
	skipDirs := map[string]bool{
		"node_modules": true, ".git": true, "vendor": true, "dist": true,
		"build": true, ".venv": true, "venv": true, "__pycache__": true,
		"target": true, ".idea": true, ".vscode": true,
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		occs, e := ScanFile(path)
		if e != nil {
			return nil // 单个文件失败不阻断整体扫描
		}
		all = append(all, occs...)
		return nil
	})
	return all, err
}

// scanGeneric 任意语言的兜底：找 compile/match/regex 等函数的字符串首参，标低置信度。
func scanGeneric(file, src string) []Occurrence {
	s := newScanner(src)
	var out []Occurrence
	for !s.done() {
		c := s.peek()
		if c == '"' || c == '\'' {
			startLine, startCol := s.location()
			startPos := s.pos
			content, closed := s.readQuotedString(c)
			raw := s.src[startPos:s.pos]
			if closed && looksLikeRegex(content) && s.genericCallBefore(startPos) {
				out = append(out, Occurrence{
					Language: "generic", File: file, Pattern: unescapeJS(content), Flags: "",
					Line: startLine, Col: startCol, Kind: "call-arg", Confidence: "low",
					Raw: raw, FromString: true, Quote: c,
				})
			}
			continue
		}
		if isIdentStart(c) {
			s.readIdentifier()
			continue
		}
		s.advance()
	}
	return out
}

func (s *scanner) genericCallBefore(strStart int) bool {
	i := strStart - 1
	for i >= 0 && (s.src[i] == ' ' || s.src[i] == '\t' || s.src[i] == '\n' || s.src[i] == '\r') {
		i--
	}
	if i < 0 || s.src[i] != '(' {
		return false
	}
	i--
	for i >= 0 && (s.src[i] == ' ' || s.src[i] == '\t') {
		i--
	}
	end := i + 1
	for i >= 0 && isIdentPart(s.src[i]) {
		i--
	}
	name := strings.ToLower(s.src[i+1 : end])
	return regexFuncNames[name]
}

// looksLikeRegex 启发式：含典型正则元字符，避免把普通字符串当正则。
func looksLikeRegex(s string) bool {
	meta := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '*', '+', '?', '[', ']', '(', ')', '|', '^', '$', '{':
			meta++
		}
	}
	return meta >= 2
}
