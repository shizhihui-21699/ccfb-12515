// Command redos-hunter 扫描代码库中的正则并产出 ReDoS 分析报告。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"redos-hunter/internal/engine"
	"redos-hunter/internal/extract"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "version":
		fmt.Println("redos-hunter dev")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法:
  redos-hunter scan [flags] <路径...>
    --out report.json      JSON 报告输出路径（缺省输出到 stdout）
    --step-cap N           回溯 VM 步数上限（默认 2000000）
    --max-n N              攻击串规模上界（默认 26）
    --no-external          禁用 Node/Python 外部引擎佐证
    --external-timeout D   外部引擎单次超时（默认 3s）
    --samples N            等价性检验样本数（默认 200）
  redos-hunter version`)
}

// splitFlagsAndPaths 把 flag（以 - 开头）与位置路径分开，
// 使路径写在 flag 前后都能被 Go flag 包正确解析。
func splitFlagsAndPaths(args []string) (paths, fsArgs []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			fsArgs = append(fsArgs, a)
			// 带值的非布尔 flag：把下一个参数也归入 flag 部分。
			name := a
			if eq := indexByte(a, '='); eq >= 0 {
				name = a[:eq]
			}
			if !boolFlags[trimDash(name)] && indexByte(a, '=') < 0 && i+1 < len(args) {
				fsArgs = append(fsArgs, args[i+1])
				i++
			}
			continue
		}
		paths = append(paths, a)
	}
	return paths, fsArgs
}

var boolFlags = map[string]bool{"no-external": true}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func trimDash(s string) string {
	for len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	return s
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	outPath := fs.String("out", "", "JSON 报告输出路径（缺省输出到 stdout）")
	stepCap := fs.Int64("step-cap", 2_000_000, "回溯 VM 步数上限")
	maxN := fs.Int("max-n", 26, "攻击串规模上界")
	noExternal := fs.Bool("no-external", false, "禁用 Node/Python 外部引擎佐证")
	timeout := fs.Duration("external-timeout", 3*time.Second, "外部引擎单次超时")
	samples := fs.Int("samples", 200, "等价性检验样本数")
	paths, fsArgs := splitFlagsAndPaths(args)
	_ = fs.Parse(fsArgs)
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "scan 需要至少一个路径参数")
		os.Exit(2)
	}

	cfg := engine.DefaultConfig()
	cfg.StepCap = *stepCap
	cfg.MaxN = *maxN
	cfg.EnableExternal = !*noExternal
	cfg.ExternalTimeout = *timeout
	cfg.Samples = *samples

	var occs []extract.Occurrence
	root := paths[0]
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "跳过不可访问路径 %s: %v\n", path, err)
			continue
		}
		if info.IsDir() {
			found, e := extract.ScanDir(path)
			if e != nil {
				fmt.Fprintf(os.Stderr, "扫描目录 %s 出错: %v\n", path, e)
			}
			occs = append(occs, found...)
		} else {
			found, e := extract.ScanFile(path)
			if e != nil {
				fmt.Fprintf(os.Stderr, "扫描文件 %s 出错: %v\n", path, e)
				continue
			}
			occs = append(occs, found...)
		}
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}

	report := engine.Run(root, occs, cfg)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "报告序列化失败: %v\n", err)
		os.Exit(1)
	}
	if *outPath == "" {
		fmt.Println(string(data))
		return
	}
	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写报告失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "报告已写入 %s（正则 %d 条，指数 %d，多项式 %d，实测确认 %d）\n",
		*outPath, report.Summary.TotalPatterns, report.Summary.Exponential,
		report.Summary.Polynomial, report.Summary.EmpiricallyConfirmed)
}
