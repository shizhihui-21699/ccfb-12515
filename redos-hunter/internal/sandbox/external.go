package sandbox

import (
	"context"
	_ "embed"
	"encoding/json"
	"os/exec"
	"time"
)

//go:embed probes/node_probe.js
var nodeProbe string

//go:embed probes/python_probe.py
var pythonProbe string

// ExternalResult 外部真实引擎对单个攻击串的测量。
type ExternalResult struct {
	Engine    string `json:"engine"`
	Available bool   `json:"available"`
	TimedOut  bool   `json:"timed_out"`
	Ms        int64  `json:"duration_ms"`
	Matched   bool   `json:"matched"`
	Error     string `json:"error,omitempty"`
}

type probeResponse struct {
	Ms      int64 `json:"duration_ms"`
	Matched bool  `json:"matched"`
}

// NodeAvailable 检测 node 是否可用。
func NodeAvailable() bool {
	_, err := exec.LookPath("node")
	return err == nil
}

// PythonAvailable 检测 python3 是否可用。
func PythonAvailable() bool {
	_, err := exec.LookPath("python3")
	return err == nil
}

// RunNode 用 Node.js 的 RegExp 实测（回溯引擎）。
func RunNode(pattern, flags, input string, timeout time.Duration) ExternalResult {
	res := ExternalResult{Engine: "node", Available: NodeAvailable()}
	if !res.Available {
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "-e", nodeProbe, pattern, flags, input)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		return res
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var pr probeResponse
	if e := json.Unmarshal(out, &pr); e != nil {
		res.Error = e.Error()
		return res
	}
	res.Ms, res.Matched = pr.Ms, pr.Matched
	return res
}

// RunPython 用 Python re 实测（回溯引擎）。
func RunPython(pattern, input string, timeout time.Duration) ExternalResult {
	res := ExternalResult{Engine: "python", Available: PythonAvailable()}
	if !res.Available {
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-I", "-c", pythonProbe, pattern, input)
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		return res
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var pr probeResponse
	if e := json.Unmarshal(out, &pr); e != nil {
		res.Error = e.Error()
		return res
	}
	res.Ms, res.Matched = pr.Ms, pr.Matched
	return res
}
