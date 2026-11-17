// Node 回溯引擎探针：node -e <script> <pattern> <flags> <input>
// 注意：node -e 模式下自定义参数从 process.argv[1] 开始（无脚本路径占位）。
const [, pattern, flags, input] = process.argv;
const t0 = process.hrtime.bigint();
let matched = false;
let errMsg = "";
try {
  const re = new RegExp(pattern, flags.includes("g") ? flags : flags.replace("g", ""));
  matched = re.test(input);
} catch (e) {
  errMsg = String(e && e.message ? e.message : e);
}
const t1 = process.hrtime.bigint();
const durationMs = Math.round(Number(t1 - t0) / 1e6);
process.stdout.write(JSON.stringify({ duration_ms: durationMs, matched, error: errMsg }));
