# Python re 回溯引擎探针：python3 -I -c <script> <pattern> <input>
import json
import re
import sys
import time

pattern = sys.argv[1]
text = sys.argv[2]
t0 = time.perf_counter()
matched = False
err = ""
try:
    matched = re.search(pattern, text) is not None
except Exception as exc:  # 语法错误等：交由引擎层标记
    err = str(exc)
t1 = time.perf_counter()
sys.stdout.write(json.dumps({
    "duration_ms": round((t1 - t0) * 1000.0),
    "matched": matched,
    "error": err,
}))
