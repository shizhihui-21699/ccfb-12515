<script lang="ts">
  import type { PatternReport } from '../lib/types';
  import { severityMeta, langMeta, fmtSteps, fmtLocation } from '../lib/format';
  import GrowthChart from './GrowthChart.svelte';

  let { report: p }: { report: PatternReport } = $props();

  const finding = $derived(p.findings?.[0] ?? null);
  const evidence = $derived(finding?.evidence ?? null);
  const sev = $derived(
    p.parse_error ? severityMeta.unknown : finding ? severityMeta[finding.severity] : severityMeta.safe
  );
  const lang = $derived(langMeta[p.occurrence.language] ?? { label: p.occurrence.language, color: '#888' });

  function copy(text: string) {
    navigator.clipboard?.writeText(text).catch(() => {});
  }
</script>

<article class="detail panel">
  <header class="head">
    <div>
      <div class="loc mono">{fmtLocation(p)}</div>
      <h2 class="pat mono" title={p.occurrence.pattern}>/{p.occurrence.pattern}/{p.occurrence.flags}</h2>
    </div>
    <div class="head-right">
      <span class="badge" style={`color:${sev.color};background:${sev.bg};border-color:${sev.border}`}>
        {sev.label}
      </span>
      <span class="badge lang" style={`border-color:${lang.color}44;color:${lang.color}`}>{lang.label}</span>
    </div>
  </header>

  {#if p.parse_error}
    <section class="block error">
      <h3>解析失败</h3>
      <pre>{p.parse_error}</pre>
    </section>
  {:else if !finding}
    <section class="block safe-note">
      <h3>✓ 未发现回溯风险</h3>
      <p>该正则的量词与其后继字符集无重叠，或受原子组/占有量词保护，回溯成本为线性。</p>
    </section>
  {:else if evidence}
    <!-- 静态判定 -->
    <section class="block">
      <h3>静态判定</h3>
      <table class="kv">
        <tbody>
          <tr><th>触发规则</th><td><code>{finding.rule}</code></td></tr>
          <tr><th>问题量词</th><td class="mono">{finding.quantifier}</td></tr>
          <tr><th>置信度</th><td>{finding.confidence}</td></tr>
          <tr><th>泵串 (pump)</th><td class="mono">「{finding.pump_word}」</td></tr>
          {#if finding.exponential}
            <tr><th>配对状态数</th><td>{fmtSteps(finding.pair_count)}</td></tr>
          {:else}
            <tr><th>估计次数</th><td>O(n^{finding.degree})</td></tr>
          {/if}
        </tbody>
      </table>
      <p class="reason">{finding.reason}</p>
    </section>

    <!-- 实测证据 -->
    <section class="block">
      <h3>沙箱实测证据 <span class="sub">回溯 VM · 步数与机器无关</span></h3>
      <p class="attack mono">
        攻击串 = <b>{evidence.pump}</b><sup>n</sup> + 「{evidence.suffix}」
        <button class="mini" onclick={() => copy(evidence.pump.repeat(10) + evidence.suffix)}>复制样例</button>
      </p>
      <GrowthChart {evidence} />
      <div class="empirical" data-e={evidence.empirical}>
        经验分类：<b>{evidence.empirical}</b>
        {#if evidence.vm_result_at_cap.capped}<span class="cap-tag">已在 n={evidence.points.find((x) => x.capped)?.n} 撞步数上限</span>{/if}
      </div>
    </section>

    <!-- 外部真实引擎 -->
    {#if evidence.external?.length}
      <section class="block">
        <h3>真实引擎佐证</h3>
        <div class="engines">
          {#each evidence.external as e}
            <div class="engine">
              <span class="engine-name">{e.engine}</span>
              {#if e.error}
                <span class="engine-err" title={e.error}>引擎错误</span>
              {:else if e.timed_out}
                <span class="engine-timeout">超时（确认卡死）</span>
              {:else}
                <span class="engine-ok">{e.duration_ms} ms · {e.matched ? '匹配' : '不匹配'}</span>
              {/if}
            </div>
          {/each}
        </div>
      </section>
    {/if}

    <!-- 改写建议 -->
    {#if p.suggestions?.length}
      <section class="block">
        <h3>安全等价改写</h3>
        <div class="sugs">
          {#each p.suggestions as s, i}
            <div class="sug">
              <div class="sug-head">
                <span class="sug-strat">{i + 1}. {s.strategy}</span>
                <span class="badge" class:re2={s.re2_safe} style={s.re2_safe
                  ? 'color:var(--sev-safe-fg);background:var(--sev-safe-bg);border-color:var(--sev-safe-border)'
                  : 'color:var(--sev-unk-fg);background:var(--sev-unk-bg);border-color:var(--sev-unk-border)'}>
                  {s.re2_safe ? 'RE2 可用' : '回溯引擎'}
                </span>
              </div>
              <pre class="code">{s.fixed}</pre>
              <p class="why">{s.why}</p>
              <p class="equiv"><b>等价性：</b>{s.equivalent}</p>
            </div>
          {/each}
        </div>
        {#if p.equiv_check}
          <div class="equiv-check" data-ok={p.equiv_check.equivalent}>
            {p.equiv_check.equivalent ? '✓' : '✗'} 等价性检验（{p.equiv_check.tested} 个样本）：{p.equiv_check.note}
            {#if p.equiv_check.countercases?.length}
              <div class="counter">反例：{p.equiv_check.countercases.map((c) => JSON.stringify(c)).join('、')}</div>
            {/if}
          </div>
        {/if}
      </section>
    {/if}

    {#if p.warnings?.length}
      <section class="block warns">
        <h3>降级特性提示</h3>
        {#each p.warnings as w}
          <div><code>{w.Code}</code> — {w.Message}</div>
        {/each}
      </section>
    {/if}
  {/if}
</article>

<style>
  .detail {
    padding: 20px 22px;
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
    flex-wrap: wrap;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .loc {
    font-size: 12px;
    color: var(--fg-dim);
  }
  .pat {
    margin: 6px 0 0;
    font-size: 17px;
    word-break: break-all;
  }
  .head-right {
    display: flex;
    gap: 8px;
  }
  .lang {
    background: transparent;
  }
  .block {
    margin-top: 20px;
  }
  h3 {
    margin: 0 0 10px;
    font-size: 14px;
  }
  .sub {
    font-weight: 400;
    color: var(--fg-dim);
    font-size: 12px;
  }
  .kv {
    border-collapse: collapse;
    width: 100%;
  }
  .kv th {
    text-align: left;
    color: var(--fg-dim);
    font-weight: 500;
    padding: 4px 12px 4px 0;
    width: 110px;
    vertical-align: top;
  }
  .kv td {
    padding: 4px 0;
  }
  .reason {
    background: var(--panel-2);
    border-radius: 8px;
    padding: 10px 12px;
    margin: 12px 0 0;
    color: var(--fg-dim);
  }
  .attack {
    background: var(--code-bg);
    color: var(--code-fg);
    padding: 10px 12px;
    border-radius: 8px;
    margin: 0 0 14px;
    font-size: 13px;
  }
  .mini {
    padding: 1px 8px;
    font-size: 11px;
    margin-left: 8px;
    background: rgba(255, 255, 255, 0.1);
    color: var(--code-fg);
    border-color: rgba(255, 255, 255, 0.25);
  }
  .empirical {
    margin-top: 10px;
    font-size: 13px;
  }
  .empirical[data-e='exponential'] b {
    color: var(--sev-exp-fg);
  }
  .empirical[data-e='polynomial'] b {
    color: var(--sev-poly-fg);
  }
  .cap-tag {
    margin-left: 10px;
    padding: 2px 8px;
    border-radius: 6px;
    background: var(--sev-exp-bg);
    color: var(--sev-exp-fg);
    font-size: 12px;
  }
  .engines {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  }
  .engine {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 14px;
    background: var(--panel-2);
    border-radius: 8px;
    min-width: 150px;
  }
  .engine-name {
    font-weight: 700;
    text-transform: capitalize;
  }
  .engine-timeout {
    color: var(--sev-exp-fg);
    font-weight: 600;
  }
  .engine-ok {
    color: var(--fg-dim);
  }
  .sugs {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .sug {
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 14px;
  }
  .sug-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }
  .sug-strat {
    font-weight: 700;
  }
  .code {
    background: var(--code-bg);
    color: var(--code-fg);
    padding: 10px 12px;
    border-radius: 8px;
    margin: 0 0 8px;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 12.5px;
  }
  .why,
  .equiv {
    margin: 6px 0 0;
    font-size: 12.5px;
    color: var(--fg-dim);
  }
  .equiv-check {
    margin-top: 12px;
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 12.5px;
    background: var(--sev-safe-bg);
    color: var(--sev-safe-fg);
  }
  .equiv-check[data-ok='false'] {
    background: var(--sev-exp-bg);
    color: var(--sev-exp-fg);
  }
  .counter {
    margin-top: 6px;
    word-break: break-all;
  }
  .safe-note p,
  .error pre {
    color: var(--fg-dim);
  }
  .warns code {
    background: var(--panel-2);
    padding: 1px 6px;
    border-radius: 5px;
  }
</style>
