<script lang="ts">
  import { onMount } from 'svelte';
  import Toolbar from './lib/Toolbar.svelte';
  import PatternList from './lib/PatternList.svelte';
  import PatternDetail from './lib/PatternDetail.svelte';
  import {
    report,
    loading,
    loadError,
    filteredPatterns,
    selectedId,
    loadReportFromUrl,
  } from './lib/stores';
  import { fmtSteps } from './lib/format';

  onMount(() => loadReportFromUrl('/sample-report.json'));

  const selected = $derived(
    $report?.patterns.find((p) => p.id === $selectedId) ?? $filteredPatterns[0] ?? null
  );
</script>

<Toolbar />

{#if $loading}
  <div class="state panel">正在加载报告…</div>
{:else if $loadError}
  <div class="state panel error">
    加载失败：{$loadError}
    <p>点击右上角「加载报告」选择 redos-hunter 生成的 JSON。</p>
  </div>
{:else if $report}
  <!-- 汇总卡片 -->
  <section class="summary">
    <div class="card panel">
      <div class="num">{$report.summary.total_patterns}</div>
      <div class="lbl">正则总数</div>
    </div>
    <div class="card panel sev-exp">
      <div class="num">{$report.summary.exponential}</div>
      <div class="lbl">指数级回溯</div>
    </div>
    <div class="card panel sev-poly">
      <div class="num">{$report.summary.polynomial}</div>
      <div class="lbl">多项式级回溯</div>
    </div>
    <div class="card panel sev-ok">
      <div class="num">{$report.summary.empirically_confirmed}</div>
      <div class="lbl">沙箱实测确认</div>
    </div>
    <div class="card panel">
      <div class="num">{$report.summary.parse_failed}</div>
      <div class="lbl">解析失败</div>
    </div>
    <div class="card panel engines">
      <div class="lbl">佐证引擎</div>
      <div class="eng-row">
        <span class:on={$report.engine_ack.node_available}>Node</span>
        <span class:on={$report.engine_ack.python_available}>Python</span>
      </div>
    </div>
  </section>

  <!-- 主体两栏 -->
  <main class="layout">
    <aside class="panel list-pane">
      <div class="pane-head">正则列表（{$filteredPatterns.length}）</div>
      <PatternList patterns={$filteredPatterns} />
    </aside>
    <section class="detail-pane">
      {#if selected}
        <PatternDetail report={selected} />
      {:else}
        <div class="state panel">选择左侧一条正则查看详情</div>
      {/if}
    </section>
  </main>

  <footer class="foot">
    静态判据（配对自动机 + 量词重叠规则）与回溯 VM 实测相互印证 · 步数与机器无关 · 报告生成于
    {$report.generated_at}
  </footer>
{/if}

<style>
  .state {
    padding: 40px;
    text-align: center;
    color: var(--fg-dim);
  }
  .state.error {
    color: var(--sev-exp-fg);
  }
  .summary {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    margin-bottom: 16px;
  }
  .card {
    padding: 14px 16px;
  }
  .num {
    font-size: 26px;
    font-weight: 800;
  }
  .lbl {
    font-size: 12px;
    color: var(--fg-dim);
    margin-top: 2px;
  }
  .sev-exp .num {
    color: var(--sev-exp-fg);
  }
  .sev-poly .num {
    color: var(--sev-poly-fg);
  }
  .sev-ok .num {
    color: var(--sev-safe-fg);
  }
  .eng-row {
    display: flex;
    gap: 8px;
    margin-top: 4px;
  }
  .eng-row span {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 999px;
    background: var(--panel-2);
    color: var(--fg-dim);
  }
  .eng-row span.on {
    background: var(--sev-safe-bg);
    color: var(--sev-safe-fg);
  }
  .layout {
    display: grid;
    grid-template-columns: 360px 1fr;
    gap: 16px;
    align-items: start;
  }
  .list-pane {
    max-height: calc(100vh - 230px);
    overflow-y: auto;
    position: sticky;
    top: 12px;
  }
  .pane-head {
    padding: 12px 14px 4px;
    font-size: 12px;
    font-weight: 700;
    color: var(--fg-dim);
  }
  .foot {
    margin: 22px 4px 8px;
    font-size: 11.5px;
    color: var(--fg-dim);
    text-align: center;
  }
  @media (max-width: 980px) {
    .summary {
      grid-template-columns: repeat(3, 1fr);
    }
    .layout {
      grid-template-columns: 1fr;
    }
    .list-pane {
      max-height: none;
      position: static;
    }
  }
</style>
