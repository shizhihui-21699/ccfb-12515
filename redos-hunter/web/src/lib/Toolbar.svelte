<script lang="ts">
  import { get } from 'svelte/store';
  import type { Severity } from '../lib/types';
  import {
    report,
    severityFilter,
    languageFilter,
    search,
    languages,
    loadReportFromFile,
  } from '../lib/stores';
  import { severityMeta, exportCsv, download } from '../lib/format';

  let theme = $state<'light' | 'dark'>(
    (typeof window !== 'undefined' &&
      (localStorage.getItem('theme') ??
        (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))) as
      | 'light'
      | 'dark'
  );

  $effect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('theme', theme);
  });

  const sevKeys: Severity[] = ['exponential', 'polynomial', 'unknown', 'safe'];

  function toggleSev(k: Severity) {
    const next = new Set(get(severityFilter));
    next.has(k) ? next.delete(k) : next.add(k);
    severityFilter.set(next);
  }

  function onFile(e: Event) {
    const input = e.target as HTMLInputElement;
    if (input.files?.[0]) loadReportFromFile(input.files[0]);
  }

  function doExport() {
    const r = get(report);
    if (r) download('redos-report.csv', exportCsv(r), 'text/csv');
  }

  const counts = $derived.by(() => {
    const c: Record<string, number> = { exponential: 0, polynomial: 0, unknown: 0, safe: 0 };
    for (const p of $report?.patterns ?? []) {
      const sev = p.parse_error
        ? 'unknown'
        : !p.findings || p.findings.length === 0
          ? 'safe'
          : p.findings[0].severity;
      c[sev]++;
    }
    return c;
  });
</script>

<header class="toolbar panel">
  <div class="brand">
    <div class="logo">Re<span>DoS</span></div>
    <div class="title">
      <strong>正则回溯风险报告</strong>
      <small>{$report ? $report.root : '未加载报告'}</small>
    </div>
  </div>

  <div class="controls">
    <div class="sev-toggle">
      {#each sevKeys as k}
        {@const meta = severityMeta[k]}
        <button
          class="seg"
          class:on={$severityFilter.has(k)}
          style={$severityFilter.has(k)
            ? `color:${meta.color};background:${meta.bg};border-color:${meta.border}`
            : ''}
          onclick={() => toggleSev(k)}
        >
          {meta.label}
          <span class="count">{counts[k]}</span>
        </button>
      {/each}
    </div>

    <select bind:value={$languageFilter}>
      <option value="all">全部语言</option>
      {#each $languages as l}
        <option value={l}>{l}</option>
      {/each}
    </select>

    <input placeholder="搜索正则 / 文件 / ID" bind:value={$search} />

    <label class="upload">
      <input type="file" accept="application/json,.json" onchange={onFile} hidden />
      加载报告
    </label>
    <button onclick={doExport} disabled={!$report}>CSV</button>
    <button class="icon" onclick={() => (theme = theme === 'dark' ? 'light' : 'dark')} title="切换主题">
      {theme === 'dark' ? '☀' : '☾'}
    </button>
  </div>
</header>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
    padding: 12px 18px;
    margin-bottom: 16px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .logo {
    font-size: 22px;
    font-weight: 800;
    letter-spacing: -0.5px;
  }
  .logo span {
    color: var(--sev-exp-fg);
  }
  .title {
    display: flex;
    flex-direction: column;
  }
  .title small {
    color: var(--fg-dim);
    font-size: 11px;
    max-width: 320px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .controls {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .sev-toggle {
    display: flex;
    gap: 4px;
  }
  .seg {
    padding: 5px 10px;
    font-size: 12.5px;
    opacity: 0.55;
  }
  .seg.on {
    opacity: 1;
  }
  .count {
    font-weight: 700;
    margin-left: 3px;
  }
  .upload {
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 6px 12px;
    cursor: pointer;
    background: var(--panel);
    font-size: 14px;
  }
  .upload:hover {
    border-color: var(--accent);
  }
  .icon {
    font-size: 16px;
    line-height: 1;
  }
  input {
    min-width: 180px;
  }
</style>
