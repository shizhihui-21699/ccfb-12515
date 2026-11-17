<script lang="ts">
  import type { PatternReport } from '../lib/types';
  import { severityMeta, langMeta, fmtLocation } from '../lib/format';
  import { selectedId, severityOf } from '../lib/stores';

  let { patterns }: { patterns: PatternReport[] } = $props();

  function sev(p: PatternReport) {
    return severityMeta[severityOf(p)];
  }
</script>

<ul class="list">
  {#each patterns as p (p.id)}
    {@const meta = sev(p)}
    {@const lang = langMeta[p.occurrence.language] ?? { label: p.occurrence.language }}
    <li>
      <button
        class="item"
        class:active={$selectedId === p.id}
        onclick={() => (selectedId.set(p.id))}
      >
        <div class="row1">
          <span class="dot" style={`background:${meta.color}`}></span>
          <span class="pat mono" title={p.occurrence.pattern}>/ {p.occurrence.pattern} /</span>
        </div>
        <div class="row2">
          <span class="loc">{fmtLocation(p)}</span>
          <span class="tags">
            <span class="lang-tag">{lang.label}</span>
            <span
              class="badge"
              style={`color:${meta.color};background:${meta.bg};border-color:${meta.border}`}
            >
              {meta.label}
            </span>
          </span>
        </div>
      </button>
    </li>
  {/each}
  {#if patterns.length === 0}
    <li class="empty">没有匹配筛选条件的正则</li>
  {/if}
</ul>

<style>
  .list {
    list-style: none;
    margin: 0;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .item {
    width: 100%;
    text-align: left;
    border: 1px solid transparent;
    background: transparent;
    padding: 9px 11px;
    border-radius: 9px;
  }
  .item:hover {
    background: var(--panel-2);
    border-color: var(--border);
  }
  .item.active {
    background: var(--panel-2);
    border-color: var(--accent);
    box-shadow: inset 3px 0 0 var(--accent);
  }
  .row1 {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    flex: none;
  }
  .pat {
    font-size: 12.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .row2 {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 6px;
    gap: 8px;
  }
  .loc {
    font-size: 11px;
    color: var(--fg-dim);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .tags {
    display: flex;
    gap: 5px;
    flex: none;
  }
  .lang-tag {
    font-size: 10.5px;
    color: var(--fg-dim);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 1px 7px;
  }
  .empty {
    padding: 28px 12px;
    text-align: center;
    color: var(--fg-dim);
  }
</style>
