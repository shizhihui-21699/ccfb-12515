<script lang="ts">
  import type { Evidence } from '../lib/types';
  import { fmtSteps } from '../lib/format';

  let { evidence }: { evidence: Evidence } = $props();

  const W = 560;
  const H = 240;
  const PAD_L = 56;
  const PAD_R = 16;
  const PAD_T = 18;
  const PAD_B = 34;

  const points = $derived(evidence.points ?? []);
  const maxN = $derived(Math.max(1, ...points.map((p) => p.n)));
  const maxSteps = $derived(Math.max(10, ...points.map((p) => p.steps)));

  // y 轴取 log10，让指数/多项式差异一眼可辨。
  const yMax = $derived(Math.ceil(Math.log10(maxSteps) * 4) / 4);
  const x = (n: number) => PAD_L + (n / maxN) * (W - PAD_L - PAD_R);
  const y = (steps: number) =>
    H - PAD_B - (Math.log10(Math.max(1, steps)) / yMax) * (H - PAD_T - PAD_B);

  const linePath = $derived(
    points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${x(p.n).toFixed(1)} ${y(p.steps).toFixed(1)}`).join(' ')
  );

  const capPoint = $derived(points.find((p) => p.capped));
  const gridYs = $derived(
    Array.from({ length: Math.floor(yMax) + 1 }, (_, i) => ({
      v: Math.pow(10, i),
      yy: y(Math.pow(10, i)),
    }))
  );
</script>

<div class="chart-wrap">
  <svg viewBox="0 0 {W} {H}" role="img" aria-label="回溯步数增长曲线">
    <!-- 网格与 y 轴刻度 -->
    {#each gridYs as g}
      <line x1={PAD_L} x2={W - PAD_R} y1={g.yy} y2={g.yy} stroke="var(--chart-grid)" stroke-width="1" />
      <text x={PAD_L - 6} y={g.yy + 4} text-anchor="end" class="axis">{fmtSteps(g.v)}</text>
    {/each}
    <!-- x 轴 -->
    <line x1={PAD_L} x2={W - PAD_R} y1={H - PAD_B} y2={H - PAD_B} stroke="var(--border)" />
    {#each Array.from({ length: Math.min(maxN, 10) }, (_, i) => i + 1) as n}
      <text x={x((n * maxN) / 10)} y={H - PAD_B + 16} text-anchor="middle" class="axis">
        {Math.round((n * maxN) / 10)}
      </text>
    {/each}
    <text x={W / 2} y={H - 4} text-anchor="middle" class="axis-title">攻击串重复次数 n</text>
    <text x={14} y={H / 2} text-anchor="middle" class="axis-title" transform="rotate(-90 14 {H / 2})"
      >回溯步数（对数）</text
    >

    <!-- 数据线 -->
    <path d={linePath} fill="none" stroke="var(--chart-line)" stroke-width="2.2" stroke-linejoin="round" />
    {#each points as p}
      <circle
        cx={x(p.n)}
        cy={y(p.steps)}
        r={p.capped ? 4.5 : 2.6}
        fill={p.capped ? 'var(--chart-cap)' : 'var(--chart-line)'}
      >
        <title>n={p.n}，步数 {fmtSteps(p.steps)}{p.capped ? '（撞步数上限）' : ''}</title>
      </circle>
    {/each}

    {#if capPoint}
      <text x={x(capPoint.n)} y={y(capPoint.steps) - 10} text-anchor="middle" class="cap-label"
        >步数上限</text
      >
    {/if}
  </svg>

  <div class="fit-bar">
    <span class="fit-kind" data-kind={evidence.fit.kind}>拟合：{evidence.fit.kind}</span>
    {#if evidence.fit.kind === 'exponential'}
      <span>底数 ≈ {evidence.fit.base.toFixed(2)}^n</span>
    {:else if evidence.fit.kind === 'polynomial'}
      <span>指数 ≈ n^{evidence.fit.exponent.toFixed(1)}</span>
    {/if}
    <span>R² = {evidence.fit.r_squared.toFixed(3)}</span>
  </div>
</div>

<style>
  .chart-wrap {
    width: 100%;
  }
  svg {
    width: 100%;
    height: auto;
    display: block;
  }
  .axis {
    font-size: 10px;
    fill: var(--fg-dim);
  }
  .axis-title {
    font-size: 11px;
    fill: var(--fg-dim);
  }
  .cap-label {
    font-size: 11px;
    font-weight: 700;
    fill: var(--chart-cap);
  }
  .fit-bar {
    display: flex;
    gap: 14px;
    flex-wrap: wrap;
    margin-top: 6px;
    font-size: 12px;
    color: var(--fg-dim);
  }
  .fit-kind {
    font-weight: 700;
    color: var(--fg);
  }
  .fit-kind[data-kind='exponential'] {
    color: var(--sev-exp-fg);
  }
  .fit-kind[data-kind='polynomial'] {
    color: var(--sev-poly-fg);
  }
</style>
