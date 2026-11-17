import type { Severity, Report, PatternReport } from './types';
import { severityOf } from './stores';

export const severityMeta: Record<
  Severity,
  { label: string; color: string; bg: string; border: string }
> = {
  exponential: {
    label: '指数级',
    color: 'var(--sev-exp-fg)',
    bg: 'var(--sev-exp-bg)',
    border: 'var(--sev-exp-border)',
  },
  polynomial: {
    label: '多项式级',
    color: 'var(--sev-poly-fg)',
    bg: 'var(--sev-poly-bg)',
    border: 'var(--sev-poly-border)',
  },
  safe: {
    label: '安全',
    color: 'var(--sev-safe-fg)',
    bg: 'var(--sev-safe-bg)',
    border: 'var(--sev-safe-border)',
  },
  unknown: {
    label: '待确认',
    color: 'var(--sev-unk-fg)',
    bg: 'var(--sev-unk-bg)',
    border: 'var(--sev-unk-border)',
  },
};

export const langMeta: Record<string, { label: string; color: string }> = {
  javascript: { label: 'JS/TS', color: '#f7df1e' },
  typescript: { label: 'TS', color: '#3178c6' },
  python: { label: 'Python', color: '#3776ab' },
  go: { label: 'Go', color: '#00add8' },
  java: { label: 'Java', color: '#e76f00' },
  generic: { label: '通用', color: '#888' },
};

export function fmtSteps(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

export function fmtLocation(p: PatternReport): string {
  const o = p.occurrence;
  const short = o.file.split('/').slice(-2).join('/');
  return `${short}:${o.line}:${o.col}`;
}

// 导出当前报告的漏洞清单为 CSV。
export function exportCsv(r: Report): string {
  const rows: string[][] = [
    ['id', 'language', 'file', 'line', 'pattern', 'severity', 'rule', 'empirical', 'pump', 'fit'],
  ];
  for (const p of r.patterns) {
    const sev = severityOf(p);
    const f = p.findings?.[0];
    rows.push([
      p.id,
      p.occurrence.language,
      p.occurrence.file,
      String(p.occurrence.line),
      p.occurrence.pattern,
      sev,
      f?.rule ?? '',
      f?.evidence?.empirical ?? '',
      f?.pump_word ?? '',
      f?.evidence?.fit.kind ?? '',
    ]);
  }
  return rows.map((r) => r.map(csvCell).join(',')).join('\n');
}

function csvCell(s: string): string {
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function download(filename: string, text: string, mime = 'text/plain') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
