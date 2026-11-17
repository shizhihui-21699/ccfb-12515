import { writable, derived } from 'svelte/store';
import type { Report, PatternReport, Severity } from './types';

export const report = writable<Report | null>(null);
export const loading = writable(false);
export const loadError = writable('');

// 筛选：严重程度集合 + 语言 + 文本搜索。
export const severityFilter = writable<Set<Severity>>(
  new Set(['exponential', 'polynomial', 'unknown', 'safe'])
);
export const languageFilter = writable<string>('all');
export const search = writable('');
export const selectedId = writable<string | null>(null);

export async function loadReportFromUrl(url: string) {
  loading.set(true);
  loadError.set('');
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as Report;
    report.set(data);
    if (data.patterns.length) selectedId.set(data.patterns[0].id);
  } catch (e) {
    loadError.set(e instanceof Error ? e.message : String(e));
  } finally {
    loading.set(false);
  }
}

export async function loadReportFromFile(file: File) {
  loading.set(true);
  loadError.set('');
  try {
    const text = await file.text();
    const data = JSON.parse(text) as Report;
    report.set(data);
    if (data.patterns.length) selectedId.set(data.patterns[0].id);
  } catch (e) {
    loadError.set(`报告解析失败：${e instanceof Error ? e.message : String(e)}`);
  } finally {
    loading.set(false);
  }
}

export function severityOf(p: PatternReport): Severity {
  if (p.parse_error) return 'unknown';
  if (!p.findings || p.findings.length === 0) return 'safe';
  return p.findings[0].severity;
}

export const filteredPatterns = derived(
  [report, severityFilter, languageFilter, search],
  ([$report, $sev, $lang, $search]) => {
    if (!$report) return [];
    const q = $search.trim().toLowerCase();
    return $report.patterns.filter((p) => {
      const sev = severityOf(p);
      if (!$sev.has(sev)) return false;
      if ($lang !== 'all' && p.occurrence.language !== $lang) return false;
      if (q) {
        const hay = `${p.occurrence.pattern} ${p.occurrence.file} ${p.id}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }
);

export const languages = derived(report, ($report) => {
  if (!$report) return [];
  const set = new Set<string>();
  for (const p of $report.patterns) set.add(p.occurrence.language);
  return [...set].sort();
});
