// 与 Go engine.Report 结构对齐的 TypeScript 类型。

export interface Point {
  n: number;
  length: number;
  steps: number;
  capped: boolean;
  matched: boolean;
}

export interface GrowthFit {
  kind: 'exponential' | 'polynomial' | 'linear' | 'unknown';
  exponent: number;
  base: number;
  r_squared: number;
  super_linear: boolean;
}

export interface MatchResult {
  matched: boolean;
  steps: number;
  max_depth: number;
  duration_ns: number;
  capped: boolean;
  backref_used: boolean;
}

export interface ExternalResult {
  engine: string;
  available: boolean;
  timed_out: boolean;
  duration_ms: number;
  matched: boolean;
  error?: string;
}

export interface Evidence {
  candidate_name: string;
  pump: string;
  suffix: string;
  points: Point[];
  fit: GrowthFit;
  empirical: 'exponential' | 'polynomial' | 'linear' | 'inconclusive';
  vm_result_at_cap: MatchResult;
  external?: ExternalResult[];
}

export interface Warning {
  Pos: number;
  Code: string;
  Message: string;
}

export interface Finding {
  id: string;
  pattern_id: string;
  severity: 'exponential' | 'polynomial' | 'safe' | 'unknown';
  confidence: string;
  node_id: number;
  quantifier: string;
  reason: string;
  pump_word: string;
  exponential: boolean;
  degree: number;
  pair_count: number;
  capped: boolean;
  rule: string;
  evidence: Evidence | null;
}

export interface Suggestion {
  original: string;
  fixed: string;
  strategy: string;
  why: string;
  equivalent: string;
  re2_safe: boolean;
  confidence: string;
}

export interface EquivCheck {
  equivalent: boolean;
  tested: number;
  countercases: string[];
  note: string;
}

export interface Occurrence {
  language: string;
  file: string;
  pattern: string;
  flags: string;
  line: number;
  col: number;
  kind: string;
  confidence: string;
  raw: string;
  from_string: boolean;
  quote: number;
  raw_string: boolean;
}

export interface PatternReport {
  id: string;
  occurrence: Occurrence;
  parse_error?: string;
  warnings?: Warning[];
  findings: Finding[] | null;
  suggestions: Suggestion[] | null;
  equiv_check?: EquivCheck | null;
}

export interface Summary {
  total_patterns: number;
  parse_failed: number;
  exponential: number;
  polynomial: number;
  unknown: number;
  empirically_confirmed: number;
}

export interface EngineAck {
  node_available: boolean;
  python_available: boolean;
}

export interface Report {
  generated_at: string;
  root: string;
  summary: Summary;
  patterns: PatternReport[];
  engine_ack: EngineAck;
}

export type Severity = Finding['severity'];
