import type { ColumnMeta, QueryResult } from "./db.js";
import { classifyColumn, sanitiseValue, type PiiOptions, type PiiType, type ScanStats } from "./pii.js";

export interface SafeResult {
  columns: string[];
  rows: Record<string, unknown>[];
  rowCount: number;
  truncated: boolean;
  maskedColumns: Record<string, PiiType>;
  inlinePiiMasked: ScanStats;
}

export interface MaskHints {
  /** Extra classifier (e.g. policy-listed sensitive columns by source table). */
  classify?: (c: ColumnMeta) => PiiType | null;
  /** Force-mask by output position (from AST analysis). */
  forceIndexes?: Map<number, PiiType> | null;
  /** Force-mask by output column name (from AST analysis). */
  forceNames?: Map<string, PiiType>;
}

export function sanitiseResult(result: QueryResult, opts: PiiOptions, maxRows: number, hints: MaskHints = {}): SafeResult {
  const colTypes = result.columns.map(
    (c, i) =>
      hints.forceIndexes?.get(i) ??
      hints.forceNames?.get(c.name.toLowerCase()) ??
      hints.classify?.(c) ??
      classifyColumn([c.name, c.originalName], c.table, opts),
  );
  const maskedColumns: Record<string, PiiType> = {};
  result.columns.forEach((c, i) => {
    const t = colTypes[i];
    if (t) maskedColumns[c.name] = t;
  });

  // Ensure unique keys for duplicate column names (e.g. joins).
  const seen = new Map<string, number>();
  const keys = result.columns.map((c) => {
    const n = seen.get(c.name) ?? 0;
    seen.set(c.name, n + 1);
    return n === 0 ? c.name : `${c.name}_${n + 1}`;
  });

  const inline: ScanStats = {};
  const slice = result.rows.slice(0, maxRows);
  const rows = slice.map((row) => {
    const obj: Record<string, unknown> = {};
    keys.forEach((k, i) => {
      obj[k] = sanitiseValue(row[i], colTypes[i], opts, colTypes[i] ? undefined : inline);
    });
    return obj;
  });

  return {
    columns: keys,
    rows,
    rowCount: result.rows.length,
    truncated: result.rows.length > maxRows,
    maskedColumns,
    inlinePiiMasked: inline,
  };
}

export function countPii(r: SafeResult): number {
  const masked = Object.keys(r.maskedColumns).length * r.rows.length;
  const inline = Object.values(r.inlinePiiMasked).reduce((a, b) => a + b, 0);
  return masked + inline;
}
