import { readFileSync } from "node:fs";
import { classifyColumn, type PiiOptions, type PiiType, type ValueRule } from "./pii.js";

/** What a sensitive column may be used for, besides being returned (masked). */
export interface ColumnRules {
  /** May the column appear in the SELECT list at all (masked)? false = blocked everywhere. */
  allow_select: boolean;
  /** WHERE / HAVING / comparisons (=, LIKE, IN, CASE WHEN ...) anywhere. */
  allow_filtering: boolean;
  /** JOIN ... ON / USING conditions. */
  allow_joining: boolean;
  /** GROUP BY / PARTITION BY. */
  allow_grouping: boolean;
  /** ORDER BY (ordering leaks values via binary search). */
  allow_sorting: boolean;
}

export interface TablePolicy extends Partial<ColumnRules> {
  sensitive_columns?: string[];
  blocked_columns?: string[];
}

export interface CustomPattern {
  name: string;
  pattern: string;
  flags?: string;
  /** Column names that should be classified as this type. */
  column_names?: string[];
}

export interface PolicyFile {
  allowed_tables?: string[];
  denied_tables?: string[];
  /** Rules applied to sensitive columns of tables without their own entry (and auto-detected PII). */
  default?: Partial<ColumnRules>;
  tables?: Record<string, TablePolicy>;
  custom_patterns?: CustomPattern[];
  /** Reject queries that cannot be parsed/verified. Defaults to true when any restriction is configured. */
  fail_closed?: boolean;
  /** Apply clause rules to columns auto-detected as PII by name (email, phone...). Default true. */
  treat_detected_pii_as_sensitive?: boolean;
}

export interface ColumnTaint {
  table: string;
  column: string;
  type: PiiType;
  rules: ColumnRules;
  blocked: boolean;
}

const PERMISSIVE: ColumnRules = {
  allow_select: true,
  allow_filtering: true,
  allow_joining: true,
  allow_grouping: true,
  allow_sorting: true,
};

/** Secrets (passwords, tokens, OTPs...) can never be used as an oracle. */
const SECRET_DEFAULT: ColumnRules = {
  allow_select: true,
  allow_filtering: false,
  allow_joining: false,
  allow_grouping: false,
  allow_sorting: false,
};

const lc = (s: string) => s.trim().toLowerCase();

export class Policy {
  readonly allowedTables: Set<string>;
  readonly deniedTables: Set<string>;
  readonly failClosed: boolean;
  readonly treatDetected: boolean;
  private readonly defaults: Partial<ColumnRules>;
  private readonly tables = new Map<string, { rules: Partial<ColumnRules>; sensitive: Set<string>; blocked: Set<string> }>();

  constructor(
    file: PolicyFile,
    private readonly pii: PiiOptions,
    private readonly globalBlocked: Set<string>,
    extraAllowed: Set<string> = new Set(),
    extraDenied: Set<string> = new Set(),
  ) {
    this.allowedTables = new Set([...(file.allowed_tables ?? []).map(lc), ...extraAllowed]);
    this.deniedTables = new Set([...(file.denied_tables ?? []).map(lc), ...extraDenied]);
    this.defaults = file.default ?? {};
    this.treatDetected = file.treat_detected_pii_as_sensitive ?? true;
    for (const [name, tp] of Object.entries(file.tables ?? {})) {
      const { sensitive_columns, blocked_columns, ...rules } = tp;
      this.tables.set(lc(name), {
        rules,
        sensitive: new Set((sensitive_columns ?? []).map(lc)),
        blocked: new Set((blocked_columns ?? []).map(lc)),
      });
    }
    const restrictive =
      this.allowedTables.size > 0 ||
      this.deniedTables.size > 0 ||
      this.tables.size > 0 ||
      Object.values(this.defaults).some((v) => v === false);
    this.failClosed = file.fail_closed ?? restrictive;
  }

  /** True when the policy restricts anything beyond the built-in defaults. */
  get hasTablePolicies(): boolean {
    return this.tables.size > 0;
  }

  private tableEntry(table: string) {
    const t = lc(table);
    return this.tables.get(t) ?? this.tables.get(t.split(".").pop()!);
  }

  /** Does this table have sensitive/blocked columns that name-based detection might not see? */
  protectsTable(table: string): boolean {
    const e = this.tableEntry(table);
    return this.globalBlocked.size > 0 || (!!e && (e.sensitive.size > 0 || e.blocked.size > 0));
  }

  isTableAllowed(table: string, schema?: string | null): boolean {
    const bare = lc(table).split(".").pop()!;
    const full = schema ? `${lc(schema)}.${bare}` : lc(table);
    const names = new Set([bare, full]);
    if (schema) names.add(`${lc(schema)}.*`);
    // Unqualified names resolve to the default schema (Postgres: public).
    else names.add(`public.${bare}`).add("public.*");
    for (const n of names) if (this.deniedTables.has(n)) return false;
    if (this.allowedTables.size === 0) return true;
    for (const n of names) if (this.allowedTables.has(n)) return true;
    return false;
  }

  /** Classify a (table, column) pair. Returns null if the column is not sensitive. */
  taint(table: string | undefined, column: string): ColumnTaint | null {
    const col = lc(column);
    const entry = table ? this.tableEntry(table) : undefined;
    const bareTable = table ? lc(table).split(".").pop()! : "";

    const blocked = this.globalBlocked.has(col) || (entry?.blocked.has(col) ?? false);
    const listed = entry?.sensitive.has(col) ?? false;
    const detected = classifyColumn([column], bareTable || undefined, this.pii);

    if (!blocked && !listed && !(detected && this.treatDetected)) return null;

    const type: PiiType = detected ?? "PII";
    const base = type === "SECRET" || type === "CVV" ? SECRET_DEFAULT : PERMISSIVE;
    const rules: ColumnRules = { ...base, ...this.defaults, ...(entry?.rules ?? {}) };
    return {
      table: bareTable || "?",
      column: col,
      type,
      rules,
      blocked: blocked || !rules.allow_select,
    };
  }

  /** Extra classifier used when masking result columns (policy-listed sensitive columns). */
  classifyResultColumn(table: string | undefined, column: string | undefined): PiiType | null {
    if (!table || !column) return null;
    const entry = this.tableEntry(table);
    if (!entry?.sensitive.has(lc(column))) return null;
    return classifyColumn([column], undefined, { ...this.pii, allowColumns: new Set() }) ?? "PII";
  }

  isBlocked(table: string | undefined, column: string): boolean {
    const col = lc(column);
    if (this.globalBlocked.has(col)) return true;
    if (!table) return false;
    const entry = this.tableEntry(table);
    if (!entry) return false;
    if (entry.blocked.has(col)) return true;
    return entry.sensitive.has(col) && entry.rules.allow_select === false;
  }
}

export function compileCustomPatterns(patterns: CustomPattern[] = []): {
  valueRules: ValueRule[];
  columnTypes: Map<string, PiiType>;
} {
  const valueRules: ValueRule[] = [];
  const columnTypes = new Map<string, PiiType>();
  for (const p of patterns) {
    const type = p.name.toUpperCase().replace(/[^A-Z0-9_]/g, "_");
    const flags = (p.flags ?? "").replace(/g/g, "") + "g";
    valueRules.push({ type, re: new RegExp(p.pattern, flags) });
    for (const c of p.column_names ?? []) columnTypes.set(lc(c), type);
  }
  return { valueRules, columnTypes };
}

export function readPolicyFile(path: string | undefined, inline: string | undefined): PolicyFile {
  if (inline) return JSON.parse(inline) as PolicyFile;
  if (!path) return {};
  return JSON.parse(readFileSync(path, "utf8")) as PolicyFile;
}
