/**
 * AST-level query analysis.
 *
 * Tracks every reference to a sensitive column through aliases, CTEs,
 * derived tables, subqueries and expressions, and checks how it is used:
 *
 *   select  – returned to the caller (allowed, but the output is force-masked)
 *   filter  – WHERE / HAVING / any comparison (=, LIKE, IN, CASE WHEN ...)
 *   join    – JOIN ... ON / USING
 *   group   – GROUP BY / PARTITION BY
 *   sort    – ORDER BY
 *
 * It also enforces the table allow/deny list on every table the query touches.
 */
import sqlParser from "node-sql-parser";
import type { Policy, ColumnTaint } from "./policy.js";
import type { PiiType } from "./pii.js";
import { SqlGuardError } from "./sqlGuard.js";

const { Parser } = sqlParser as unknown as { Parser: new () => { astify(sql: string, o: object): unknown } };
const parser = new Parser();

type Clause = "select" | "filter" | "join" | "group" | "sort";
type Dialect = "mysql" | "postgres";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Node = any;

type Source =
  | { kind: "base"; table: string; schema?: string }
  | { kind: "derived"; columns: Map<string, ColumnTaint[]>; stars: Source[]; unnamedTainted: boolean };

interface Scope {
  sources: Map<string, Source>;
  ctes: Map<string, Source>;
  selectAliases: Map<string, ColumnTaint[]>;
  parent?: Scope;
}

interface SelectItem {
  name: string | null;
  taints: ColumnTaint[];
  star: Source[] | null;
}

export interface Analysis {
  parsed: boolean;
  operation: string;
  tables: string[];
  /** Output positions to force-mask (only when the select list has no `*`). */
  maskIndexes: Map<number, PiiType> | null;
  /** Output column names to force-mask. */
  maskNames: Map<string, PiiType>;
}

const CLAUSE_LABEL: Record<Exclude<Clause, "select">, [keyof ColumnTaint["rules"], string]> = {
  filter: ["allow_filtering", "WHERE/HAVING filters or comparisons"],
  join: ["allow_joining", "JOIN conditions"],
  group: ["allow_grouping", "GROUP BY / PARTITION BY"],
  sort: ["allow_sorting", "ORDER BY"],
};

const COMPARISON_OPS = new Set([
  "=", "!=", "<>", "<", ">", "<=", ">=", "<=>", "LIKE", "NOT LIKE", "ILIKE", "NOT ILIKE", "IN", "NOT IN",
  "BETWEEN", "NOT BETWEEN", "IS", "IS NOT", "REGEXP", "NOT REGEXP", "RLIKE", "NOT RLIKE", "~", "~*", "!~",
  "!~*", "SIMILAR TO", "NOT SIMILAR TO", "@>", "<@", "?", "?|", "?&", "&&", "@@",
]);

const lc = (s: unknown) => String(s ?? "").toLowerCase();

/** Identifier that may be a string or {type, value} depending on dialect; null if absent. */
function ident(x: Node): string | null {
  if (x === null || x === undefined) return null;
  if (typeof x === "string") return x;
  if (x.value !== undefined) return String(x.value);
  if (x.expr?.value !== undefined) return String(x.expr.value);
  return null;
}

function colName(c: Node): string {
  if (typeof c === "string") return c;
  if (c?.expr?.value !== undefined) return String(c.expr.value);
  if (c?.value !== undefined) return String(c.value);
  return String(c);
}

class Analyzer {
  private violations: string[] = [];
  readonly tables = new Set<string>();

  constructor(private policy: Policy) {}

  fail(msg: string) {
    if (!this.violations.includes(msg)) this.violations.push(msg);
  }

  finish() {
    if (this.violations.length) {
      throw new SqlGuardError(
        this.violations.slice(0, 5).join(" ") + (this.violations.length > 5 ? ` (+${this.violations.length - 5} more)` : ""),
      );
    }
  }

  private check(t: ColumnTaint, clause: Clause) {
    if (t.blocked) {
      this.fail(`Column ${t.table}.${t.column} is blocked by policy and cannot be referenced.`);
      return;
    }
    if (clause === "select") return;
    const [rule, label] = CLAUSE_LABEL[clause];
    if (!t.rules[rule]) {
      this.fail(`Column ${t.table}.${t.column} is sensitive and cannot be used in ${label} (policy: ${rule}=false).`);
    }
  }

  private registerTable(table: string, schema?: string | null) {
    const name = schema ? `${lc(schema)}.${lc(table)}` : lc(table);
    this.tables.add(name);
    if (!this.policy.isTableAllowed(table, schema)) this.fail(`Access to table "${name}" is not allowed by policy.`);
  }

  /* ------------------------------ resolution ------------------------------ */

  private lookupSource(scope: Scope | undefined, alias: string): Source | undefined {
    for (let s = scope; s; s = s.parent) {
      const src = s.sources.get(alias);
      if (src) return src;
    }
    return undefined;
  }

  private resolveIn(src: Source, column: string, seen = new Set<Source>()): ColumnTaint[] {
    if (seen.has(src)) return [];
    seen.add(src);
    if (src.kind === "base") {
      const t = this.policy.taint(src.table, column);
      return t ? [t] : [];
    }
    const direct = src.columns.get(column);
    if (direct) return direct;
    return src.stars.flatMap((s) => this.resolveIn(s, column, seen));
  }

  /** Whole-row reference (e.g. to_jsonb(c), row_to_json(c.*)) on a protected source. */
  private sourceIsProtected(src: Source, seen = new Set<Source>()): boolean {
    if (seen.has(src)) return false;
    seen.add(src);
    if (src.kind === "base") return this.policy.protectsTable(src.table);
    if (src.unnamedTainted) return true;
    for (const t of src.columns.values()) if (t.length) return true;
    return src.stars.some((s) => this.sourceIsProtected(s, seen));
  }

  private resolve(scope: Scope, table: string | null, column: string, clause: Clause): ColumnTaint[] {
    const col = lc(column);
    if (table) {
      const src = this.lookupSource(scope, lc(table));
      if (src) return this.resolveIn(src, col);
      const t = this.policy.taint(table, col);
      return t ? [t] : [];
    }
    const out: ColumnTaint[] = [];
    // Whole-row reference via bare alias: SELECT to_jsonb(c) FROM customers c
    const rowSrc = this.lookupSource(scope, col);
    if (rowSrc && this.sourceIsProtected(rowSrc)) {
      this.fail(`Whole-row reference "${col}" is not allowed on a table with sensitive columns; select columns explicitly.`);
    }
    for (let s: Scope | undefined = scope; s; s = s.parent) {
      for (const src of s.sources.values()) out.push(...this.resolveIn(src, col));
      if (clause !== "select" && s === scope) {
        const alias = s.selectAliases.get(col);
        if (alias) out.push(...alias);
      }
    }
    if (out.length === 0 && scope.sources.size === 0) {
      const t = this.policy.taint(undefined, col);
      if (t) out.push(t);
    }
    return out;
  }

  /* ------------------------------ expressions ----------------------------- */

  /**
   * Walk an expression. Every sensitive column found is checked against
   * `clause`; columns that flow into the expression's value are pushed to `acc`.
   */
  walkExpr(node: Node, clause: Clause, scope: Scope, acc: ColumnTaint[]): void {
    if (node === null || node === undefined || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const n of node) this.walkExpr(n, clause, scope, acc);
      return;
    }

    // Subquery
    if (node.ast || node.type === "select") {
      const ast = node.ast ?? node;
      const res = this.analyzeSelect(ast, scope, clause);
      for (const item of res.items) acc.push(...item.taints);
      return;
    }

    if (node.type === "column_ref") {
      const name = colName(node.column);
      if (name === "*") {
        // t.* inside an expression (row_to_json(c.*)) – whole-row reference.
        const nt = ident(node.table);
        const srcs = nt ? [this.lookupSource(scope, lc(nt))].filter(Boolean) : [...scope.sources.values()];
        for (const s of srcs as Source[]) {
          if (this.sourceIsProtected(s)) this.fail("Whole-row references (t.*) inside expressions are not allowed on tables with sensitive columns.");
        }
        return;
      }
      const taints = this.resolve(scope, ident(node.table), name, clause);
      for (const t of taints) this.check(t, clause);
      acc.push(...taints);
      return;
    }

    // COUNT(x) reveals nothing about x's values.
    if (node.type === "aggr_func" && lc(node.name) === "count") {
      this.walkExpr(node.args, "select", scope, []);
      if (node.over) this.walkGeneric(node.over, clause, scope, acc);
      return;
    }

    // Comparisons anywhere (incl. SELECT list / CASE WHEN) act as filters: they are oracles.
    if (node.type === "binary_expr" && COMPARISON_OPS.has(String(node.operator).toUpperCase())) {
      const eff: Clause = clause === "join" ? "join" : "filter";
      const inner: ColumnTaint[] = [];
      this.walkExpr(node.left, eff, scope, inner);
      this.walkExpr(node.right, eff, scope, inner);
      return; // boolean result: no value flows out
    }

    this.walkGeneric(node, clause, scope, acc);
  }

  private walkGeneric(node: Node, clause: Clause, scope: Scope, acc: ColumnTaint[]) {
    for (const [k, v] of Object.entries(node)) {
      if (k === "loc" || k === "tableList" || k === "columnList" || v === null || typeof v !== "object") continue;
      let c: Clause = clause;
      if (k === "partitionby") c = "group";
      else if (k === "orderby") c = "sort";
      else if (k === "where" || k === "having" || k === "filter") c = "filter";
      else if (k === "on") c = "join";
      this.walkExpr(v, c, scope, c === clause ? acc : []);
    }
  }

  /* -------------------------------- SELECT -------------------------------- */

  analyzeSelect(ast: Node, parent: Scope | undefined, listClause: Clause): { items: SelectItem[] } {
    const scope: Scope = {
      sources: new Map(),
      ctes: new Map(parent?.ctes ?? []),
      selectAliases: new Map(),
      parent,
    };

    // WITH
    for (const cte of ast.with ?? []) {
      const name = lc(colName(cte.name));
      const stmt = cte.stmt?.ast ?? cte.stmt;
      const res = this.analyzeSelect(stmt, scope, "select");
      const src = this.derivedFrom(res.items);
      if (Array.isArray(cte.columns) && cte.columns.length && src.kind === "derived") {
        const renamed = new Map<string, ColumnTaint[]>();
        cte.columns.forEach((c: Node, i: number) => renamed.set(lc(colName(c)), res.items[i]?.taints ?? []));
        src.columns = renamed;
      }
      scope.ctes.set(name, src);
    }

    // FROM
    const joins: Node[] = [];
    for (const f of ast.from ?? []) {
      if (f.expr?.ast || f.expr?.type === "select") {
        const res = this.analyzeSelect(f.expr.ast ?? f.expr, f.lateral ? scope : parent, "select");
        scope.sources.set(lc(ident(f.as) ?? `__derived${scope.sources.size}`), this.derivedFrom(res.items));
      } else if (ident(f.table)) {
        const tname = lc(ident(f.table));
        const schema = ident(f.db) ?? ident(f.schema);
        const cte = !schema ? scope.ctes.get(tname) : undefined;
        if (cte) {
          scope.sources.set(lc(ident(f.as) ?? tname), cte);
        } else {
          this.registerTable(tname, schema);
          scope.sources.set(lc(ident(f.as) ?? tname), { kind: "base", table: tname, schema: schema ?? undefined });
        }
      } else if (f.expr) {
        // table function, VALUES etc.
        this.walkExpr(f.expr, "select", scope, []);
        if (ident(f.as)) scope.sources.set(lc(ident(f.as)), { kind: "derived", columns: new Map(), stars: [], unnamedTainted: false });
      }
      if (f.on || f.using) joins.push(f);
    }
    for (const f of joins) {
      if (f.on) this.walkExpr(f.on, "join", scope, []);
      for (const u of f.using ?? []) {
        for (const t of this.resolve(scope, null, colName(u), "join")) this.check(t, "join");
      }
    }

    // SELECT list
    const items: SelectItem[] = [];
    const cols = ast.columns === "*" ? [{ expr: { type: "column_ref", table: null, column: "*" } }] : ast.columns ?? [];
    for (const c of cols) {
      const e = c.expr ?? c;
      if (e?.type === "column_ref" && colName(e.column) === "*") {
        const et = ident(e.table);
        const srcs = et
          ? [this.lookupSource(scope, lc(et))].filter((s): s is Source => !!s)
          : [...scope.sources.values()];
        for (const s of srcs) this.checkStarBlocked(s);
        items.push({ name: null, taints: [], star: srcs });
        continue;
      }
      const acc: ColumnTaint[] = [];
      this.walkExpr(e, listClause, scope, acc);
      const name = ident(c.as) ? lc(ident(c.as)) : e?.type === "column_ref" ? lc(colName(e.column)) : null;
      if (name) scope.selectAliases.set(name, acc);
      items.push({ name, taints: acc, star: null });
    }

    // Positional references: ORDER BY 2 / GROUP BY 1
    const positional = (n: Node, clause: Clause) => {
      if (n?.type === "number") {
        const it = items[Number(n.value) - 1];
        for (const t of it?.taints ?? []) this.check(t, clause);
        return true;
      }
      return false;
    };

    if (ast.where) this.walkExpr(ast.where, "filter", scope, []);
    const groupCols = Array.isArray(ast.groupby) ? ast.groupby : ast.groupby?.columns ?? [];
    for (const g of groupCols) if (!positional(g, "group")) this.walkExpr(g, "group", scope, []);
    if (ast.having) this.walkExpr(ast.having, "filter", scope, []);
    for (const o of ast.orderby ?? []) if (!positional(o.expr, "sort")) this.walkExpr(o.expr, "sort", scope, []);
    if (ast.window) this.walkGeneric({ window: ast.window }, "select", scope, []);
    if (ast.distinct?.columns) this.walkExpr(ast.distinct.columns, "group", scope, []); // DISTINCT ON
    if (ast.limit?.value) this.walkExpr(ast.limit.value, "filter", scope, []);

    // UNION / INTERSECT / EXCEPT
    if (ast._next) {
      const next = this.analyzeSelect(ast._next, parent, listClause);
      next.items.forEach((it, i) => {
        if (items[i]) {
          items[i].taints.push(...it.taints);
          if (it.star) items[i].star = [...(items[i].star ?? []), ...it.star];
        }
      });
    }
    return { items };
  }

  private checkStarBlocked(src: Source, seen = new Set<Source>()) {
    if (seen.has(src)) return;
    seen.add(src);
    if (src.kind === "derived") {
      for (const ts of src.columns.values()) for (const t of ts) if (t.blocked) this.check(t, "select");
      for (const s of src.stars) this.checkStarBlocked(s, seen);
    }
    // Base tables: blocked columns are caught after execution from result metadata.
  }

  private derivedFrom(items: SelectItem[]): Source {
    const columns = new Map<string, ColumnTaint[]>();
    const stars: Source[] = [];
    let unnamedTainted = false;
    for (const it of items) {
      if (it.star) stars.push(...it.star);
      else if (it.name) columns.set(it.name, it.taints);
      else if (it.taints.length) unnamedTainted = true;
    }
    return { kind: "derived", columns, stars, unnamedTainted };
  }

  /** Names of tainted columns exposed by `*` over derived sources. */
  starTaints(src: Source, out: Map<string, PiiType>, seen = new Set<Source>()) {
    if (seen.has(src) || src.kind === "base") return;
    seen.add(src);
    if (src.unnamedTainted) {
      this.fail("Derived expressions over sensitive columns must have an alias (e.g. UPPER(name) AS name_upper).");
    }
    for (const [name, ts] of src.columns) if (ts.length) out.set(name, ts[0].type);
    for (const s of src.stars) this.starTaints(s, out, seen);
  }
}

function operationOf(ast: Node): string {
  return String(ast?.type ?? "unknown").toUpperCase();
}

export function analyzeQuery(sql: string, dialect: Dialect, policy: Policy): Analysis {
  const empty: Analysis = { parsed: false, operation: "UNKNOWN", tables: [], maskIndexes: null, maskNames: new Map() };
  const first = sql.trim().match(/^\(*\s*([A-Za-z]+)/)?.[1]?.toUpperCase() ?? "UNKNOWN";

  // DESCRIBE / SHOW: only need the table check.
  if (first === "DESCRIBE" || first === "DESC" || first === "SHOW") {
    const m = sql.match(/^\s*(?:describe|desc)\s+([`"\w.]+)/i) ?? sql.match(/\b(?:from|in)\s+([`"\w.]+)/i);
    const a = new Analyzer(policy);
    if (m) {
      const parts = m[1].replace(/[`"]/g, "").split(".");
      const table = parts.pop()!;
      const schema = parts.pop() ?? null;
      // SHOW TABLES FROM db names a database, not a table.
      if (!/^\s*show\s+(full\s+)?tables\b/i.test(sql)) a["registerTable"](table, schema);
    } else if (!/^\s*show\s+(full\s+)?(tables|databases|schemas)\b/i.test(sql) && policy.failClosed) {
      throw new SqlGuardError("This SHOW statement cannot be verified against the table policy.");
    }
    a.finish();
    return { ...empty, parsed: true, operation: first, tables: [...a.tables] };
  }

  let ast: Node;
  try {
    ast = parser.astify(sql, { database: dialect === "mysql" ? "MySQL" : "PostgresQL" });
  } catch {
    if (policy.failClosed) {
      throw new SqlGuardError(
        "Query could not be parsed for policy verification. Rewrite it using standard SELECT syntax (avoid vendor-specific constructs).",
      );
    }
    return { ...empty, operation: first };
  }
  if (Array.isArray(ast)) {
    if (ast.length !== 1) throw new SqlGuardError("Multiple statements are not allowed.");
    ast = ast[0];
  }

  if (ast.type === "explain") ast = ast.expr;
  if (ast?.type !== "select") {
    throw new SqlGuardError(`Only SELECT queries are allowed (got ${operationOf(ast)}).`);
  }

  const a = new Analyzer(policy);
  const { items } = a.analyzeSelect(ast, undefined, "select");

  const hasStar = items.some((i) => i.star);
  const maskNames = new Map<string, PiiType>();
  let maskIndexes: Map<number, PiiType> | null = null;
  if (!hasStar) {
    maskIndexes = new Map();
    items.forEach((it, i) => {
      if (it.taints.length) maskIndexes!.set(i, it.taints[0].type);
    });
  }
  for (const it of items) {
    if (it.star) for (const s of it.star) a.starTaints(s, maskNames);
    else if (it.taints.length) {
      if (it.name) maskNames.set(it.name, it.taints[0].type);
      else if (hasStar) a.fail("Expressions over sensitive columns must have an alias when combined with SELECT *.");
    }
  }
  a.finish();
  return { parsed: true, operation: first === "EXPLAIN" ? "EXPLAIN" : "SELECT", tables: [...a.tables], maskIndexes, maskNames };
}
