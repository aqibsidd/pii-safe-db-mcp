import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod";
import type { Config } from "./config.js";
import type { DbAdapter } from "./db.js";
import { classifyColumn, scrubText } from "./pii.js";
import { countPii, sanitiseResult } from "./sanitize.js";
import { assertNoBlockedColumns, assertReadOnly, isValidIdentifier, SqlGuardError } from "./sqlGuard.js";
import { analyzeQuery } from "./analyzer.js";
import { sanitiseErrorMessage } from "./errors.js";
import { AuditLogger, type Decision } from "./audit.js";

export const VERSION = "0.2.0";

type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

export function createServer(cfg: Config, getDb: () => Promise<DbAdapter>, audit: AuditLogger): McpServer {
  const server = new McpServer({ name: "pii-safe-db-mcp", version: VERSION });
  audit.actorResolver = () => server.server.getClientVersion()?.name;
  const policy = cfg.policy;

  const ok = (data: unknown): ToolResult => ({ content: [{ type: "text", text: JSON.stringify(data, null, 2) }] });

  /** Run a tool body with uniform error sanitisation and auditing. */
  async function guarded(
    tool: string,
    operation: string,
    sql: string | undefined,
    body: (meta: AuditMeta) => Promise<unknown>,
  ): Promise<ToolResult> {
    const started = Date.now();
    const meta: AuditMeta = { operation };
    try {
      const data = await body(meta);
      audit.log({ tool, decision: "ALLOWED", started, sql, ...metaFields(meta) });
      return ok(data);
    } catch (err) {
      const blocked = err instanceof SqlGuardError;
      const raw = err instanceof Error ? err.message : String(err);
      // Guard messages are ours (no data); DB errors may echo values.
      const msg = blocked ? scrubText(raw, cfg.pii) : sanitiseErrorMessage(raw, cfg.pii);
      const decision: Decision = blocked ? "BLOCKED" : "ERROR";
      audit.log({ tool, decision, started, sql, reason: msg, ...metaFields(meta) });
      return { content: [{ type: "text", text: `${blocked ? "Blocked" : "Error"}: ${msg}` }], isError: true };
    }
  }

  const checkTable = (table: string) => {
    if (!isValidIdentifier(table)) throw new SqlGuardError("Invalid table name.");
    const parts = table.split(".");
    const bare = parts.pop()!;
    if (!policy.isTableAllowed(bare, parts.pop() ?? null)) {
      throw new SqlGuardError(`Access to table "${table.toLowerCase()}" is not allowed by policy.`);
    }
    return bare;
  };

  server.registerTool(
    "list_tables",
    {
      title: "List tables",
      description: `List tables and views in the connected ${cfg.dbType} database that this server is allowed to access.`,
      inputSchema: { schema: z.string().optional().describe("Schema/database name. Defaults to the current one.") },
      annotations: { readOnlyHint: true },
    },
    ({ schema }) =>
      guarded("list_tables", "LIST_TABLES", undefined, async (meta) => {
        if (schema && !isValidIdentifier(schema)) throw new SqlGuardError("Invalid schema name.");
        const all = await (await getDb()).listTables(schema);
        const visible = all.filter((t) => policy.isTableAllowed(t.name, t.schema));
        meta.rows = visible.length;
        return visible;
      }),
  );

  server.registerTool(
    "describe_table",
    {
      title: "Describe table",
      description:
        "Show the columns of a table, their types, whether each column is PII (masked) or blocked, and which SQL clauses it may be used in.",
      inputSchema: { table: z.string().describe("Table name, optionally schema-qualified (schema.table).") },
      annotations: { readOnlyHint: true },
    },
    ({ table }) =>
      guarded("describe_table", "DESCRIBE", undefined, async (meta) => {
        const bare = checkTable(table);
        meta.tables = [table.toLowerCase()];
        const cols = await (await getDb()).describeTable(table);
        if (cols.length === 0) throw new Error(`Table not found: ${table}`);
        meta.rows = cols.length;
        return cols.map((c) => {
          const t = policy.taint(bare, c.name);
          const blocked = policy.isBlocked(bare, c.name) || (t?.blocked ?? false);
          const pii = t?.type ?? classifyColumn([c.name], bare, cfg.pii) ?? policy.classifyResultColumn(bare, c.name);
          return {
            ...c,
            default: c.default == null ? null : sanitiseErrorMessage(String(c.default), cfg.pii),
            pii: pii ?? null,
            policy: blocked ? "blocked" : pii ? "masked" : "visible",
            ...(t && !blocked
              ? {
                  usable_in: {
                    where: t.rules.allow_filtering,
                    join: t.rules.allow_joining,
                    group_by: t.rules.allow_grouping,
                    order_by: t.rules.allow_sorting,
                  },
                }
              : {}),
          };
        });
      }),
  );

  server.registerTool(
    "query",
    {
      title: "Run read-only SQL",
      description: [
        `Run a single read-only SQL statement (SELECT / WITH / SHOW / DESCRIBE / EXPLAIN) against ${cfg.dbType}.`,
        `Results are capped at ${cfg.maxRows} rows. PII is masked before results are returned:`,
        `columns recognised as PII (email, phone, name, address, Aadhaar, PAN, card numbers, passwords...) are replaced with`,
        cfg.pii.mode === "token"
          ? "stable tokens like <EMAIL_3f9a1c2b7d> (same input → same token, so you can still GROUP BY / COUNT DISTINCT / compare),"
          : cfg.pii.mode === "partial"
            ? "partially-masked values like j***@***.com or ******3210,"
            : "placeholders like [EMAIL],",
        "and PII patterns found inside other text columns are masked too.",
        "Some sensitive columns may not be usable in WHERE / JOIN / GROUP BY / ORDER BY — call describe_table to see the rules.",
        "Expressions over sensitive columns are masked too. Prefer aggregates (COUNT, GROUP BY) over pulling raw rows.",
        "Use ? (MySQL) or $1 (Postgres) placeholders with `params`.",
      ].join(" "),
      inputSchema: {
        sql: z.string().describe("A single read-only SQL statement."),
        params: z
          .array(z.union([z.string(), z.number(), z.boolean(), z.null()]))
          .optional()
          .describe("Bind parameters for placeholders."),
      },
      annotations: { readOnlyHint: true },
    },
    ({ sql, params }) =>
      guarded("query", (sql.trim().match(/^\(*\s*([A-Za-z]+)/)?.[1] ?? "QUERY").toUpperCase(), sql, async (meta) => {
        const safeSql = assertReadOnly(sql);
        assertNoBlockedColumns(safeSql, cfg.blockedColumns);
        const analysis = analyzeQuery(safeSql, cfg.dbType, policy);
        meta.operation = analysis.operation;
        meta.tables = analysis.tables;

        const res = await (await getDb()).query(safeSql, params ?? []);
        for (const c of res.columns) {
          if (policy.isBlocked(c.table, c.originalName ?? c.name) || policy.isBlocked(undefined, c.name)) {
            throw new SqlGuardError(`Column "${c.originalName ?? c.name}" is blocked by policy and cannot be queried.`);
          }
        }
        const safe = sanitiseResult(res, cfg.pii, cfg.maxRows, {
          forceIndexes: analysis.maskIndexes,
          forceNames: analysis.maskNames,
          classify: (c) => policy.classifyResultColumn(c.table, c.originalName ?? c.name),
        });
        meta.rows = safe.rows.length;
        meta.pii = countPii(safe);
        meta.maskedColumns = Object.keys(safe.maskedColumns);
        return safe;
      }),
  );

  server.registerTool(
    "pii_scan",
    {
      title: "Scan table for PII",
      description:
        "Sample rows from a table and report which columns contain PII (by column name and by detected values). Returns counts only, never values. Use it to discover PII hiding in free-text columns.",
      inputSchema: {
        table: z.string().describe("Table name, optionally schema-qualified."),
        sample_size: z.number().int().min(1).max(5000).optional().describe("Rows to sample (default 200)."),
      },
      annotations: { readOnlyHint: true },
    },
    ({ table, sample_size }) =>
      guarded("pii_scan", "PII_SCAN", undefined, async (meta) => {
        const bare = checkTable(table);
        meta.tables = [table.toLowerCase()];
        const q = cfg.dbType === "mysql" ? "`" : '"';
        const ident = table.split(".").map((p) => `${q}${p}${q}`).join(".");
        const n = sample_size ?? 200;
        const res = await (await getDb()).query(`SELECT * FROM ${ident} LIMIT ${n}`);
        let total = 0;
        const report = res.columns.map((c, i) => {
          const name = c.originalName ?? c.name;
          const byName =
            policy.taint(c.table ?? bare, name)?.type ??
            classifyColumn([c.name, c.originalName], c.table ?? bare, cfg.pii) ??
            policy.classifyResultColumn(c.table ?? bare, name);
          const stats: Record<string, number> = {};
          let nonNull = 0;
          for (const row of res.rows) {
            const v = row[i];
            if (v == null) continue;
            nonNull++;
            if (typeof v === "string" || typeof v === "number" || typeof v === "bigint") {
              const found: Record<string, number> = {};
              scrubText(String(v), cfg.pii, found);
              for (const k of Object.keys(found)) stats[k] = (stats[k] ?? 0) + 1;
            }
          }
          total += Object.values(stats).reduce((a, b) => a + b, 0);
          return {
            column: c.name,
            blocked: policy.isBlocked(c.table ?? bare, name),
            piiByName: byName,
            valuesWithPii: stats,
            sampledNonNull: nonNull,
            recommendation:
              !byName && Object.keys(stats).length > 0
                ? `Inline PII found; it is masked at query time. Add "${c.name}" to tables.${bare}.sensitive_columns in the policy file to mask the whole column.`
                : undefined,
          };
        });
        meta.rows = res.rows.length;
        meta.pii = total;
        return { table, sampledRows: res.rows.length, columns: report };
      }),
  );

  return server;
}

interface AuditMeta {
  operation: string;
  tables?: string[];
  rows?: number;
  pii?: number;
  maskedColumns?: string[];
}

function metaFields(m: AuditMeta) {
  return { operation: m.operation, tables: m.tables, rows: m.rows, pii: m.pii, maskedColumns: m.maskedColumns };
}
