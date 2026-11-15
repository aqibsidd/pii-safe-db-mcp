import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod";
import type { Config } from "./config.js";
import type { DbAdapter } from "./db.js";
import { classifyColumn, scrubText, type PiiOptions } from "./pii.js";
import { countPii, plainResult, sanitiseResult } from "./sanitize.js";
import { assertNoBlockedColumns, assertReadOnly, isValidIdentifier, SqlGuardError } from "./sqlGuard.js";
import { analyzeQuery } from "./analyzer.js";
import { sanitiseErrorMessage } from "./errors.js";
import { AuditLogger, type Decision } from "./audit.js";
import type { Policy } from "./policy.js";
import type { EffectiveMode } from "./state.js";

export const VERSION = "0.3.0";

type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

interface AuditMeta {
  operation: string;
  tables?: string[];
  rows?: number;
  pii?: number;
  maskedColumns?: string[];
}

/** Everything a tool call needs, snapshotted once per call. */
interface CallCtx {
  meta: AuditMeta;
  policy: Policy;
  pii: PiiOptions;
  mode: EffectiveMode;
}

const leadingKeyword = (sql: string) => (sql.trim().match(/^\(*\s*([A-Za-z]+)/)?.[1] ?? "QUERY").toUpperCase();

export function createServer(cfg: Config, getDb: () => Promise<DbAdapter>, audit: AuditLogger): McpServer {
  const server = new McpServer({ name: "pii-safe-db-mcp", version: VERSION });
  audit.actorResolver = () => server.server.getClientVersion()?.name;

  /* ----------------------------- protection mode ----------------------------- */

  let lastProtected: boolean | undefined;
  let lastNote: string | undefined;

  /** Current mode; audits every transition (and every refused "off" request). */
  function currentMode(): EffectiveMode {
    const mode = cfg.protection.current();
    const changed = lastProtected !== undefined && lastProtected !== mode.protected;
    const firstOff = lastProtected === undefined && !mode.protected;
    if (changed || firstOff) {
      const op = mode.protected ? "PROTECTION_ON" : "PROTECTION_OFF";
      audit.log({
        tool: "protection",
        operation: op,
        decision: "ALLOWED",
        started: Date.now(),
        protection: mode.protected ? "on" : "off",
        reason: mode.protected ? undefined : `source=${mode.source}${mode.until ? ` until=${mode.until}` : ""}`,
      });
      process.stderr.write(
        `pii-safe-db-mcp: PII protection is now ${mode.protected ? "ON" : `OFF${mode.until ? ` until ${mode.until}` : ""}`}\n`,
      );
    }
    if (mode.note && mode.note !== lastNote) {
      audit.log({
        tool: "protection",
        operation: "PROTECTION_OFF_REQUEST",
        decision: "BLOCKED",
        started: Date.now(),
        protection: "on",
        reason: mode.note,
      });
    }
    lastProtected = mode.protected;
    lastNote = mode.note;
    return mode;
  }

  const banner = (m: EffectiveMode) =>
    `PII protection is OFF${m.until ? ` until ${m.until}` : ""}: values below are RAW and UNMASKED. Turn it back on with /pii-on.`;

  /* ------------------------------- tool wrapper ------------------------------ */

  const ok = (data: unknown): ToolResult => ({ content: [{ type: "text", text: JSON.stringify(data, null, 2) }] });

  /** Run a tool body with a per-call policy snapshot, uniform error sanitisation and auditing. */
  async function guarded(
    tool: string,
    operation: string,
    sql: string | undefined,
    body: (ctx: CallCtx) => Promise<unknown>,
  ): Promise<ToolResult> {
    const started = Date.now();
    const meta: AuditMeta = { operation };
    let pii: PiiOptions = cfg.pii;
    let mode: EffectiveMode = { protected: true, source: "default" };
    try {
      const snap = cfg.store.current();
      pii = snap.pii;
      mode = currentMode();
      const data = await body({ meta, policy: snap.policy, pii, mode });
      audit.log({ tool, decision: "ALLOWED", started, sql, protection: mode.protected ? "on" : "off", ...metaFields(meta) });
      if (!mode.protected) {
        return ok(Array.isArray(data) ? { _protection: banner(mode), items: data } : { _protection: banner(mode), ...(data as object) });
      }
      return ok(data);
    } catch (err) {
      const blocked = err instanceof SqlGuardError;
      const raw = err instanceof Error ? err.message : String(err);
      // Guard messages are ours (no data); DB errors may echo values.
      const safeMsg = blocked ? scrubText(raw, pii) : sanitiseErrorMessage(raw, pii);
      const decision: Decision = blocked ? "BLOCKED" : "ERROR";
      // The audit log NEVER gets raw values, whatever the mode.
      audit.log({ tool, decision, started, sql, protection: mode.protected ? "on" : "off", reason: safeMsg, ...metaFields(meta) });
      const shown = mode.protected ? safeMsg : raw;
      return { content: [{ type: "text", text: `${blocked ? "Blocked" : "Error"}: ${shown}` }], isError: true };
    }
  }

  const checkTable = (policy: Policy, mode: EffectiveMode, table: string) => {
    if (!isValidIdentifier(table)) throw new SqlGuardError("Invalid table name.");
    const parts = table.split(".");
    const bare = parts.pop()!;
    if (mode.protected && !policy.isTableAllowed(bare, parts.pop() ?? null)) {
      throw new SqlGuardError(`Access to table "${table.toLowerCase()}" is not allowed by policy.`);
    }
    return bare;
  };

  /* ---------------------------------- tools ---------------------------------- */

  server.registerTool(
    "protection_status",
    {
      title: "PII protection status",
      description:
        "Report whether PII protection (masking + query policy) is currently ON or OFF, where the policy file lives, and whether it loaded cleanly. Read-only: protection cannot be changed through MCP.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    () =>
      guarded("protection_status", "STATUS", undefined, async ({ mode, policy }) => ({
        protection: mode.protected ? "on" : "off",
        source: mode.source,
        until: mode.until ?? null,
        note: mode.note ?? null,
        unprotected_mode_allowed: cfg.protection.allowUnprotected,
        policy_file: cfg.store.path ?? "(inline PII_POLICY)",
        policy_error: cfg.store.lastError ?? null,
        allowed_tables: [...policy.allowedTables],
        fail_closed: policy.failClosed,
        how_to_change:
          "A human runs /pii-on, /pii-off, /pii-add, /pii-block in Claude Code (install with: npx pii-safe-db-mcp install-commands). Policy edits apply on the next call; no reconnect needed.",
      })),
  );

  server.registerTool(
    "list_tables",
    {
      title: "List tables",
      description: `List tables and views in the connected ${cfg.dbType} database that this server is allowed to access.`,
      inputSchema: { schema: z.string().optional().describe("Schema/database name. Defaults to the current one.") },
      annotations: { readOnlyHint: true },
    },
    ({ schema }) =>
      guarded("list_tables", "LIST_TABLES", undefined, async ({ meta, policy, mode }) => {
        if (schema && !isValidIdentifier(schema)) throw new SqlGuardError("Invalid schema name.");
        const all = await (await getDb()).listTables(schema);
        const visible = mode.protected ? all.filter((t) => policy.isTableAllowed(t.name, t.schema)) : all;
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
      guarded("describe_table", "DESCRIBE", undefined, async ({ meta, policy, pii, mode }) => {
        const bare = checkTable(policy, mode, table);
        meta.tables = [table.toLowerCase()];
        const cols = await (await getDb()).describeTable(table);
        if (cols.length === 0) throw new Error(`Table not found: ${table}`);
        meta.rows = cols.length;
        return cols.map((c) => {
          const t = policy.taint(bare, c.name);
          const blocked = policy.isBlocked(bare, c.name) || (t?.blocked ?? false);
          const type = t?.type ?? classifyColumn([c.name], bare, pii) ?? policy.classifyResultColumn(bare, c.name);
          if (!mode.protected) return { ...c, pii: type ?? null, policy: "visible (protection off)" };
          return {
            ...c,
            default: c.default == null ? null : sanitiseErrorMessage(String(c.default), pii),
            pii: type ?? null,
            policy: blocked ? "blocked" : type ? "masked" : "visible",
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
        `Results are capped at ${cfg.maxRows} rows. While PII protection is ON (the default), PII is masked before results are returned:`,
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
      guarded("query", leadingKeyword(sql), sql, async ({ meta, policy, pii, mode }) => {
        // Read-only is enforced in BOTH modes.
        const safeSql = assertReadOnly(sql);

        if (!mode.protected) {
          const res = await (await getDb()).query(safeSql, params ?? []);
          const plain = plainResult(res, cfg.maxRows);
          meta.rows = plain.rows.length;
          return plain;
        }

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
        const safe = sanitiseResult(res, pii, cfg.maxRows, {
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
      guarded("pii_scan", "PII_SCAN", undefined, async ({ meta, policy, pii, mode }) => {
        const bare = checkTable(policy, mode, table);
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
            classifyColumn([c.name, c.originalName], c.table ?? bare, pii) ??
            policy.classifyResultColumn(c.table ?? bare, name);
          const stats: Record<string, number> = {};
          let nonNull = 0;
          for (const row of res.rows) {
            const v = row[i];
            if (v == null) continue;
            nonNull++;
            if (typeof v === "string" || typeof v === "number" || typeof v === "bigint") {
              const found: Record<string, number> = {};
              scrubText(String(v), pii, found);
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
                ? `Inline PII found; it is masked at query time. To mask the whole column, run: /pii-add ${bare} ${c.name}`
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

function metaFields(m: AuditMeta) {
  return { operation: m.operation, tables: m.tables, rows: m.rows, pii: m.pii, maskedColumns: m.maskedColumns };
}
