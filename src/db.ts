import type { Config } from "./config.js";

export interface ColumnMeta {
  /** Name as returned in the result set (may be an alias). */
  name: string;
  /** Original column name in the source table, when the driver can tell us. */
  originalName?: string;
  /** Source table, when known. */
  table?: string;
}

export interface QueryResult {
  columns: ColumnMeta[];
  rows: unknown[][];
}

export interface TableInfo {
  schema: string;
  name: string;
  type: string;
}

export interface ColumnInfo {
  name: string;
  dataType: string;
  nullable: boolean;
  key?: string;
  default?: unknown;
}

export interface DbAdapter {
  readonly kind: "mysql" | "postgres";
  query(sql: string, params?: unknown[]): Promise<QueryResult>;
  listTables(schema?: string): Promise<TableInfo[]>;
  describeTable(table: string): Promise<ColumnInfo[]>;
  close(): Promise<void>;
}

/* ------------------------------------------------------------------ */
/* MySQL                                                               */
/* ------------------------------------------------------------------ */

class MysqlAdapter implements DbAdapter {
  readonly kind = "mysql" as const;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private pool: any;

  constructor(private cfg: Config) {}

  async init(): Promise<void> {
    const mysql = await import("mysql2/promise");
    const common = {
      connectionLimit: 4,
      multipleStatements: false,
      dateStrings: false,
      supportBigNumbers: true,
      bigNumberStrings: true,
      ssl: this.cfg.ssl ? { rejectUnauthorized: true } : undefined,
    };
    this.pool = this.cfg.connectionString
      ? mysql.createPool({ uri: this.cfg.connectionString, ...common })
      : mysql.createPool({
          host: this.cfg.host,
          port: this.cfg.port,
          user: this.cfg.user,
          password: this.cfg.password,
          database: this.cfg.database,
          ...common,
        });
  }

  async query(sql: string, params: unknown[] = []): Promise<QueryResult> {
    const conn = await this.pool.getConnection();
    try {
      await conn.query("START TRANSACTION READ ONLY");
      const [rows, fields] = await conn.query({ sql, values: params, timeout: this.cfg.timeoutMs, rowsAsArray: true });
      const columns: ColumnMeta[] = (fields ?? []).map((f: { name: string; orgName?: string; orgTable?: string; table?: string }) => ({
        name: f.name,
        originalName: f.orgName || undefined,
        table: f.orgTable || f.table || undefined,
      }));
      return { columns, rows: Array.isArray(rows) ? (rows as unknown[][]) : [] };
    } finally {
      await conn.query("ROLLBACK").catch(() => undefined);
      conn.release();
    }
  }

  async listTables(schema?: string): Promise<TableInfo[]> {
    const r = await this.query(
      `SELECT table_schema, table_name, table_type FROM information_schema.tables
       WHERE table_schema = COALESCE(?, DATABASE()) ORDER BY table_name`,
      [schema ?? null],
    );
    return r.rows.map(([s, n, t]) => ({ schema: String(s), name: String(n), type: String(t) }));
  }

  async describeTable(table: string): Promise<ColumnInfo[]> {
    const [schema, name] = table.includes(".") ? table.split(".") : [null, table];
    const r = await this.query(
      `SELECT column_name, column_type, is_nullable, column_key, column_default
       FROM information_schema.columns
       WHERE table_schema = COALESCE(?, DATABASE()) AND table_name = ?
       ORDER BY ordinal_position`,
      [schema, name],
    );
    return r.rows.map(([n, t, nul, k, d]) => ({
      name: String(n),
      dataType: String(t),
      nullable: nul === "YES",
      key: k ? String(k) : undefined,
      default: d,
    }));
  }

  async close(): Promise<void> {
    await this.pool?.end();
  }
}

/* ------------------------------------------------------------------ */
/* Postgres                                                            */
/* ------------------------------------------------------------------ */

class PostgresAdapter implements DbAdapter {
  readonly kind = "postgres" as const;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private pool: any;
  private attCache = new Map<string, { table: string; column: string }>();

  constructor(private cfg: Config) {}

  async init(): Promise<void> {
    const pg = (await import("pg")).default;
    // Return int8 / numeric as strings to avoid precision loss.
    pg.types.setTypeParser(20, (v: string) => v);
    this.pool = new pg.Pool({
      connectionString: this.cfg.connectionString,
      host: this.cfg.connectionString ? undefined : this.cfg.host,
      port: this.cfg.connectionString ? undefined : this.cfg.port,
      user: this.cfg.connectionString ? undefined : this.cfg.user,
      password: this.cfg.connectionString ? undefined : this.cfg.password,
      database: this.cfg.connectionString ? undefined : this.cfg.database,
      ssl: this.cfg.ssl ? { rejectUnauthorized: true } : undefined,
      max: 4,
    });
  }

  private async run(sql: string, params: unknown[] = []) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN READ ONLY");
      await client.query(`SET LOCAL statement_timeout = ${Math.floor(this.cfg.timeoutMs)}`);
      return await client.query({ text: sql, values: params, rowMode: "array" });
    } finally {
      await client.query("ROLLBACK").catch(() => undefined);
      client.release();
    }
  }

  /** Resolve (tableID, columnID) pairs from the wire protocol to real column names. */
  private async resolveOrigins(fields: Array<{ tableID: number; columnID: number }>): Promise<void> {
    const missing = fields.filter((f) => f.tableID && f.columnID && !this.attCache.has(`${f.tableID}:${f.columnID}`));
    if (missing.length === 0) return;
    const rel = missing.map((f) => f.tableID);
    const att = missing.map((f) => f.columnID);
    const r = await this.run(
      `SELECT a.attrelid::int, a.attnum::int, c.relname, a.attname
       FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
       JOIN unnest($1::oid[], $2::int[]) AS k(relid, num) ON k.relid = a.attrelid AND k.num = a.attnum`,
      [rel, att],
    );
    for (const [relid, num, table, column] of r.rows as Array<[number, number, string, string]>) {
      this.attCache.set(`${relid}:${num}`, { table, column });
    }
  }

  async query(sql: string, params: unknown[] = []): Promise<QueryResult> {
    const r = await this.run(sql, params);
    const fields = (r.fields ?? []) as Array<{ name: string; tableID: number; columnID: number }>;
    try {
      await this.resolveOrigins(fields);
    } catch {
      // Best-effort: alias names + value scanning still apply.
    }
    const columns: ColumnMeta[] = fields.map((f) => {
      const o = this.attCache.get(`${f.tableID}:${f.columnID}`);
      return { name: f.name, originalName: o?.column, table: o?.table };
    });
    return { columns, rows: r.rows ?? [] };
  }

  async listTables(schema?: string): Promise<TableInfo[]> {
    const r = await this.query(
      `SELECT table_schema, table_name, table_type FROM information_schema.tables
       WHERE ($1::text IS NULL AND table_schema NOT IN ('pg_catalog','information_schema'))
          OR table_schema = $1
       ORDER BY table_schema, table_name`,
      [schema ?? null],
    );
    return r.rows.map(([s, n, t]) => ({ schema: String(s), name: String(n), type: String(t) }));
  }

  async describeTable(table: string): Promise<ColumnInfo[]> {
    const [schema, name] = table.includes(".") ? table.split(".") : ["public", table];
    const r = await this.query(
      `SELECT column_name, data_type, is_nullable, column_default
       FROM information_schema.columns
       WHERE table_schema = $1 AND table_name = $2
       ORDER BY ordinal_position`,
      [schema, name],
    );
    return r.rows.map(([n, t, nul, d]) => ({
      name: String(n),
      dataType: String(t),
      nullable: nul === "YES",
      default: d,
    }));
  }

  async close(): Promise<void> {
    await this.pool?.end();
  }
}

export async function createAdapter(cfg: Config): Promise<DbAdapter> {
  const a = cfg.dbType === "mysql" ? new MysqlAdapter(cfg) : new PostgresAdapter(cfg);
  await a.init();
  return a;
}
