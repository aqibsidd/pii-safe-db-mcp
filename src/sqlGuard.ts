/**
 * Static read-only guard for SQL. This is defence in depth: queries are ALSO
 * executed inside a READ ONLY transaction, and you should connect with a
 * database user that only has SELECT privileges.
 */

const ALLOWED_LEADING = new Set(["select", "with", "show", "describe", "desc", "explain", "values", "table"]);

// Keywords that can turn a single SELECT/WITH statement into a write or a
// file/side-effect operation. Kept deliberately short so that common column
// names (comment, start, status...) and functions (REPLACE()) still work.
const FORBIDDEN_KEYWORDS = [
  "insert", "update", "delete", "merge", "upsert", "drop", "alter", "create", "truncate",
  "grant", "revoke", "call", "exec", "execute", "copy", "into", "outfile", "dumpfile",
  "vacuum", "reindex", "shutdown", "kill",
];

const FORBIDDEN_FUNCTIONS = [
  // Postgres file / network / timing
  "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file", "lo_import", "lo_export",
  "lo_get", "dblink", "dblink_exec", "pg_sleep", "pg_terminate_backend", "pg_cancel_backend",
  "set_config", "pg_reload_conf", "query_to_xml", "copy_to",
  // MySQL
  "load_file", "sleep", "benchmark", "sys_exec", "sys_eval",
];

export class SqlGuardError extends Error {}

/** Remove comments and string/identifier literals so keyword checks can't be fooled. */
export function stripSql(sql: string): string {
  let out = "";
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const c = sql[i];
    const next = sql[i + 1];
    if (c === "-" && next === "-") {
      while (i < n && sql[i] !== "\n") i++;
      out += " ";
    } else if (c === "#") {
      while (i < n && sql[i] !== "\n") i++;
      out += " ";
    } else if (c === "/" && next === "*") {
      // MySQL executable comments /*! ... */ are code, not comments.
      if (sql[i + 2] === "!") throw new SqlGuardError("MySQL executable comments (/*! */) are not allowed.");
      const end = sql.indexOf("*/", i + 2);
      i = end === -1 ? n : end + 2;
      out += " ";
    } else if (c === "'" || c === '"' || c === "`") {
      const q = c;
      i++;
      while (i < n) {
        if (sql[i] === "\\" && q !== "`") {
          i += 2;
          continue;
        }
        if (sql[i] === q) {
          if (sql[i + 1] === q) {
            i += 2;
            continue;
          }
          break;
        }
        i++;
      }
      i++;
      // Keep identifiers' contents for column checks, blank out string literals.
      out += q === "'" ? " '' " : ` ${q}ident${q} `;
    } else if (c === "$") {
      // Postgres dollar quoting: $tag$ ... $tag$
      const m = sql.slice(i).match(/^\$([A-Za-z_][A-Za-z0-9_]*)?\$/);
      if (m) {
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        i = end === -1 ? n : end + tag.length;
        out += " '' ";
      } else {
        out += c;
        i++;
      }
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

export function assertReadOnly(sql: string): string {
  const trimmed = sql.trim().replace(/;\s*$/, "");
  if (!trimmed) throw new SqlGuardError("Empty query.");
  const stripped = stripSql(trimmed);

  if (stripped.includes(";")) throw new SqlGuardError("Multiple statements are not allowed.");

  const lower = stripped.toLowerCase();
  const first = lower.trim().match(/^\(*\s*([a-z]+)/)?.[1];
  if (!first || !ALLOWED_LEADING.has(first)) {
    throw new SqlGuardError(
      `Only read-only statements are allowed (SELECT, WITH, SHOW, DESCRIBE, EXPLAIN). Got: ${first ?? "unknown"}`,
    );
  }

  const words = new Set(lower.match(/[a-z_][a-z0-9_]*/g) ?? []);
  for (const kw of FORBIDDEN_KEYWORDS) {
    if (words.has(kw)) throw new SqlGuardError(`Forbidden keyword in read-only query: ${kw.toUpperCase()}`);
  }
  for (const fn of FORBIDDEN_FUNCTIONS) {
    if (new RegExp(`\\b${fn}\\s*\\(`).test(lower)) throw new SqlGuardError(`Forbidden function: ${fn}()`);
  }
  if (/\bfor\s+(update|share|no\s+key\s+update|key\s+share)\b/.test(lower)) {
    throw new SqlGuardError("Row locking clauses are not allowed.");
  }
  return trimmed;
}

/** Throw if the query references any of the blocked column names as an identifier. */
export function assertNoBlockedColumns(sql: string, blocked: Set<string>): void {
  if (blocked.size === 0) return;
  // Keep identifier contents this time (quoted identifiers can still name a column).
  const noStrings = sql
    .replace(/'(?:[^'\\]|\\.|'')*'/g, "''")
    .replace(/--[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\//g, " ")
    .toLowerCase();
  const idents = noStrings.match(/[a-z_][a-z0-9_$]*/g) ?? [];
  for (const id of idents) {
    if (blocked.has(id)) throw new SqlGuardError(`Column "${id}" is blocked by policy and cannot be queried.`);
  }
}

export function isValidIdentifier(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_$]*(\.[A-Za-z_][A-Za-z0-9_$]*)?$/.test(name);
}
