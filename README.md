# pii-safe-db-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an LLM query **MySQL** or **PostgreSQL** while **masking PII before any value leaves your machine**. It also controls *how* sensitive columns may be used in a query.

Most database MCP servers forward the raw result set straight to the model. This one sits in between:

```
LLM  ──►  pii-safe-db-mcp  ──────────────────────────────────►  MySQL / Postgres
              │
              ├─ 1. static read-only guard (single statement, no writes/files/sleep)
              ├─ 2. SQL AST policy check
              │      • table allow / deny list (joins, subqueries, CTEs too)
              │      • sensitive columns in WHERE / JOIN / GROUP BY / ORDER BY
              │      • taint tracking through aliases, CTEs, derived tables, expressions
              ├─ 3. execution in a READ ONLY transaction + timeout
              ├─ 4. result masking (column origin + AST taint + value scanning)
              ├─ 5. error-message scrubbing
              └─ 6. audit log (no raw PII, ever)
```

## Why masking the output isn't enough

```sql
SELECT c.customer_id, c.name
FROM customers c JOIN loans l ON c.pan = l.pan
WHERE c.customer_id = 123;
```

Every value this query *returns* can be masked, yet it still uses the customer's PAN to link two datasets. Filters work the same way. `WHERE email LIKE 'a%'`, `ORDER BY name` and `CASE WHEN pan = 'X'` act as **oracles**: they let a model reconstruct values one character at a time without ever seeing them. pii-safe-db-mcp parses every query into an AST and rejects these uses according to your policy.

## Features

- **MySQL and PostgreSQL** in one server
- **Read-only, enforced three ways:** a static SQL guard, a `READ ONLY` transaction, and a statement timeout
- **SQL AST security (v0.2):** per-table rules for sensitive columns in `WHERE`/`HAVING`, `JOIN ON`/`USING`, `GROUP BY`/`PARTITION BY` and `ORDER BY`, including positional (`ORDER BY 1`) and alias references
- **Taint tracking (v0.2):** sensitive columns are followed through aliases, CTEs, derived tables, scalar subqueries, `UNION`s and functions. `UPPER(name) AS x` and `SUBSTR(pan, 1, 3)` are still masked.
- **Table allowlist and denylist (v0.2):** enforced for every table a query touches, including joins, subqueries and CTEs, and also applied to `list_tables`, `describe_table`, `pii_scan`, `DESCRIBE` and `SHOW`
- **Fail-closed (v0.2):** when a policy is configured, any query that can't be parsed and verified is rejected
- **Error sanitisation (v0.2):** database errors that echo values (`Duplicate entry 'Ravi Kumar'…`, `Key (email)=(…)`) are scrubbed
- **Audit logging (v0.2):** each record holds actor, environment, database, operation, decision, duration, row count, PII count and a literal-free query fingerprint. It never contains raw PII.
- **Indian PII recognisers (v0.2):** PAN, Aadhaar (Verhoeff-checked), GSTIN, IFSC, UPI IDs, bank account numbers (context-anchored) and mobile numbers, plus **custom patterns** such as loan IDs
- **Alias-proof column detection:** `SELECT email AS x` is still masked, because the server uses the driver's column-origin metadata *and* the AST
- **Value scanning:** PII hidden in `notes`, `comments` or JSON columns is masked inline
- **LLM-friendly tokens:** the same value always maps to the same token (`<EMAIL_75423bc6b9>`), so the model can still join on output, count distinct and compare
- **Secrets are never oracles:** password, token, OTP and API-key columns can't be filtered, joined, grouped or sorted on, even without a policy file

## Tools

| Tool | What it does |
|---|---|
| `list_tables` | Lists the tables and views this server is allowed to access |
| `describe_table` | Shows columns and types, each column's PII class and policy (`visible` / `masked` / `blocked`), and which clauses it may be used in |
| `query` | Runs one read-only SQL statement, checked against the policy, and returns masked rows (capped at `MAX_ROWS`) |
| `pii_scan` | Samples rows and reports PII found by column name and by value, as counts only |

## Quick start

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "safe-db": {
      "command": "npx",
      "args": ["-y", "pii-safe-db-mcp"],
      "env": {
        "DATABASE_URL": "postgres://readonly_user:pass@localhost:5432/customer_db",
        "PII_POLICY_FILE": "/path/to/pii-policy.json",
        "AUDIT_LOG": "/var/log/pii-safe-db-mcp/audit.jsonl",
        "AUDIT_ENVIRONMENT": "preprod"
      }
    }
  }
}
```

Claude Code one-liner:

```bash
claude mcp add safe-db \
  -e DATABASE_URL=mysql://readonly:pass@localhost:3306/customer_db \
  -e PII_POLICY_FILE=$PWD/pii-policy.json \
  -- npx -y pii-safe-db-mcp
```

## Policy file

The policy file is optional. Without one, the server behaves as v0.1 did: masking only, except that secret columns are never usable as oracles. See [`examples/pii-policy.json`](examples/pii-policy.json) for a complete example.

```json
{
  "allowed_tables": ["customers", "loans", "public.payments"],
  "denied_tables": ["internal_audit"],
  "default": {
    "allow_filtering": true,
    "allow_joining": true,
    "allow_grouping": true,
    "allow_sorting": true
  },
  "tables": {
    "customers": {
      "sensitive_columns": ["name", "mobile", "pan", "aadhaar", "email"],
      "blocked_columns": ["kyc_document_url"],
      "allow_filtering": false,
      "allow_joining": false,
      "allow_grouping": false,
      "allow_sorting": false
    },
    "loans": {
      "sensitive_columns": ["pan"],
      "allow_joining": false
    }
  },
  "custom_patterns": [
    { "name": "LOAN_ID", "pattern": "\\bLN\\d{8}\\b", "column_names": ["loan_no"] }
  ],
  "fail_closed": true,
  "treat_detected_pii_as_sensitive": true
}
```

| Key | Meaning |
|---|---|
| `allowed_tables` | If set, only these tables can be touched anywhere in a query. Accepts `table`, `schema.table` or `schema.*`. |
| `denied_tables` | These tables can never be touched. The denylist wins over the allowlist. |
| `tables.<t>.sensitive_columns` | Columns that are always masked in output and subject to the clause rules below. Use this for PII that name detection can't see, such as `customer_ref`. |
| `tables.<t>.blocked_columns` | Columns that can't be referenced at all, and can't come back through `SELECT *`. |
| `allow_select` | Set to `false` to block the table's sensitive columns entirely. |
| `allow_filtering` | Allows `WHERE`, `HAVING` and **any comparison** (`=`, `LIKE`, `IN`, `BETWEEN`, `CASE WHEN …`), including comparisons in the SELECT list. |
| `allow_joining` | Allows `JOIN … ON` and `USING`. |
| `allow_grouping` | Allows `GROUP BY` and window `PARTITION BY`. |
| `allow_sorting` | Allows `ORDER BY` and window `ORDER BY`. |
| `default` | Clause rules for sensitive columns in tables that have no entry, and for auto-detected PII such as `email` or `phone`. |
| `treat_detected_pii_as_sensitive` | Applies clause rules to columns detected as PII by name. Default `true`. |
| `custom_patterns` | Extra value patterns (regex) and the column names that carry them. Masked as `<NAME_xxxx>`. |
| `fail_closed` | Rejects queries the parser can't verify. Defaults to `true` whenever the policy restricts anything. |

**Always allowed:** `COUNT(col)` and `COUNT(DISTINCT col)` on sensitive columns, because they reveal no values.

**Always force-masked:** any output expression derived from a sensitive column. If a sensitive expression is combined with `SELECT *`, it must have an alias.

## Audit log

By default, one JSON line per tool call is written to stderr. Set `AUDIT_LOG` to a file path to append to a file (mode 600), or to `off` to disable it.

```json
{
  "timestamp": "2026-11-07T09:23:57.249Z",
  "actor": "claude-code",
  "environment": "preprod",
  "database": "customer_db",
  "db_type": "mysql",
  "tool": "query",
  "operation": "SELECT",
  "decision": "ALLOWED",
  "tables": ["customers", "loans"],
  "duration_ms": 12,
  "rows_returned": 10,
  "pii_detected": 3,
  "masked_columns": ["name", "mobile"],
  "query_fingerprint": "ef4144c6cfcee85f",
  "query_shape": "SELECT name, mobile FROM customers WHERE id = ?",
  "raw_pii_logged": false
}
```

- `decision` is `ALLOWED`, `BLOCKED` (policy or guard) or `ERROR` (database error, sanitised).
- `actor` comes from `AUDIT_ACTOR`. If that isn't set, the MCP client's own name is used (e.g. `claude-code`).
- `query_shape` has every literal replaced by `?`, so it never contains values. Disable it with `AUDIT_QUERY_SHAPE=false`. Bind parameters are never logged.

## Configuration

| Env var | Default | Description |
|---|---|---|
| `DATABASE_URL` | – | `mysql://user:pass@host:3306/db` or `postgres://user:pass@host:5432/db` |
| `DB_TYPE` | inferred | `mysql` or `postgres` (needed only if you don't set `DATABASE_URL`) |
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | – | Alternative to `DATABASE_URL` |
| `DB_SSL` | `false` | Enables TLS, with certificate verification |
| `PII_POLICY_FILE` | – | Path to the JSON policy file (see above) |
| `PII_POLICY` | – | The policy as an inline JSON string, instead of a file |
| `ALLOWED_TABLES` / `DENIED_TABLES` | – | Comma-separated shortcut for the allow and deny lists |
| `POLICY_FAIL_CLOSED` | auto | Forces fail-closed on (`true`) or off (`false`) |
| `PII_MASK_MODE` | `token` | `token`: `<EMAIL_ab12cd34ef>` · `partial`: `j***@***.com`, `******3210` · `redact`: `[EMAIL]` |
| `PII_TOKEN_SECRET` | random per run | HMAC secret for tokens. Set it to keep tokens stable across restarts |
| `PII_BLOCKED_COLUMNS` | – | Comma list of columns that can never be queried in any table |
| `PII_EXTRA_COLUMNS` | – | Columns that are always fully redacted: `notes` or `table.column` |
| `PII_ALLOW_COLUMNS` | – | Columns that are never masked, for false positives: `name` or `products.name` |
| `PII_SCAN_VALUES` | `true` | Scans text values for embedded PII |
| `MAX_ROWS` | `200` | Maximum number of rows returned per query |
| `QUERY_TIMEOUT_MS` | `15000` | Per-query timeout |
| `AUDIT_LOG` | `stderr` | `stderr`, `off`, or a file path (JSON lines) |
| `AUDIT_ACTOR` | MCP client name | Actor recorded in audit records |
| `AUDIT_ENVIRONMENT` | `default` | Environment label, e.g. `preprod` or `prod` |
| `AUDIT_QUERY_SHAPE` | `true` | Includes the literal-free query shape in audit records |

## Examples

```sql
-- ✅ allowed, output masked
SELECT c.id, UPPER(c.full_name) AS nm, l.amount
FROM customers c JOIN loans l ON c.id = l.customer_id ORDER BY l.amount DESC
-- → [{"id":1,"nm":"<NAME_ac0d9937c4>","amount":500000}, ...]

-- ✅ aggregates over sensitive columns
SELECT city, COUNT(DISTINCT email) AS n FROM customers GROUP BY city

-- ❌ Blocked: Column customers.pan is sensitive and cannot be used in JOIN conditions
SELECT c.name FROM customers c JOIN loans l ON c.pan = l.pan

-- ❌ Blocked: Column customers.email ... cannot be used in WHERE/HAVING filters or comparisons
SELECT id FROM customers WHERE email LIKE 'r%'

-- ❌ Blocked: Access to table "salaries" is not allowed by policy.
SELECT * FROM customers c WHERE EXISTS (SELECT 1 FROM salaries s WHERE s.id = c.id)
```

## Detected PII

Detected **by column name** (snake_case and camelCase):

| Category | Columns |
|---|---|
| Contact and identity | email, phone/mobile, first/last/full/borrower name, address, zip/pincode, DOB |
| Government IDs | Aadhaar, PAN, GSTIN, passport, SSN |
| Financial | bank account/IBAN, IFSC, UPI/VPA, card number, CVV |
| Network | IP address |
| Secrets | password, token, secret, api_key, otp, pin, mpin |

Detected **by value**: emails, UPI IDs, phone numbers (international and Indian mobile), credit cards (Luhn-checked), Aadhaar (Verhoeff-checked), PAN, GSTIN, IFSC, bank accounts next to an "A/C No" or "account" label, US SSN, IPv4, and your custom patterns.

## Security notes and limitations

- **Use a read-only database user.** The SQL guard, AST policy and read-only transaction are defence in depth. They are not a replacement for least privilege. For the strongest guarantee, also expose only a curated schema or views to that user.
- **Name detection and value patterns are heuristics.** Run `pii_scan`, then list any extra columns under `tables.<t>.sensitive_columns`.
- **Value scanning can't detect free-text names or addresses.** Add those columns to the policy.
- **Configure a policy for strict guarantees.** With a policy, the server fails closed on SQL it can't parse. Without one, unparseable SQL falls back to masking only.
- **JSON paths are covered by value scanning, not the AST.** In `data->>'pan'`, the output is masked by the PAN pattern. If a whole JSON column is sensitive, list it in `sensitive_columns`.

## Development

```bash
npm install
npm test        # builds, then runs unit, SQL-bypass and end-to-end regression tests
npm start       # runs the server on stdio (needs DATABASE_URL)
```

The test suites:

| File | Covers |
|---|---|
| `test/pii.test.mjs` | Detection and masking |
| `test/security.test.mjs` | SQL bypass attempts in both dialects, Indian recognisers, error sanitisation, audit |
| `test/regression.test.mjs` | Runs the MCP server in memory, calls every tool and error path, and asserts that **no raw PII appears in any response or audit record** |

## License

MIT © Aqib Siddiqui
