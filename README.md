# pii-safe-db-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an LLM query **MySQL** or **PostgreSQL** while **masking PII before any value leaves your machine**.

Most database MCP servers forward the raw result set straight to the model. This one sits in between: queries are read-only, and every result row is scrubbed of emails, phone numbers, names, addresses, Aadhaar, PAN, card numbers, passwords and similar fields before the LLM sees it.

```
LLM  ──►  pii-safe-db-mcp  ──►  MySQL / Postgres
              │
              ├─ read-only SQL guard + READ ONLY transaction
              ├─ column-name PII classification (alias-proof)
              ├─ value scanning inside free text & JSON
              └─ masking: stable tokens / partial / redact
```

## Features

- **MySQL and PostgreSQL** in one server
- **Read-only, enforced three ways:** a static SQL guard (single statement, SELECT/WITH/SHOW/DESCRIBE/EXPLAIN only, no `INTO`/`OUTFILE`/`pg_read_file`/`LOAD_FILE`/`sleep`…), a `READ ONLY` transaction, and a statement timeout
- **Alias-proof column detection:** `SELECT email AS x` is still masked, because the server resolves each result column back to its source column (MySQL `orgName`, Postgres `tableID`/`columnID`)
- **Value scanning:** PII hidden in `notes`, `comments` or JSON columns is detected and masked inline (email, phone, credit card with Luhn check, Aadhaar with Verhoeff check, PAN, SSN, IPv4)
- **LLM-friendly tokens:** in the default `token` mode, the same value always maps to the same token (`<EMAIL_75423bc6b9>`), so the model can still join, group, count distinct and compare
- **Policies:** block columns outright, force-mask extra columns, or allow-list false positives
- **`pii_scan` tool:** samples a table and reports where PII lives, returning counts only and never values

## Tools

| Tool | What it does |
|---|---|
| `list_tables` | Lists the tables and views in the database |
| `describe_table` | Shows a table's columns and types, plus each column's PII class and policy (`visible` / `masked` / `blocked`) |
| `query` | Runs one read-only SQL statement and returns the masked rows (capped at `MAX_ROWS`) |
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
        "DATABASE_URL": "postgres://readonly_user:pass@localhost:5432/mydb",
        "PII_MASK_MODE": "token",
        "PII_BLOCKED_COLUMNS": "password_hash,otp"
      }
    }
  }
}
```

Claude Code one-liner:

```bash
claude mcp add safe-db -e DATABASE_URL=mysql://readonly:pass@localhost:3306/mydb -- npx -y pii-safe-db-mcp
```

## Configuration

| Env var | Default | Description |
|---|---|---|
| `DATABASE_URL` | – | `mysql://user:pass@host:3306/db` or `postgres://user:pass@host:5432/db` |
| `DB_TYPE` | inferred | `mysql` or `postgres` (needed only if you don't set `DATABASE_URL`) |
| `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME` | – | Alternative to `DATABASE_URL` |
| `DB_SSL` | `false` | Enables TLS, with certificate verification |
| `PII_MASK_MODE` | `token` | `token`: `<EMAIL_ab12cd34ef>` · `partial`: `j***@***.com`, `******3210` · `redact`: `[EMAIL]` |
| `PII_TOKEN_SECRET` | random per run | HMAC secret for tokens. Set it to keep tokens stable across restarts |
| `PII_BLOCKED_COLUMNS` | – | Comma list of columns that can never be queried (e.g. `password_hash,otp`) |
| `PII_EXTRA_COLUMNS` | – | Columns that are always fully masked: `notes` or `table.column` |
| `PII_ALLOW_COLUMNS` | – | Columns never masked, for false positives: `name` or `products.name` |
| `PII_SCAN_VALUES` | `true` | Scans text values for embedded PII |
| `MAX_ROWS` | `200` | Maximum number of rows returned per query |
| `QUERY_TIMEOUT_MS` | `15000` | Per-query timeout |

## Example

```sql
SELECT id, full_name, email AS contact, mobile_no, city, notes FROM customers LIMIT 1
```

```json
{
  "id": 1,
  "full_name": "<NAME_5b23526ff1>",
  "contact": "<EMAIL_75423bc6b9>",
  "mobile_no": "<PHONE_5afd76f8b4>",
  "city": "Pune",
  "notes": "prefers call on <PHONE_fd75e06b08>"
}
```

## Detected PII

Detected **by column name** (snake_case and camelCase): email, phone/mobile, first/last/full name, address, zip/pincode, DOB, Aadhaar, PAN, passport, bank account/IBAN, card number, CVV, SSN, IP address, and password/token/secret/api_key/otp. Secrets and CVVs are always fully redacted.

Detected **by value**: emails, phone numbers (international and Indian mobile), credit cards (Luhn-checked), Aadhaar (Verhoeff-checked), PAN, US SSN, and IPv4.

## Security notes and limitations

**Use a read-only database user.** The SQL guard and the read-only transaction are defence in depth. They are not a replacement for least privilege.

**Derived expressions can lose column origin.** For example, `UPPER(full_name)` or `SUBSTR(email, 1, 3)` lose the link to the source column. Value scanning still catches emails, phones, cards and similar values, but **names and addresses inside expressions cannot be detected by pattern**. To be strict:
  - put sensitive columns in `PII_BLOCKED_COLUMNS`, or
  - expose only a curated view or schema to the DB user, or use column-level `GRANT`s.

**Regex-based detection is not perfect.** Run `pii_scan` on your tables, then use `PII_EXTRA_COLUMNS` for any column that holds free-text PII.

**Error messages from the database are scrubbed** before they are returned.

## Development

```bash
npm install
npm test        # builds and runs unit tests
npm start       # runs the server on stdio (needs DATABASE_URL)
```

## License

MIT © Aqib Siddiqui
