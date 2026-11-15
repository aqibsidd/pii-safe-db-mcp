# Changelog

## 0.3.0: Protection mode, policy CLI and Claude Code slash commands

### Added
- **Protection ON/OFF.** OFF behaves like a plain read-only database MCP, with no masking and no policy. It's guarded in several ways:
  - it needs `PII_ALLOW_UNPROTECTED_MODE=true` on the server
  - it isn't an MCP tool, so the model can't toggle it
  - it auto-expires after 30 minutes by default, 8 hours at most, and tampered or expired state is ignored
  - it stays read-only
  - every response carries a banner
  - every switch, and every refused request, is audited
- **`protection_status` tool** (read-only)
- **Policy hot-reload**: edits to the policy file apply on the next call with no reconnect. Invalid edits keep the previous policy and report the error.
- **Policy validation** with readable error messages
- **CLI**:
  - `mode status|on|off [--for 30m]`
  - `policy show|path|init|add|block|remove|allow-table|deny-table|tables|merge`
  - `install-commands [--project]`
- **Claude Code slash commands**: `/pii-status`, `/pii-on`, `/pii-off`, `/pii-add`, `/pii-block`, `/pii-remove`, `/pii-tables`, `/pii-json`. The loosening commands are marked `disable-model-invocation`.
- **New env vars**: `PII_PROTECTION`, `PII_ALLOW_UNPROTECTED_MODE`, `PII_CONFIG_DIR`, `PII_STATE_FILE`
- **Audit records** now include `"protection": "on" | "off"`
- **`test/modes.test.mjs`**: 11 new tests

### Changed
- `PII_POLICY_FILE` now defaults to `~/.config/pii-safe-db/policy.json`, used if it exists
- `pii_scan` recommendations now suggest the `/pii-add` command

## 0.2.0: Security hardening

This release is backward compatible. Without a policy file, behaviour matches 0.1.0, with two exceptions noted under **Changed**.

### Added
- **SQL AST policy engine** (`node-sql-parser`), covering both MySQL and PostgreSQL:
  - per-table rules for sensitive columns: `allow_filtering`, `allow_joining`, `allow_grouping`, `allow_sorting`, `allow_select`
  - comparisons anywhere count as filtering, including the SELECT list and `CASE WHEN`
  - taint tracking through aliases, CTEs, derived tables, scalar subqueries, `UNION` and functions
  - positional `ORDER BY` / `GROUP BY` and select-alias references are resolved
  - whole-row references (`to_jsonb(t)`, `row_to_json(t.*)`) are rejected on protected tables
  - force-masking of derived expressions such as `UPPER(name)` and `SUBSTR(pan, 1, 3)`
- **Table allowlist and denylist**, enforced across joins, subqueries, CTEs, `EXPLAIN`, `DESCRIBE`, `SHOW`, `list_tables`, `describe_table` and `pii_scan`
- **Fail-closed mode**: when a policy is configured, SQL that can't be parsed and verified is rejected
- **Policy file**: `PII_POLICY_FILE` or inline `PII_POLICY`, plus the `ALLOWED_TABLES` / `DENIED_TABLES` / `POLICY_FAIL_CLOSED` env vars
- **Audit logging** (`AUDIT_LOG`, `AUDIT_ACTOR`, `AUDIT_ENVIRONMENT`, `AUDIT_QUERY_SHAPE`). Records actor, environment, database, operation, decision, duration, rows, PII count, masked columns and a literal-free query fingerprint. Never records raw PII or bind parameters.
- **Error sanitisation**: quoted values and `Key (col)=(value)` details are removed from database errors
- **Indian PII recognisers**: GSTIN, IFSC, UPI IDs, context-anchored bank account numbers, and `borrower_name` / `mpin` style column names
- **Custom patterns** (`custom_patterns`) for organisation-specific identifiers such as loan IDs
- `describe_table` now shows which clauses each sensitive column may be used in
- Test suites for SQL bypass attempts (`test/security.test.mjs`) and an end-to-end leak regression (`test/regression.test.mjs`)

### Changed
- Secret columns (password, token, otp, api_key…) can no longer be used in `WHERE`/`JOIN`/`GROUP BY`/`ORDER BY`, even without a policy, because they'd act as oracles
- Database error messages no longer include quoted values
- Masking tokens are protected from being re-matched by later patterns
- The server is split into `createServer()` (testable) and the CLI entry point

## 0.1.0
- Initial release: read-only MySQL/PostgreSQL MCP server with PII masking (token, partial and redact modes), alias-proof column detection, value scanning and the `pii_scan` tool
