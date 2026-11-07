import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { analyzeQuery } from "../dist/analyzer.js";
import { Policy, compileCustomPatterns } from "../dist/policy.js";
import { defaultPiiOptions, scrubText, classifyColumn } from "../dist/pii.js";
import { sanitiseErrorMessage } from "../dist/errors.js";
import { normaliseSql } from "../dist/sqlGuard.js";
import { AuditLogger } from "../dist/audit.js";

const pii = defaultPiiOptions({ secret: "t" });
const strict = new Policy(
  {
    allowed_tables: ["customers", "loans", "public.payments"],
    tables: {
      customers: {
        sensitive_columns: ["name", "mobile", "pan", "aadhaar", "email", "customer_ref"],
        allow_filtering: false,
        allow_joining: false,
        allow_grouping: false,
        allow_sorting: false,
      },
      loans: { blocked_columns: ["internal_notes"] },
    },
  },
  pii,
  new Set(["password_hash"]),
);
const permissive = new Policy({}, pii, new Set());

const blocks = (sql, policy = strict, dialect = "postgres") =>
  assert.throws(() => analyzeQuery(sql, dialect, policy), undefined, `expected BLOCK: ${sql}`);
const allows = (sql, policy = strict, dialect = "postgres") => analyzeQuery(sql, dialect, policy);

for (const dialect of ["postgres", "mysql"]) {
  describe(`SQL bypass protection (${dialect})`, () => {
    const B = (s) => blocks(s, strict, dialect);
    const A = (s) => allows(s, strict, dialect);

    test("sensitive column in JOIN condition is rejected even though SELECT is masked", () => {
      B("SELECT c.customer_id, c.name FROM customers c JOIN loans l ON c.pan = l.pan WHERE c.customer_id = 123");
      B("SELECT c.customer_id FROM customers c JOIN loans l ON l.pan = c.pan");
      B("SELECT c.customer_id FROM customers c LEFT JOIN loans l ON c.customer_id = l.customer_id AND c.mobile = l.mobile");
    });

    test("WHERE / HAVING / comparisons", () => {
      B("SELECT customer_id FROM customers WHERE pan = 'ABCPK1234F'");
      B("SELECT count(*) FROM customers WHERE email LIKE 'a%'");
      B("SELECT customer_id FROM customers WHERE upper(name) = 'RAVI'");
      B("SELECT city FROM customers GROUP BY city HAVING max(name) > 'M'");
      B("SELECT CASE WHEN pan = 'X' THEN 1 ELSE 0 END AS hit FROM customers");
      B("SELECT customer_id FROM customers WHERE mobile IN ('9876543210')");
      B("SELECT customer_id FROM customers WHERE mobile BETWEEN '9' AND '99'");
    });

    test("GROUP BY / PARTITION BY / ORDER BY, including aliases and positions", () => {
      B("SELECT name FROM customers GROUP BY name");
      B("SELECT customer_id FROM customers ORDER BY name");
      B("SELECT name AS n FROM customers ORDER BY n");
      B("SELECT name FROM customers ORDER BY 1");
      B("SELECT name, count(*) FROM customers GROUP BY 1");
      B("SELECT row_number() OVER (PARTITION BY pan) AS rn FROM customers");
      B("SELECT row_number() OVER (ORDER BY email) AS rn FROM customers");
    });

    test("aliases, CTEs, derived tables and subqueries", () => {
      B("WITH x AS (SELECT pan AS p FROM customers) SELECT l.id FROM loans l WHERE l.loan_pan IN (SELECT p FROM x)");
      B("SELECT * FROM (SELECT customer_ref AS r FROM customers) t WHERE t.r = 5");
      B("SELECT id FROM loans WHERE borrower_pan IN (SELECT pan FROM customers)");
      B("SELECT id FROM loans l WHERE EXISTS (SELECT 1 FROM customers c WHERE c.pan = l.borrower_pan)");
      B("WITH a AS (SELECT name FROM customers), b AS (SELECT name AS nn FROM a) SELECT nn FROM b ORDER BY nn");
      B("SELECT x.e FROM (SELECT y.email AS e FROM (SELECT email FROM customers) y) x WHERE x.e IS NOT NULL");
    });

    test("table allowlist covers joins, subqueries and CTEs", () => {
      B("SELECT * FROM salaries");
      B("SELECT c.customer_id FROM customers c JOIN secrets s ON s.id = c.customer_id");
      B("SELECT customer_id FROM customers WHERE customer_id IN (SELECT id FROM hidden)");
      B("WITH h AS (SELECT * FROM hidden) SELECT * FROM h");
      B("SELECT * FROM information_schema.columns");
      A("SELECT * FROM payments");
      A("SELECT customer_id FROM customers");
    });

    test("blocked columns (global and per-table)", () => {
      B("SELECT password_hash FROM customers");
      B("SELECT l.internal_notes FROM loans l");
      B("SELECT id FROM loans WHERE internal_notes LIKE '%x%'");
    });

    test("whole-row references on protected tables", () => {
      if (dialect === "postgres") {
        B("SELECT to_jsonb(c) FROM customers c");
        B("SELECT row_to_json(c.*) FROM customers c");
      } else {
        B("SELECT JSON_OBJECT('n', c.name) AS j FROM customers c WHERE c.name = 'x'");
      }
    });

    test("safe analytics still work", () => {
      A("SELECT city, count(*) FROM customers GROUP BY city ORDER BY count(*) DESC");
      A("SELECT count(DISTINCT pan) AS n, city FROM customers GROUP BY city");
      A("SELECT c.customer_id, l.amount FROM customers c JOIN loans l ON c.customer_id = l.customer_id WHERE l.amount > 1000");
      A("SELECT customer_id FROM customers c JOIN loans USING (customer_id)");
      A("SELECT name, email FROM customers WHERE customer_id = 5");
    });

    test("expressions over sensitive columns are force-masked", () => {
      const a = A("SELECT upper(name) AS nm, customer_id, concat(email, '') AS e2 FROM customers");
      assert.equal(a.maskIndexes.get(0), "NAME");
      assert.equal(a.maskIndexes.has(1), false);
      assert.equal(a.maskIndexes.get(2), "EMAIL");
      const b = A("SELECT a.* FROM (SELECT name AS who FROM customers) a");
      assert.equal(b.maskNames.get("who"), "NAME");
      const c = A("WITH x AS (SELECT substr(pan, 1, 3) AS pfx FROM customers) SELECT pfx FROM x");
      assert.equal(c.maskIndexes.get(0), "PAN");
      const d = A("SELECT (SELECT max(name) FROM customers) AS top");
      assert.equal(d.maskIndexes.get(0), "NAME");
    });

    test("unaliased derived expression with SELECT * is rejected (cannot be mapped)", () => {
      B("SELECT * FROM (SELECT upper(name) FROM customers) t");
    });

    test("UNION propagates taint", () => {
      const a = A("SELECT customer_id AS v FROM customers UNION SELECT name FROM customers");
      assert.equal(a.maskIndexes.get(0), "NAME");
    });

    test("EXPLAIN analyses the inner query", () => {
      B("EXPLAIN SELECT * FROM customers WHERE pan = 'X'");
      B("EXPLAIN SELECT * FROM salaries");
    });
  });
}

describe("policy behaviour", () => {
  test("permissive default keeps v0.1 behaviour", () => {
    allows("SELECT id FROM customers WHERE email = 'a@b.com' ORDER BY name", permissive);
    allows("SELECT * FROM anything", permissive);
  });

  test("secrets can never be used as an oracle, even with no policy file", () => {
    blocks("SELECT id FROM users WHERE password_hash LIKE 'a%'", permissive);
    blocks("SELECT id FROM users ORDER BY api_key", permissive);
  });

  test("fail-closed rejects unparseable SQL when a policy is configured", () => {
    blocks("SELECT * FROM customers TABLESAMPLE ??? weird", strict);
    assert.equal(strict.failClosed, true);
    assert.equal(permissive.failClosed, false);
  });

  test("DESCRIBE / SHOW respect the allowlist", () => {
    blocks("DESCRIBE salaries", strict, "mysql");
    blocks("SHOW COLUMNS FROM salaries", strict, "mysql");
    allows("DESCRIBE customers", strict, "mysql");
    allows("SHOW TABLES", strict, "mysql");
  });

  test("schema-qualified allowlist entries", () => {
    allows("SELECT * FROM public.payments");
    blocks("SELECT * FROM other.payments");
  });
});

describe("Indian PII recognisers", () => {
  const s = (t) => scrubText(t, pii);
  test("PAN, GSTIN, IFSC, UPI, Aadhaar, mobile, bank account", () => {
    const out = s(
      "PAN ABCPK1234F GSTIN 27ABCPK1234F1Z5 IFSC HDFC0001234 UPI ravi.k@okhdfcbank aadhaar 2341 2341 2346 mob 9876543210 A/C No: 123456789012",
    );
    for (const raw of ["ABCPK1234F", "27ABCPK1234F1Z5", "HDFC0001234", "ravi.k@okhdfcbank", "2341 2341 2346", "9876543210", "123456789012"]) {
      assert.ok(!out.includes(raw), `${raw} leaked: ${out}`);
    }
    assert.match(out, /<GSTIN_/);
    assert.match(out, /<IFSC_/);
    assert.match(out, /<UPI_/);
    assert.match(out, /<BANK_ACCOUNT_/);
    assert.match(out, /A\/C No: </, "context label is preserved");
  });

  test("emails are not mistaken for UPI", () => {
    assert.match(s("mail ravi@example.com"), /<EMAIL_/);
  });

  test("custom patterns (loan IDs) and custom column names", () => {
    const c = compileCustomPatterns([{ name: "loan_id", pattern: "\\bLN\\d{8}\\b", column_names: ["loan_no"] }]);
    const o = defaultPiiOptions({ secret: "t", customRules: c.valueRules, customColumns: c.columnTypes });
    assert.match(scrubText("loan LN00012345 overdue", o), /<LOAN_ID_[0-9a-f]{10}>/);
    assert.equal(classifyColumn(["loan_no"], undefined, o), "LOAN_ID");
  });

  test("Indian column names", () => {
    for (const [col, type] of [["ifsc_code", "IFSC"], ["upi_id", "UPI"], ["gstin", "GSTIN"], ["borrower_name", "NAME"], ["mpin", "SECRET"]]) {
      assert.equal(classifyColumn([col], undefined, pii), type, col);
    }
  });

  test("masking tokens are never re-matched by later rules", () => {
    for (let i = 0; i < 300; i++) {
      const out = s(`a${i}@x.com 98765${String(i).padStart(5, "0")}`);
      assert.doesNotMatch(out, /<[A-Z_]+_[^>]*</, out);
    }
  });
});

describe("error sanitisation", () => {
  const e = (m) => sanitiseErrorMessage(m, pii);
  test("removes echoed values but keeps identifiers", () => {
    const a = e("Duplicate entry 'Ravi Kumar' for key 'customers.name'");
    assert.ok(!a.includes("Ravi"), a);
    const b = e('duplicate key value violates unique constraint "customers_email_key"\nDETAIL: Key (email)=(ravi@example.com) already exists.');
    assert.ok(!b.includes("ravi@example.com"), b);
    assert.match(b, /customers_email_key/);
    const c = e('invalid input syntax for type integer: "ABCPK1234F"');
    assert.ok(!c.includes("ABCPK1234F"), c);
    const d = e('column "pan" does not exist');
    assert.match(d, /"pan"/);
    const f = e("Key (email)=(ravi@example.com) already exists");
    assert.ok(!f.includes("ravi"), f);
  });
});

describe("audit log", () => {
  test("query shape has no literals; record never contains raw values", () => {
    const shape = normaliseSql(`SELECT * FROM customers WHERE pan = 'ABCPK1234F' AND mobile = 9876543210 AND n = "Ravi Kumar" -- Ravi`);
    for (const raw of ["ABCPK1234F", "9876543210", "Ravi"]) assert.ok(!shape.includes(raw), shape);
    assert.match(shape, /pan = \?/);

    const lines = [];
    const log = new AuditLogger(
      { target: "x", actor: "claude-code", environment: "preprod", database: "customer_db", dbType: "mysql", includeQueryShape: true },
      (l) => lines.push(l),
    );
    log.log({ tool: "query", operation: "SELECT", decision: "ALLOWED", started: Date.now(), rows: 10, pii: 3, sql: "SELECT * FROM t WHERE email='ravi@example.com'" });
    const rec = JSON.parse(lines[0]);
    assert.equal(rec.actor, "claude-code");
    assert.equal(rec.environment, "preprod");
    assert.equal(rec.database, "customer_db");
    assert.equal(rec.decision, "ALLOWED");
    assert.equal(rec.rows_returned, 10);
    assert.equal(rec.pii_detected, 3);
    assert.equal(rec.raw_pii_logged, false);
    assert.match(rec.query_fingerprint, /^[0-9a-f]{16}$/);
    assert.ok(!lines[0].includes("ravi"), lines[0]);
  });
});
