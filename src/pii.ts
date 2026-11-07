import { createHmac, randomBytes } from "node:crypto";

export type PiiType =
  | "EMAIL"
  | "PHONE"
  | "CREDIT_CARD"
  | "CVV"
  | "SSN"
  | "AADHAAR"
  | "PAN"
  | "PASSPORT"
  | "BANK_ACCOUNT"
  | "IP_ADDRESS"
  | "DOB"
  | "ADDRESS"
  | "POSTAL_CODE"
  | "NAME"
  | "SECRET";

export type MaskMode = "token" | "partial" | "redact";

export interface PiiOptions {
  mode: MaskMode;
  /** Secret used for deterministic tokens. Random per process if not provided. */
  secret: string;
  /** Column names (or table.column) that are never masked. Lower-case. */
  allowColumns: Set<string>;
  /** Extra column names (or table.column) that are always masked. Lower-case. */
  extraColumns: Set<string>;
  /** Scan free-text values for PII patterns (emails, phones, cards...). */
  scanValues: boolean;
}

export function defaultPiiOptions(partial: Partial<PiiOptions> = {}): PiiOptions {
  return {
    mode: "token",
    secret: randomBytes(32).toString("hex"),
    allowColumns: new Set(),
    extraColumns: new Set(),
    scanValues: true,
    ...partial,
  };
}

/* ------------------------------------------------------------------ */
/* Column-name classification                                          */
/* ------------------------------------------------------------------ */

const COLUMN_RULES: Array<[RegExp, PiiType]> = [
  [/(^|_)(password|passwd|pwd|pass_?hash|secret|api_?key|access_?token|refresh_?token|auth_?token|private_?key|otp|pin)($|_)/, "SECRET"],
  [/(^|_)(e_?mail|email_?(id|address)?)($|_)/, "EMAIL"],
  [/(^|_)(phone|mobile|cell|telephone|tel|msisdn|whatsapp|contact_?(no|num|number))($|_)/, "PHONE"],
  [/(^|_)(card_?(no|num|number)|cc_?(no|num|number)?|credit_?card|debit_?card|pan_?card_?number)($|_)/, "CREDIT_CARD"],
  [/(^|_)(cvv|cvc|card_?security_?code)($|_)/, "CVV"],
  [/(^|_)(ssn|social_?security(_?(no|number))?)($|_)/, "SSN"],
  [/(^|_)(aadhaa?r|aadhaa?r_?(no|num|number)|uid_?(no|number)|uidai)($|_)/, "AADHAAR"],
  [/(^|_)(pan|pan_?(no|num|number)|pancard)($|_)/, "PAN"],
  [/(^|_)(passport(_?(no|num|number))?)($|_)/, "PASSPORT"],
  [/(^|_)((bank_?)?acc(oun)?t_?(no|num|number)|iban|routing_?(no|number))($|_)/, "BANK_ACCOUNT"],
  [/(^|_)(ip|ip_?addr(ess)?|last_?login_?ip|remote_?addr)($|_)/, "IP_ADDRESS"],
  [/(^|_)(dob|date_?of_?birth|birth_?date|birthday)($|_)/, "DOB"],
  [/(^|_)(address|addr|street|address_?line_?\d?|house_?(no|number))($|_)/, "ADDRESS"],
  [/(^|_)(zip|zip_?code|postal_?code|postcode|pin_?code|pincode)($|_)/, "POSTAL_CODE"],
  [/^((first|last|middle|full|given|family|sur|customer|user|contact|father|mother|spouse|nominee|account_?holder|applicant)_?name|name|surname)$/, "NAME"],
];

/** Normalise camelCase / spaces / dashes to snake_case lower-case. */
export function normaliseColumnName(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[\s\-.]+/g, "_")
    .toLowerCase();
}

/**
 * Classify a column. `names` may contain the alias and the original column
 * name; `table` is the source table (if known). Returns null for non-PII.
 */
export function classifyColumn(
  names: Array<string | undefined>,
  table: string | undefined,
  opts: PiiOptions,
): PiiType | null {
  const candidates = names.filter((n): n is string => !!n).map(normaliseColumnName);
  const t = table?.toLowerCase();
  for (const n of candidates) {
    if (opts.allowColumns.has(n) || (t && opts.allowColumns.has(`${t}.${n}`))) return null;
  }
  for (const n of candidates) {
    if (opts.extraColumns.has(n) || (t && opts.extraColumns.has(`${t}.${n}`))) return "SECRET";
  }
  for (const n of candidates) {
    for (const [re, type] of COLUMN_RULES) if (re.test(n)) return type;
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Value-level detection                                               */
/* ------------------------------------------------------------------ */

function luhnValid(digits: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

// Verhoeff checksum (used by Aadhaar) to keep false positives low.
const VD = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VP = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
function verhoeffValid(digits: string): boolean {
  let c = 0;
  const rev = digits.split("").reverse();
  for (let i = 0; i < rev.length; i++) c = VD[c][VP[i % 8][Number(rev[i])]];
  return c === 0;
}

interface ValueRule {
  type: PiiType;
  re: RegExp;
  validate?: (match: string) => boolean;
}

// Order matters: more specific patterns first.
const VALUE_RULES: ValueRule[] = [
  { type: "EMAIL", re: /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g },
  {
    type: "CREDIT_CARD",
    re: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: (m) => {
      const d = m.replace(/\D/g, "");
      return d.length >= 13 && d.length <= 19 && luhnValid(d);
    },
  },
  {
    type: "AADHAAR",
    re: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g,
    validate: (m) => verhoeffValid(m.replace(/\D/g, "")),
  },
  { type: "SSN", re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { type: "PAN", re: /\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b/g },
  {
    type: "PHONE",
    // +91 98765 43210, (555) 123-4567, +1-555-123-4567, 9876543210
    re: /(?<![\w.+])(?:\+\d{1,3}[ \-.]?)?(?:\(\d{2,4}\)[ \-.]?)?\d(?:[ \-.]?\d){8,12}(?!\w)(?!\.\d)/g,
    validate: (m) => {
      const d = m.replace(/\D/g, "");
      if (d.length < 10 || d.length > 13) return false;
      // Explicit international / area-code formatting → phone.
      if (/[+(]/.test(m)) return true;
      // Bare or separated: Indian mobile (10 digits starting 6-9, optional 0/91 prefix)
      // or a NANP-style 3-3-4 grouping.
      if (/^(0|91)?[6-9]\d{9}$/.test(d)) return true;
      return /^\d{3}[ \-.]\d{3}[ \-.]\d{4}$/.test(m);
    },
  },
  {
    type: "IP_ADDRESS",
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  },
];

/* ------------------------------------------------------------------ */
/* Masking                                                             */
/* ------------------------------------------------------------------ */

export function token(type: PiiType, value: string, secret: string): string {
  const h = createHmac("sha256", secret).update(`${type}:${value}`).digest("hex").slice(0, 10);
  return `<${type}_${h}>`;
}

function partial(type: PiiType, value: string): string {
  switch (type) {
    case "EMAIL": {
      const [user, domain = ""] = value.split("@");
      const tld = domain.includes(".") ? domain.slice(domain.lastIndexOf(".")) : "";
      return `${user.slice(0, 1)}***@***${tld}`;
    }
    case "PHONE":
    case "CREDIT_CARD":
    case "AADHAAR":
    case "BANK_ACCOUNT": {
      const d = value.replace(/\D/g, "");
      return `${"*".repeat(Math.max(0, d.length - 4))}${d.slice(-4)}`;
    }
    case "PAN":
    case "PASSPORT":
      return `${"*".repeat(Math.max(0, value.length - 2))}${value.slice(-2)}`;
    case "NAME":
      return value
        .split(/\s+/)
        .map((p) => (p ? `${p[0]}***` : p))
        .join(" ");
    case "DOB": {
      const y = value.match(/\b(19|20)\d{2}\b/);
      return y ? `${y[0]}-**-**` : `[${type}]`;
    }
    case "POSTAL_CODE":
      return `${value.slice(0, 2)}${"*".repeat(Math.max(0, value.length - 2))}`;
    default:
      return `[${type}]`;
  }
}

export function maskValue(type: PiiType, value: string, opts: PiiOptions): string {
  // Secrets / CVVs are never partially revealed or tokenised.
  if (type === "SECRET" || type === "CVV") return `[${type}]`;
  switch (opts.mode) {
    case "redact":
      return `[${type}]`;
    case "partial":
      return partial(type, value);
    case "token":
    default:
      return token(type, value, opts.secret);
  }
}

export interface ScanStats {
  [type: string]: number;
}

/** Find and mask PII embedded in a free-text string. */
export function scrubText(text: string, opts: PiiOptions, stats?: ScanStats): string {
  let out = text;
  for (const rule of VALUE_RULES) {
    out = out.replace(rule.re, (m) => {
      if (rule.validate && !rule.validate(m)) return m;
      if (stats) stats[rule.type] = (stats[rule.type] ?? 0) + 1;
      return maskValue(rule.type, m, opts);
    });
  }
  return out;
}

/** Convert a raw DB value into something JSON-safe and PII-free. */
export function sanitiseValue(
  value: unknown,
  columnType: PiiType | null,
  opts: PiiOptions,
  stats?: ScanStats,
  depth = 0,
): unknown {
  if (value === null || value === undefined) return value ?? null;

  if (columnType) {
    if (stats) stats[columnType] = (stats[columnType] ?? 0) + 1;
    const str = value instanceof Date ? value.toISOString().slice(0, 10) : stringify(value);
    return maskValue(columnType, str, opts);
  }

  if (typeof value === "bigint") return scanScalar(value.toString(), opts, stats);
  if (typeof value === "number") {
    if (Number.isInteger(value) && Math.abs(value) >= 1e9) {
      const s = String(value);
      const scrubbed = scanScalar(s, opts, stats);
      return scrubbed === s ? value : scrubbed;
    }
    return value;
  }
  if (typeof value === "boolean") return value;
  if (value instanceof Date) return isNaN(value.getTime()) ? null : value.toISOString();
  if (Buffer.isBuffer(value)) return `<binary ${value.length} bytes>`;
  if (typeof value === "string") return opts.scanValues ? scrubText(value, opts, stats) : value;

  if (depth > 8) return "[NESTED]";
  if (Array.isArray(value)) return value.map((v) => sanitiseValue(v, null, opts, stats, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const keyType = classifyColumn([k], undefined, opts);
      out[k] = sanitiseValue(v, keyType, opts, stats, depth + 1);
    }
    return out;
  }
  return opts.scanValues ? scrubText(String(value), opts, stats) : String(value);
}

function scanScalar(s: string, opts: PiiOptions, stats?: ScanStats): string {
  return opts.scanValues ? scrubText(s, opts, stats) : s;
}

function stringify(v: unknown): string {
  if (typeof v === "string") return v;
  if (Buffer.isBuffer(v)) return v.toString("hex");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}
