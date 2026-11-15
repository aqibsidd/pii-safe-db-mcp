import { mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Protection on/off.
 *
 * Turning protection OFF makes the server behave like a plain read-only
 * database MCP (no masking, no policy). Because that is exactly what an attacker
 * (or a prompt-injected model) would want, it is deliberately hard:
 *
 *  - it is NOT an MCP tool — the model cannot switch it;
 *  - the server ignores it unless started with PII_ALLOW_UNPROTECTED_MODE=true;
 *  - a state-file "off" always expires (default 30 min, hard max 8 h);
 *  - every change is audited.
 */

export const MAX_UNPROTECTED_MS = 8 * 60 * 60 * 1000;
export const DEFAULT_UNPROTECTED_MS = 30 * 60 * 1000;

export interface ProtectionState {
  mode: "on" | "off";
  /** ISO time when an "off" request expires. */
  until?: string;
  changed_at: string;
  changed_by?: string;
}

export interface EffectiveMode {
  protected: boolean;
  source: "default" | "env" | "state";
  until?: string;
  /** Explanation when an "off" request was ignored. */
  note?: string;
}

export function readState(path: string): ProtectionState | null {
  try {
    const s = JSON.parse(readFileSync(path, "utf8"));
    if (s && (s.mode === "on" || s.mode === "off")) return s as ProtectionState;
  } catch {
    /* missing or invalid → no state */
  }
  return null;
}

export function writeJsonAtomic(path: string, data: unknown, mode = 0o644): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 2) + "\n", { mode });
  renameSync(tmp, path);
}

export function writeState(path: string, state: ProtectionState): void {
  writeJsonAtomic(path, state, 0o600);
}

/** Parse "30m", "2h", "90" (minutes). Returns milliseconds. */
export function parseDuration(s: string | undefined): number {
  if (!s) return DEFAULT_UNPROTECTED_MS;
  const m = s.trim().match(/^(\d+(?:\.\d+)?)\s*(m|min|mins|minutes?|h|hr|hrs|hours?)?$/i);
  if (!m) throw new Error(`Invalid duration "${s}". Use e.g. 30m or 2h.`);
  const n = Number(m[1]);
  const ms = /^h/i.test(m[2] ?? "") ? n * 3600_000 : n * 60_000;
  if (ms <= 0) throw new Error("Duration must be positive.");
  if (ms > MAX_UNPROTECTED_MS) throw new Error("Maximum unprotected duration is 8h.");
  return ms;
}

export class ProtectionController {
  private key = "";
  private cached: ProtectionState | null = null;

  constructor(
    private readonly opts: {
      envMode?: string;
      allowUnprotected: boolean;
      statePath: string;
    },
  ) {}

  get allowUnprotected(): boolean {
    return this.opts.allowUnprotected;
  }

  get statePath(): string {
    return this.opts.statePath;
  }

  private state(): ProtectionState | null {
    let key = "missing";
    try {
      const st = statSync(this.opts.statePath);
      key = `${st.mtimeMs}:${st.size}`;
    } catch {
      /* missing */
    }
    if (key !== this.key) {
      this.cached = key === "missing" ? null : readState(this.opts.statePath);
      this.key = key;
    }
    return this.cached;
  }

  current(now = Date.now()): EffectiveMode {
    const refused = "PII_ALLOW_UNPROTECTED_MODE is not enabled for this server, so protection stays ON.";

    if ((this.opts.envMode ?? "on").toLowerCase() === "off") {
      return this.opts.allowUnprotected
        ? { protected: false, source: "env" }
        : { protected: true, source: "default", note: `PII_PROTECTION=off ignored: ${refused}` };
    }

    const s = this.state();
    if (s?.mode === "off" && s.until) {
      const until = Date.parse(s.until);
      const changed = Date.parse(s.changed_at);
      const valid =
        Number.isFinite(until) && Number.isFinite(changed) && until > now && until - changed <= MAX_UNPROTECTED_MS + 1000;
      if (valid) {
        return this.opts.allowUnprotected
          ? { protected: false, source: "state", until: new Date(until).toISOString() }
          : { protected: true, source: "default", note: `Protection-off request ignored: ${refused}` };
      }
    }
    return { protected: true, source: s ? "state" : "default" };
  }
}
