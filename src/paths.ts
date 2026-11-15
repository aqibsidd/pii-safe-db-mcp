import { homedir } from "node:os";
import { join, resolve } from "node:path";

type Env = NodeJS.ProcessEnv;

/** Shared config directory used by both the MCP server and the CLI. */
export function configDir(env: Env = process.env): string {
  return env.PII_CONFIG_DIR ? resolve(env.PII_CONFIG_DIR) : join(homedir(), ".config", "pii-safe-db");
}

/** Policy file: PII_POLICY_FILE, or <configDir>/policy.json. */
export function policyPath(env: Env = process.env): string {
  return env.PII_POLICY_FILE ? resolve(env.PII_POLICY_FILE) : join(configDir(env), "policy.json");
}

/** Runtime state (protection on/off): PII_STATE_FILE, or <configDir>/state.json. */
export function statePath(env: Env = process.env): string {
  return env.PII_STATE_FILE ? resolve(env.PII_STATE_FILE) : join(configDir(env), "state.json");
}
