import path from "node:path";

export type AppConfig = {
  host: string;
  port: number;
  databasePath: string;
  webDistDir: string;
  token: string;
  ports: number[];
};

function parsePorts(spec: string): number[] {
  const out = new Set<number>();
  for (const part of spec.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const range = trimmed.split("-");
    if (range.length === 2) {
      const start = Number(range[0]);
      const end = Number(range[1]);
      if (Number.isInteger(start) && Number.isInteger(end) && start > 0 && end <= 65535 && start <= end) {
        for (let port = start; port <= end; port += 1) {
          out.add(port);
        }
      }
      continue;
    }
    const port = Number(trimmed);
    if (Number.isInteger(port) && port > 0 && port <= 65535) {
      out.add(port);
    }
  }
  return [...out];
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): AppConfig {
  const defaultPorts = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443";
  return {
    host: env.ASM_HOST || "127.0.0.1",
    port: Number(env.ASM_PORT || 8080),
    databasePath: env.ASM_DATABASE_PATH || path.resolve(cwd, "data/asm.db"),
    webDistDir: env.ASM_WEB_DIST || path.resolve(cwd, "web/dist"),
    token: env.ASM_DASHBOARD_TOKEN || env.ASM_TOKEN || "",
    ports: parsePorts(env.ASM_PORTS || defaultPorts),
  };
}

export { parsePorts };
