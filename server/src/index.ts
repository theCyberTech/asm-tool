import path from "node:path";
import { serve } from "@hono/node-server";
import { loadConfig } from "./config.ts";
import { openDatabase } from "./db/database.ts";
import { Store } from "./db/store.ts";
import { createApp } from "./app.ts";
import { ALLOWED_ROOT_DOMAIN } from "./target.ts";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const config = loadConfig(process.env, repoRoot);
const db = openDatabase(config.databasePath);
const store = new Store(db);
store.ensureDomain(ALLOWED_ROOT_DOMAIN);

const app = createApp(store, config);

serve({ fetch: app.fetch, hostname: config.host, port: config.port }, (info) => {
  console.log(`ASM web app listening on http://${info.address}:${info.port}`);
  console.log(`Scan scope: ${ALLOWED_ROOT_DOMAIN}`);
  console.log(`Database: ${config.databasePath}`);
});
