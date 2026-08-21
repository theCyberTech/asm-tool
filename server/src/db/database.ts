import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SCHEMA } from "./schema.ts";

export type SqliteDatabase = DatabaseSync;

export function openDatabase(databasePath: string): DatabaseSync {
  if (databasePath !== ":memory:") {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  }
  const db = new DatabaseSync(databasePath);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(SCHEMA);
  db.exec("DROP TABLE IF EXISTS emails");
  return db;
}

export function nowIso(date = new Date()): string {
  return date.toISOString();
}

export function asRecord(row: unknown): Record<string, unknown> {
  return { ...(row as Record<string, unknown>) };
}
