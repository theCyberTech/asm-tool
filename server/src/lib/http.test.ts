import { describe, expect, it } from "vitest";
import { fetchText } from "./http.ts";

describe("http client", () => {
  it("aborts hung fetches instead of waiting forever", async () => {
    const fetchImpl: typeof fetch = async (_input, init) => {
      await new Promise<never>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        });
      });
      throw new Error("unreachable");
    };
    await expect(fetchText("https://crewai.com", { timeoutMs: 50 }, fetchImpl)).rejects.toThrow(/aborted|AbortError|timeout/i);
  });
});
