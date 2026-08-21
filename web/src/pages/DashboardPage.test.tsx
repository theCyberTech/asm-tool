import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";

const overview = {
  status: "ok",
  stats: {
    domains: 1,
    subdomains: 2,
    ports: 3,
    certificates: 0,
    urls: 0,
    apis: 0,
    cloud_buckets: 0,
    takeovers: 0,
  },
  findings: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
  domains: [
    {
      id: 1,
      domain: "example.com",
      added_at: "2026-01-01T00:00:00Z",
      last_scanned: "2026-01-02T00:00:00Z",
      subdomain_count: 2,
      port_count: 3,
      critical_count: 1,
      high_count: 0,
    },
  ],
  change_events: [],
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("dashboard pages", () => {
  it("renders overview stats and domain links", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => overview,
        text: async () => JSON.stringify(overview),
      }),
    );

    render(
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("heading", { name: "Attack Surface Overview" })).toBeInTheDocument();
    expect(screen.getByText("CrewAI - ASM")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "View domains" })).toHaveAttribute("href", "/domains");
    expect(screen.getByRole("link", { name: "example.com" })).toHaveAttribute("href", "/domains/example.com");
    expect(screen.getByText("1 Critical")).toBeInTheDocument();
  });

  it("renders the domains inventory table", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo): Promise<{
        ok: boolean;
        json: () => Promise<unknown>;
        text: () => Promise<string>;
      }> => {
        const url = String(input);
        if (url.startsWith("/api/domains")) {
          return {
            ok: true,
            json: async () => ({ status: "ok", count: 1, domains: overview.domains }),
            text: async () => "",
          };
        }
        return {
          ok: true,
          json: async () => overview,
          text: async () => "",
        };
      }),
    );

    render(
      <MemoryRouter initialEntries={["/domains"]}>
        <App />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("heading", { name: "All Domains" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Domains", level: 1 })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "example.com" })).toHaveAttribute("href", "/domains/example.com");
  });
});
