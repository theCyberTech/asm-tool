import { fetchText } from "../lib/http.ts";

const PATHS = [
  { path: "/swagger.json", type: "swagger", title: "Swagger" },
  { path: "/openapi.json", type: "openapi", title: "OpenAPI" },
  { path: "/api/docs", type: "docs", title: "API docs" },
  { path: "/graphql", type: "graphql", title: "GraphQL" },
  { path: "/v1/", type: "rest", title: "REST v1" },
  { path: "/api/", type: "rest", title: "API root" },
];

export type ApiRecord = {
  url: string;
  type: string;
  title: string;
  version: string;
};

export async function discoverApis(host: string, fetchImpl: typeof fetch = fetch): Promise<ApiRecord[]> {
  const found: ApiRecord[] = [];
  for (const spec of PATHS) {
    for (const scheme of ["https", "http"]) {
      const url = `${scheme}://${host}${spec.path}`;
      try {
        const { status, body } = await fetchText(url, { redirect: "follow" }, fetchImpl);
        if (status >= 400) {
          continue;
        }
        const looksUseful =
          spec.type === "graphql"
            ? /graphql|__schema/i.test(body) || status === 400
            : status < 400 && body.length > 0;
        if (!looksUseful) {
          continue;
        }
        found.push({
          url,
          type: spec.type,
          title: spec.title,
          version: "",
        });
        break;
      } catch {
        // try next scheme
      }
    }
  }
  return found;
}
