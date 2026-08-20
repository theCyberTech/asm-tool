import { fetchText } from "../lib/http.ts";

export type TechnologyResult = {
  host: string;
  statusCode: number;
  title: string;
  server: string;
  technologies: string;
  headers: Record<string, string>;
  body: string;
};

function detectTech(headers: Headers, body: string): string[] {
  const techs: string[] = [];
  const server = headers.get("server") ?? "";
  const powered = headers.get("x-powered-by") ?? "";
  if (server) techs.push(server.split(" ")[0] ?? server);
  if (powered) techs.push(powered);
  if (/cloudflare/i.test(headers.get("cf-ray") ?? "") || /cloudflare/i.test(server)) techs.push("Cloudflare");
  if (/wp-content|wordpress/i.test(body)) techs.push("WordPress");
  if (/__NEXT_DATA__|\/_next\//.test(body)) techs.push("Next.js");
  if (/react/i.test(body)) techs.push("React");
  if (/ngrok|nginx/i.test(server)) techs.push("nginx");
  return [...new Set(techs.filter(Boolean))];
}

export async function fingerprintHost(host: string, fetchImpl: typeof fetch = fetch): Promise<TechnologyResult> {
  const url = host.includes("://") ? host : `https://${host}`;
  try {
    const { status, body, headers } = await fetchText(url, {}, fetchImpl);
    const title = body.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.trim() ?? "";
    return {
      host,
      statusCode: status,
      title,
      server: headers.get("server") ?? "",
      technologies: detectTech(headers, body).join(", "),
      headers: Object.fromEntries(headers.entries()),
      body,
    };
  } catch {
    const httpUrl = `http://${host}`;
    const { status, body, headers } = await fetchText(httpUrl, {}, fetchImpl);
    const title = body.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.trim() ?? "";
    return {
      host,
      statusCode: status,
      title,
      server: headers.get("server") ?? "",
      technologies: detectTech(headers, body).join(", "),
      headers: Object.fromEntries(headers.entries()),
      body,
    };
  }
}
