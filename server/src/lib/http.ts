export const USER_AGENT = "ASM-Tool/3.0";

export async function fetchText(
  url: string,
  init: RequestInit = {},
  fetchImpl: typeof fetch = fetch,
): Promise<{ status: number; body: string; headers: Headers }> {
  const response = await fetchImpl(url, {
    ...init,
    headers: {
      "User-Agent": USER_AGENT,
      Accept: "*/*",
      ...(init.headers ?? {}),
    },
    redirect: init.redirect ?? "follow",
    signal: init.signal,
  });
  const body = await response.text();
  return { status: response.status, body, headers: response.headers };
}

export async function fetchJSON<T>(url: string, fetchImpl: typeof fetch = fetch): Promise<T> {
  const { status, body } = await fetchText(url, { headers: { Accept: "application/json" } }, fetchImpl);
  if (status >= 400) {
    throw new Error(`GET ${url} failed: ${status}`);
  }
  return JSON.parse(body) as T;
}

export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}
