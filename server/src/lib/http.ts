export const USER_AGENT = "ASM-Tool/3.0";
export const DEFAULT_FETCH_TIMEOUT_MS = 10_000;

export type FetchTextInit = RequestInit & { timeoutMs?: number };

export async function fetchText(
  url: string,
  init: FetchTextInit = {},
  fetchImpl: typeof fetch = fetch,
): Promise<{ status: number; body: string; headers: Headers }> {
  const { timeoutMs = DEFAULT_FETCH_TIMEOUT_MS, signal: userSignal, ...rest } = init;
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const signal = userSignal ? AbortSignal.any([userSignal, timeoutSignal]) : timeoutSignal;
  const response = await fetchImpl(url, {
    ...rest,
    headers: {
      "User-Agent": USER_AGENT,
      Accept: "*/*",
      ...(rest.headers ?? {}),
    },
    redirect: rest.redirect ?? "follow",
    signal,
  });
  const body = await response.text();
  return { status: response.status, body, headers: response.headers };
}

export async function fetchTextRetry(
  url: string,
  init: FetchTextInit = {},
  fetchImpl: typeof fetch = fetch,
  attempts = 3,
): Promise<{ status: number; body: string; headers: Headers }> {
  let last = { status: 0, body: "", headers: new Headers() };
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    last = await fetchText(url, init, fetchImpl);
    if (last.status < 500 && last.status !== 429) {
      return last;
    }
    if (attempt < attempts - 1) {
      await new Promise((resolve) => setTimeout(resolve, 400 * (attempt + 1)));
    }
  }
  return last;
}

export async function fetchJSON<T>(url: string, fetchImpl: typeof fetch = fetch): Promise<T> {
  const { status, body } = await fetchTextRetry(url, { headers: { Accept: "application/json" } }, fetchImpl);
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
