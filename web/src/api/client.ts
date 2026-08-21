import type {
  AssetKind,
  AssetListResponse,
  AssetRowByKind,
  DomainAssetKind,
  DomainDetail,
  DomainListResponse,
  OperationsResponse,
  OverviewResponse,
  StartRunRequest,
} from "./types";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function readError(response: Response): Promise<string> {
  const text = await response.text();
  try {
    const parsed = JSON.parse(text) as { message?: string };
    if (parsed.message) {
      return parsed.message;
    }
  } catch {
    // keep raw text
  }
  return text || response.statusText;
}

async function getJSON<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    throw new ApiError(response.status, await readError(response));
  }
  return response.json() as Promise<T>;
}

export async function fetchOverview(): Promise<OverviewResponse> {
  return getJSON<OverviewResponse>("/api/overview");
}

export async function fetchDomains(params?: {
  q?: string;
  from?: string;
  to?: string;
}): Promise<DomainListResponse> {
  const query = new URLSearchParams();
  if (params?.q) {
    query.set("q", params.q);
  }
  if (params?.from) {
    query.set("from", params.from);
  }
  if (params?.to) {
    query.set("to", params.to);
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return getJSON<DomainListResponse>(`/api/domains${suffix}`);
}

export async function fetchDomain(name: string): Promise<DomainDetail> {
  return getJSON<DomainDetail>(`/api/domains/${encodeURIComponent(name)}`);
}

export async function fetchDomainAssets<K extends DomainAssetKind>(
  name: string,
  kind: K,
): Promise<AssetListResponse<AssetRowByKind[K]>> {
  return getJSON<AssetListResponse<AssetRowByKind[K]>>(
    `/api/domains/${encodeURIComponent(name)}/assets/${kind}`,
  );
}

export async function fetchAssets<K extends AssetKind>(
  kind: K,
): Promise<AssetListResponse<AssetRowByKind[K]>> {
  return getJSON<AssetListResponse<AssetRowByKind[K]>>(`/api/assets/${kind}`);
}

export async function fetchOperations(token?: string): Promise<OperationsResponse> {
  const headers: HeadersInit = { Accept: "application/json" };
  if (token) {
    headers["X-ASM-Token"] = token;
  }
  const response = await fetch("/api/operations", { headers });
  if (!response.ok) {
    throw new ApiError(response.status, await readError(response));
  }
  return response.json() as Promise<OperationsResponse>;
}

export async function startRun(
  body: StartRunRequest,
  token?: string,
): Promise<OperationsResponse["runs"][number]> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  if (token) {
    headers["X-ASM-Token"] = token;
  }
  const response = await fetch("/api/runs/start", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new ApiError(response.status, await readError(response));
  }
  const payload = (await response.json()) as {
    status: string;
    run: OperationsResponse["runs"][number];
  };
  return payload.run;
}
