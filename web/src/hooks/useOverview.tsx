import { createContext, useContext, type ReactNode } from "react";
import { fetchOverview } from "../api/client";
import type { OverviewResponse } from "../api/types";
import { useApi } from "./useApi";

type OverviewState = ReturnType<typeof useApi<OverviewResponse>>;

const OverviewContext = createContext<OverviewState | null>(null);

export function OverviewProvider({ children }: { children: ReactNode }) {
  const state = useApi(fetchOverview);
  return <OverviewContext.Provider value={state}>{children}</OverviewContext.Provider>;
}

export function useOverview(): OverviewState {
  const value = useContext(OverviewContext);
  if (!value) {
    throw new Error("useOverview must be used within OverviewProvider");
  }
  return value;
}
