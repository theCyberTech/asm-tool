import { Navigate, Route, Routes } from "react-router-dom";
import { AssetListPage } from "./pages/AssetListPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DomainDetailPage } from "./pages/DomainDetailPage";
import { DomainsPage } from "./pages/DomainsPage";
import { OperationsPage } from "./pages/OperationsPage";

export function App() {
  return (
    <Routes>
      <Route path="/" element={<DashboardPage />} />
      <Route path="/domains" element={<DomainsPage />} />
      <Route path="/domains/:name" element={<DomainDetailPage />} />
      <Route path="/operations" element={<OperationsPage />} />
      <Route path="/emails" element={<Navigate to="/" replace />} />
      <Route path="/:kind" element={<AssetListPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
