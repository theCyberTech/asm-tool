import type { ReactNode } from "react";
import { useEffect } from "react";
import { NavLink } from "react-router-dom";
import type { FindingCounts, Stats } from "../api/types";
import { useOverview } from "../hooks/useOverview";

type LayoutProps = {
  activePage: string;
  runningCount?: number;
  children: ReactNode;
};

export function Layout({ activePage, runningCount, children }: LayoutProps) {
  const { data } = useOverview();
  const stats = data?.stats;
  const findings = data?.findings;
  useEffect(() => {
    const titles: Record<string, string> = {
      dashboard: "Dashboard",
      domains: "Domains",
      operations: "Operations",
      subdomains: "Subdomains",
      ports: "Open Ports",
      certificates: "Certificates",
      urls: "URLs",
      apis: "APIs",
      cloud: "Cloud Storage",
      findings: "Findings",
      takeovers: "Takeovers",
    };
    document.title = `${titles[activePage] ?? "Dashboard"} - ASM`;
  }, [activePage]);
  return (
    <>
      <nav className="nav">
        <NavLink to="/" end className="nav-brand">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span>ASM Dashboard</span>
        </NavLink>
        <div className="nav-links">
          <NavLink to="/operations" className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
            Operations
          </NavLink>
          <a className="nav-link" href="/health">
            Health
          </a>
          <a className="nav-link" href="/api/stats">
            API
          </a>
        </div>
      </nav>
      <div className="layout">
        <Sidebar stats={stats} findings={findings} runningCount={runningCount} />
        <main className="main-content">{children}</main>
      </div>
    </>
  );
}

type NavItem = {
  to: string;
  page: string;
  label: string;
  badge?: number;
  icon: ReactNode;
};

function Sidebar({
  stats,
  findings,
  runningCount,
}: {
  stats?: Stats;
  findings?: FindingCounts;
  runningCount?: number;
}) {
  const overview: NavItem[] = [
    {
      to: "/",
      page: "dashboard",
      label: "Dashboard",
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="3" width="7" height="7" />
          <rect x="14" y="3" width="7" height="7" />
          <rect x="14" y="14" width="7" height="7" />
          <rect x="3" y="14" width="7" height="7" />
        </svg>
      ),
    },
    {
      to: "/operations",
      page: "operations",
      label: "Operations",
      badge: runningCount,
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="4 17 10 11 4 5" />
          <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
      ),
    },
  ];

  const discovery: NavItem[] = [
    { to: "/domains", page: "domains", label: "Domains", badge: stats?.domains, icon: globeIcon },
    { to: "/subdomains", page: "subdomains", label: "Subdomains", badge: stats?.subdomains, icon: codeIcon },
    { to: "/ports", page: "ports", label: "Ports", badge: stats?.ports, icon: serverIcon },
  ];

  const assets: NavItem[] = [
    { to: "/certificates", page: "certificates", label: "Certificates", badge: stats?.certificates, icon: lockIcon },
    { to: "/urls", page: "urls", label: "URLs", badge: stats?.urls, icon: linkIcon },
    { to: "/apis", page: "apis", label: "APIs", badge: stats?.apis, icon: fileIcon },
    { to: "/cloud", page: "cloud", label: "Cloud Storage", badge: stats?.cloud_buckets, icon: cloudIcon },
  ];

  const security: NavItem[] = [
    { to: "/findings", page: "findings", label: "Findings", badge: findings?.total, icon: alertIcon },
    { to: "/takeovers", page: "takeovers", label: "Takeovers", badge: stats?.takeovers, icon: starIcon },
  ];

  return (
    <aside className="sidebar">
      <SidebarSection title="Overview" items={overview} />
      <SidebarSection title="Discovery" items={discovery} />
      <SidebarSection title="Assets" items={assets} />
      <SidebarSection title="Security" items={security} />
    </aside>
  );
}

function SidebarSection({
  title,
  items,
}: {
  title: string;
  items: NavItem[];
}) {
  return (
    <div className="sidebar-section">
      <div className="sidebar-title">{title}</div>
      <ul className="sidebar-nav">
        {items.map((item) => (
          <li className="sidebar-item" key={item.to}>
            <NavLink
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => `sidebar-link${isActive ? " active" : ""}`}
            >
              {item.icon}
              {item.label}
              {item.badge ? <span className="sidebar-badge">{item.badge}</span> : null}
            </NavLink>
          </li>
        ))}
      </ul>
    </div>
  );
}

const globeIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10" />
    <line x1="2" y1="12" x2="22" y2="12" />
    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
  </svg>
);

const codeIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="16 18 22 12 16 6" />
    <polyline points="8 6 2 12 8 18" />
  </svg>
);

const serverIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="2" y="2" width="20" height="8" rx="2" />
    <rect x="2" y="14" width="20" height="8" rx="2" />
    <line x1="6" y1="6" x2="6.01" y2="6" />
    <line x1="6" y1="18" x2="6.01" y2="18" />
  </svg>
);

const lockIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="3" y="11" width="18" height="11" rx="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

const linkIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
  </svg>
);

const fileIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
  </svg>
);

const cloudIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />
  </svg>
);

const alertIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);

const starIcon = (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
  </svg>
);
