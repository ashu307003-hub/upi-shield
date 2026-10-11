import type { AppProps } from "next/app";
import Link from "next/link";
import { useRouter } from "next/router";
import { useState } from "react";
import "../styles/globals.css";

export default function App({ Component, pageProps }: AppProps) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const router = useRouter();
  return (
    <div className={`app-shell ${sidebarOpen ? "" : "sidebar-collapsed"}`}>
      <aside className="sidebar" aria-label="Primary navigation">
        <Link href="/" className="brand">
          <span className="brand-mark">U</span>
          <span>UPI <strong>Shield</strong></span>
        </Link>
        <button
          className="sidebar-toggle"
          type="button"
          aria-label={sidebarOpen ? "Close navigation" : "Open navigation"}
          aria-expanded={sidebarOpen}
          onClick={() => setSidebarOpen((open) => !open)}
        >
          {sidebarOpen ? "‹" : "›"}
        </button>
        <div className="workspace-label">SECURITY OPERATIONS</div>
        <nav className="nav-list">
          <Link href="/" className={`nav-item ${router.pathname === "/" ? "active" : ""}`}><span>◉</span><span>Triage queue</span></Link>
          <Link href="/graph" className={`nav-item ${router.pathname === "/graph" ? "active" : ""}`}><span>⌘</span><span>Campaign graph</span></Link>
        </nav>
        <div className="sidebar-bottom">
          <div className="system-status"><span className="status-dot" /> Systems operational</div>
          <div className="user-card"><div className="avatar">RA</div><div><strong>Research analyst</strong><small>Workspace admin</small></div><span>•••</span></div>
        </div>
      </aside>
      <main className="main-content"><Component {...pageProps} /></main>
    </div>
  );
}
