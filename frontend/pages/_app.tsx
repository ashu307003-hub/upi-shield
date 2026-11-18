import type { AppProps } from "next/app";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  createContext,
  useContext,
  useEffect,
  useState,
} from "react";
import "../styles/globals.css";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type Analyst = {
  id: number;
  email: string;
  full_name: string;
  is_admin: boolean;
  mobile_number: string;
  account_type: "student" | "professional";
  academic_session: string;
  institution: string;
  department: string;
  course: string;
  study_year: string;
  has_student_id_document: boolean;
  employer: string;
  job_title: string;
  employment_type: string;
  employee_id: string;
  is_verified: boolean;
  created_at: string | null;
};

type AuthContextValue = {
  user: Analyst | null;
  setUser: (user: Analyst | null) => void;
  serviceError: string;
  isAdmin: boolean;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth() {
  const auth = useContext(AuthContext);
  if (!auth) {
    throw new Error("useAuth must be used within the application");
  }
  return auth;
}

function LoadingScreen({ message }: { message: string }) {
  return (
    <div className="auth-loading">
      <span className="brand-mark">U</span>
      <span>{message}</span>
    </div>
  );
}

export default function App({ Component, pageProps }: AppProps) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [user, setUser] = useState<Analyst | null>(null);
  const [authStatus, setAuthStatus] = useState<
    "loading" | "authenticated" | "anonymous" | "error"
  >("loading");
  const [authError, setAuthError] = useState("");
  const [checkAttempt, setCheckAttempt] = useState(0);
  const router = useRouter();
  const isLoginPage = router.pathname === "/login";
  const isPasswordResetPage = router.pathname === "/reset-password";
  const isPublicAuthPage = isLoginPage || isPasswordResetPage;

  useEffect(() => {
    if (!router.isReady) return;

    const recordVisit = (path: string) => {
      const cleanPath = path.split("?")[0].split("#")[0];
      void fetch(`${API}/analytics/visit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: cleanPath }),
      }).catch((error: unknown) => {
        console.warn("Could not record aggregate page view", error);
      });
    };
    const handleRouteChange = (path: string) => recordVisit(path);
    recordVisit(router.asPath);
    router.events.on("routeChangeComplete", handleRouteChange);

    return () => {
      router.events.off("routeChangeComplete", handleRouteChange);
    };
  }, [router.isReady, router.events]);

  useEffect(() => {
    if (!router.isReady) return;

    let active = true;
    fetch(`${API}/auth/me`, { credentials: "include" })
      .then(async (response) => {
        if (response.status === 401) return null;
        if (!response.ok) {
          throw new Error(`Authentication service returned ${response.status}`);
        }
        const payload = await response.json();
        return payload.user as Analyst;
      })
      .then((analyst) => {
        if (!active) return;
        setUser(analyst);
        setAuthError("");
        setAuthStatus(analyst ? "authenticated" : "anonymous");
        if (!analyst && !isPublicAuthPage) {
          void router.replace({
            pathname: "/login",
            query: { next: router.asPath },
          });
        } else if (analyst && isLoginPage) {
          void router.replace("/");
        }
      })
      .catch((error: unknown) => {
        if (!active) return;
        setAuthError(
          error instanceof Error
            ? error.message
            : "Could not check your sign-in status"
        );
        setAuthStatus("error");
      });

    return () => {
      active = false;
    };
  }, [checkAttempt, isLoginPage, isPublicAuthPage, router]);

  function updateUser(nextUser: Analyst | null) {
    setUser(nextUser);
    setAuthStatus(nextUser ? "authenticated" : "anonymous");
    setAuthError("");
  }

  async function signOut() {
    try {
      const response = await fetch(`${API}/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      if (!response.ok) {
        throw new Error(`Sign out failed (${response.status})`);
      }
      setUser(null);
      setAuthStatus("anonymous");
      await router.replace("/login");
    } catch (error) {
      window.alert("Could not sign out. Please try again.");
    }
  }

  if (!router.isReady || authStatus === "loading") {
    return <LoadingScreen message="Checking your sign-in…" />;
  }

  if (authStatus === "error") {
    if (isPublicAuthPage) {
      return (
        <AuthContext.Provider
          value={{
            user,
            setUser: updateUser,
            serviceError: authError,
            isAdmin: Boolean(user?.is_admin),
          }}
        >
          <Component {...pageProps} />
        </AuthContext.Provider>
      );
    }
    return (
      <div className="auth-loading auth-loading-error">
        <div>
          <span className="brand-mark">U</span>
          <h1>Can’t sign you in right now</h1>
          <p>Refresh the page and try again. If this keeps happening, contact your administrator.</p>
          <button
            className="button primary"
            type="button"
            onClick={() => {
              setAuthStatus("loading");
              setCheckAttempt((attempt) => attempt + 1);
            }}
          >
            Try again
          </button>
        </div>
      </div>
    );
  }

  if (authStatus === "anonymous" || !user) {
    if (isPublicAuthPage) {
      return (
        <AuthContext.Provider
          value={{
            user,
            setUser: updateUser,
            serviceError: "",
            isAdmin: Boolean(user?.is_admin),
          }}
        >
          <Component {...pageProps} />
        </AuthContext.Provider>
      );
    }
    return <LoadingScreen message="Redirecting to sign in…" />;
  }

  if (isLoginPage) {
    return <LoadingScreen message="Opening your account…" />;
  }

  if (isPasswordResetPage) {
    return (
      <AuthContext.Provider
        value={{
          user,
          setUser: updateUser,
          serviceError: "",
          isAdmin: user.is_admin,
        }}
      >
        <Component {...pageProps} />
      </AuthContext.Provider>
    );
  }

  const initials = user.email
    .split("@")[0]
    .split(/[._-]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0].toUpperCase())
    .join("");

  return (
    <AuthContext.Provider
      value={{
        user,
        setUser: updateUser,
        serviceError: "",
        isAdmin: user.is_admin,
      }}
    >
      <div
        className={`app-shell ${sidebarOpen ? "" : "sidebar-collapsed"}`}
      >
        <aside className="sidebar" aria-label="Primary navigation">
          <button
            className="brand"
            type="button"
            aria-label={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
            aria-expanded={sidebarOpen}
            title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
            onClick={() => setSidebarOpen((open) => !open)}
          >
            <span className="brand-mark">U</span>
            <span>
              UPI <strong>Shield</strong>
            </span>
          </button>
          <button
            className="sidebar-toggle"
            type="button"
            aria-label={sidebarOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={sidebarOpen}
            onClick={() => setSidebarOpen((open) => !open)}
          >
            {sidebarOpen ? "‹" : "›"}
          </button>
          <div className="workspace-label">MAIN MENU</div>
          <nav className="nav-list">
            <Link
              href="/"
              className={`nav-item ${router.pathname === "/" ? "active" : ""}`}
            >
              <span>◉</span>
              <span>Website checks</span>
            </Link>
            <Link
              href="/graph"
              className={`nav-item ${router.pathname === "/graph" ? "active" : ""}`}
            >
              <span>⌘</span>
              <span>Website connections</span>
            </Link>
            <Link
              href="/profile"
              className={`nav-item ${router.pathname === "/profile" ? "active" : ""}`}
            >
              <span>◎</span>
              <span>My profile</span>
            </Link>
            {user.is_admin && (
              <Link
                href="/admin"
                className={`nav-item ${router.pathname === "/admin" ? "active" : ""}`}
              >
                <span>▦</span>
                <span>Admin tools</span>
              </Link>
            )}
          </nav>
          <div className="sidebar-bottom">
            <div className="system-status">
              <span className="status-dot" /> All systems ready
            </div>
            <div className="user-card">
              <div className="avatar">{initials || "A"}</div>
              <div className="user-identity">
                <strong>{user.full_name || user.email}</strong>
                <small>
                  {user.account_type === "student"
                    ? "Student account"
                    : "Working professional"}
                </small>
              </div>
            </div>
            <div className="account-actions">
              <button type="button" onClick={signOut}>
                Sign out
              </button>
              <button type="button" onClick={signOut}>
                Switch account
              </button>
            </div>
          </div>
        </aside>
        <main className="main-content">
          <Component {...pageProps} />
        </main>
      </div>
    </AuthContext.Provider>
  );
}
