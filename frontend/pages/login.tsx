import Head from "next/head";
import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/router";
import { useAuth } from "./_app";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type AuthResponse = {
  user: {
    id: number;
    email: string;
    full_name: string;
    is_admin: boolean;
  };
};

export default function Login() {
  const router = useRouter();
  const { setUser, serviceError } = useAuth();
  const [isRegistering, setIsRegistering] = useState(false);
  const [verificationPending, setVerificationPending] = useState(false);
  const [verificationComplete, setVerificationComplete] = useState(false);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [fullName, setFullName] = useState("");
  const [mobileNumber, setMobileNumber] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [resendAvailable, setResendAvailable] = useState(false);

  useEffect(() => {
    if (!router.isReady || typeof router.query.token !== "string") return;
    let active = true;
    setVerificationLoading(true);
    fetch(`${API}/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: router.query.token }),
    })
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(
            typeof payload.detail === "string"
              ? payload.detail
              : `Email confirmation failed (${response.status})`
          );
        }
        return payload;
      })
      .then(() => {
        if (!active) return;
        setVerificationComplete(true);
        setVerificationPending(false);
        setError("");
        setIsRegistering(false);
        void router.replace("/login");
      })
      .catch((verificationError: unknown) => {
        if (!active) return;
        setError(
          verificationError instanceof Error
            ? verificationError.message
            : "Email confirmation failed"
        );
      })
      .finally(() => {
        if (active) setVerificationLoading(false);
      });

    return () => {
      active = false;
    };
  }, [router.isReady, router.query.token]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");

    if (isRegistering && password !== confirmPassword) {
      setError("Your passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(
        `${API}/auth/${isRegistering ? "register" : "login"}`,
        {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(
            isRegistering
              ? {
                  full_name: fullName,
                  mobile_number: mobileNumber,
                  email,
                  password,
                }
              : { email, password }
          ),
        }
      );
      const payload = await response.json();
      if (!response.ok) {
        if (
          isRegistering &&
          response.status === 503 &&
          typeof payload.detail === "string" &&
          payload.detail.includes("account was created")
        ) {
          setVerificationPending(true);
          setResendAvailable(true);
          setError(payload.detail);
          return;
        }
        if (isRegistering && response.status === 409) {
          setResendAvailable(true);
          throw new Error(
            "That email already has an account. If it is not verified yet, resend its confirmation email."
          );
        }
        throw new Error(
          typeof payload.detail === "string"
            ? payload.detail
            : `Could not ${isRegistering ? "create account" : "sign in"} (${response.status})`
        );
      }

      const result = payload as AuthResponse;
      if (isRegistering) {
        setVerificationPending(true);
        setResendAvailable(false);
        setError("");
        return;
      }
      setUser(result.user);
      const requestedPath = router.query.next;
      const next =
        typeof requestedPath === "string" &&
        requestedPath.startsWith("/") &&
        !requestedPath.startsWith("//")
          ? requestedPath
          : "/";
      await router.replace(next);
    } catch (submitError) {
      setError(
        submitError instanceof Error
          ? submitError.message
          : "The request could not be completed."
      );
    } finally {
      setLoading(false);
    }
  }

  async function resendConfirmation() {
    setError("");
    setLoading(true);
    try {
      const response = await fetch(`${API}/auth/resend-verification`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail ?? `Request failed (${response.status})`);
      }
      setError(payload.message ?? "Check your email for a confirmation link.");
      setVerificationPending(true);
      setResendAvailable(false);
    } catch (resendError) {
      setError(
        resendError instanceof Error
          ? resendError.message
          : "Could not resend the confirmation email"
      );
    } finally {
      setLoading(false);
    }
  }

  if (verificationLoading) {
    return (
      <main className="verification-message">
        <div className="verification-card">
          <span className="brand-mark">U</span>
          <h1>Confirming your email…</h1>
          <p>We’re activating your analyst account.</p>
        </div>
      </main>
    );
  }

  if (verificationPending) {
    return (
      <>
        <Head>
          <title>Check your email · UPI Shield</title>
        </Head>
        <main className="verification-message">
          <div className="verification-card">
            <span className="verification-icon" aria-hidden="true">✉</span>
            <div className="login-card-kicker">ONE LAST STEP</div>
            <h1>Check your inbox</h1>
            <p>
              We sent a confirmation link to <strong>{email}</strong>. Confirm
              your address before signing in.
            </p>
            {error && <div className="login-error" role="alert">{error}</div>}
            <button
              className="login-submit"
              type="button"
              disabled={loading}
              onClick={resendConfirmation}
            >
              {loading ? "Sending…" : "Resend confirmation email"}
            </button>
            <button
              className="verification-back"
              type="button"
              onClick={() => {
                setVerificationPending(false);
                setIsRegistering(false);
                setError("");
              }}
            >
              Back to sign in
            </button>
          </div>
        </main>
      </>
    );
  }

  return (
    <>
      <Head>
        <title>{isRegistering ? "Create account" : "Sign in"} · UPI Shield</title>
        <meta
          name="description"
          content="Sign in to the UPI Shield analyst workspace."
        />
      </Head>
      <main className="login-page">
        <section className="login-showcase" aria-label="UPI Shield overview">
          <Link href="/" className="login-brand">
            <span className="brand-mark">U</span>
            <span>
              UPI <strong>Shield</strong>
            </span>
          </Link>

          <div className="showcase-copy">
            <div className="showcase-eyebrow">
              <span className="showcase-pulse" />
              ANALYST SECURITY WORKSPACE
            </div>
            <h1>
              See the signal.
              <br />
              <span>Protect every payment.</span>
            </h1>
            <p>
              Investigate suspicious payment experiences with clear evidence,
              connected infrastructure, and explainable risk signals.
            </p>
          </div>

          <div className="showcase-visual" aria-hidden="true">
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />
            <div className="orbit orbit-three" />
            <div className="orbit-center">
              <span className="orbit-shield">
                <svg viewBox="0 0 48 48" fill="none">
                  <path
                    d="M24 5.5 39 11v11.5c0 9.1-6.3 16.6-15 20-8.7-3.4-15-10.9-15-20V11l15-5.5Z"
                    stroke="currentColor"
                    strokeWidth="2"
                  />
                  <path
                    d="m17 23 4.5 4.5L31.5 18"
                    stroke="currentColor"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </span>
              <span className="orbit-label">THREAT INTELLIGENCE</span>
            </div>
            <span className="orbit-node orbit-node-a">UPI</span>
            <span className="orbit-node orbit-node-b">DNS</span>
            <span className="orbit-node orbit-node-c">WEB</span>
            <span className="orbit-node orbit-node-d">TLS</span>
            <div className="signal-card">
              <span className="signal-card-icon">↗</span>
              <span>
                <strong>Risk signals</strong>
                <small>Connected. Explained.</small>
              </span>
              <span className="signal-card-status" />
            </div>
          </div>

          <div className="showcase-footer">
            <span>DEFENSIVE ANALYSIS · AUTHORIZED USE ONLY</span>
            <span>UPI SHIELD <i /> 01.0</span>
          </div>
        </section>

        <section className="login-panel">
          <div className="login-panel-top">
            <span className="login-mobile-brand">
              <span className="brand-mark">U</span>
              UPI <strong>Shield</strong>
            </span>
            <span className="secure-label">
              <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <rect
                  x="3"
                  y="7"
                  width="10"
                  height="7"
                  rx="1.5"
                  stroke="currentColor"
                  strokeWidth="1.4"
                />
                <path
                  d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"
                  stroke="currentColor"
                  strokeWidth="1.4"
                />
              </svg>
              SECURE WORKSPACE
            </span>
          </div>

          <div className="login-card">
            {verificationComplete && (
              <div className="verification-success" role="status">
                Email confirmed. You can now sign in.
              </div>
            )}
            <div className="login-card-kicker">
              {isRegistering ? "GET STARTED" : "WELCOME BACK"}
            </div>
            <h2>{isRegistering ? "Create your account" : "Sign in to Shield"}</h2>
            <p className="login-intro">
              {isRegistering
                ? "Set up your analyst access to start investigating."
                : "Your intelligence workspace is ready when you are."}
            </p>

            <form className="login-form" onSubmit={submit}>
              {isRegistering && (
                <>
                  <label htmlFor="analyst-name">Full name</label>
                  <div className="login-input-wrap">
                    <input
                      id="analyst-name"
                      type="text"
                      autoComplete="name"
                      required
                      minLength={2}
                      maxLength={120}
                      placeholder="Your name"
                      value={fullName}
                      onChange={(event) => setFullName(event.target.value)}
                    />
                  </div>

                  <label htmlFor="analyst-mobile">Mobile number</label>
                  <div className="login-input-wrap">
                    <input
                      id="analyst-mobile"
                      type="tel"
                      autoComplete="tel"
                      inputMode="tel"
                      required
                      minLength={8}
                      maxLength={20}
                      placeholder="+91 98765 43210"
                      value={mobileNumber}
                      onChange={(event) => setMobileNumber(event.target.value)}
                    />
                  </div>
                  <p className="password-hint">
                    Include your country code, for example +91.
                  </p>
                </>
              )}
              <label htmlFor="analyst-email">Work email</label>
              <div className="login-input-wrap">
                <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
                  <rect
                    x="2.5"
                    y="4"
                    width="15"
                    height="12"
                    rx="2"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="m3.5 5 6.5 5 6.5-5"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinejoin="round"
                  />
                </svg>
                <input
                  id="analyst-email"
                  type="email"
                  autoComplete="email"
                  required
                  maxLength={254}
                  placeholder="you@organization.com"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                />
              </div>

              <div className="login-password-heading">
                <label htmlFor="analyst-password">Password</label>
                {!isRegistering && (
                  <span className="password-note">MIN. 12 CHARACTERS</span>
                )}
              </div>
              <div className="login-input-wrap">
                <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
                  <rect
                    x="3.5"
                    y="8.5"
                    width="13"
                    height="9"
                    rx="2"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M6.5 8.5V6a3.5 3.5 0 1 1 7 0v2.5"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                </svg>
                <input
                  id="analyst-password"
                  type={showPassword ? "text" : "password"}
                  autoComplete={isRegistering ? "new-password" : "current-password"}
                  required
                  minLength={12}
                  maxLength={128}
                  placeholder="Enter your password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
                <button
                  className="password-toggle"
                  type="button"
                  onClick={() => setShowPassword((visible) => !visible)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? "HIDE" : "SHOW"}
                </button>
              </div>

              {isRegistering && (
                <>
                  <label htmlFor="confirm-password">Confirm password</label>
                  <div className="login-input-wrap">
                    <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
                      <rect
                        x="3.5"
                        y="8.5"
                        width="13"
                        height="9"
                        rx="2"
                        stroke="currentColor"
                        strokeWidth="1.5"
                      />
                      <path
                        d="M6.5 8.5V6a3.5 3.5 0 1 1 7 0v2.5"
                        stroke="currentColor"
                        strokeWidth="1.5"
                      />
                    </svg>
                    <input
                      id="confirm-password"
                      type={showPassword ? "text" : "password"}
                      autoComplete="new-password"
                      required
                      minLength={12}
                      maxLength={128}
                      placeholder="Re-enter your password"
                      value={confirmPassword}
                      onChange={(event) =>
                        setConfirmPassword(event.target.value)
                      }
                    />
                  </div>
                  <p className="password-hint">
                    Use at least 12 characters for a stronger password.
                  </p>
                </>
              )}

              {serviceError && (
                <div className="login-error" role="status">
                  <span aria-hidden="true">!</span>
                  Sign-in service is unavailable. Start the backend and
                  database, then retry. {serviceError}
                </div>
              )}

              {error && (
                <>
                  <div className="login-error" role="alert">
                    <span aria-hidden="true">!</span>
                    {error}
                  </div>
                  {resendAvailable && (
                    <button
                      className="verification-back"
                      type="button"
                      disabled={loading}
                      onClick={resendConfirmation}
                    >
                      Resend confirmation email
                    </button>
                  )}
                </>
              )}

              <button
                className="login-submit"
                type="submit"
                disabled={loading}
              >
                {loading
                  ? isRegistering
                    ? "Creating account…"
                    : "Signing in…"
                  : isRegistering
                    ? "Create analyst account"
                    : "Sign in to workspace"}
                {!loading && <span aria-hidden="true">→</span>}
              </button>
            </form>

            <div className="login-switch">
              {isRegistering
                ? "Already have analyst access?"
                : "New to the workspace?"}
              <button
                type="button"
                onClick={() => {
                  setError("");
                  setIsRegistering((registering) => !registering);
                }}
              >
                {isRegistering ? "Sign in" : "Create an account"}
              </button>
            </div>
          </div>

          <div className="login-legal">
            <span>© 2026 UPI Shield</span>
            <span>
              <span className="legal-dot" />
              Authorized analyst access
            </span>
          </div>
        </section>
      </main>
    </>
  );
}
