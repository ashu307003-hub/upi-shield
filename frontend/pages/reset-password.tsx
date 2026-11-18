import Head from "next/head";
import Link from "next/link";
import { FormEvent, useState } from "react";
import { useRouter } from "next/router";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function ResetPassword() {
  const router = useRouter();
  const token = typeof router.query.token === "string" ? router.query.token : "";
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    if (!token || token.length < 32) {
      setError("This reset link is invalid or has expired. Request a new one.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Your passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API}/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(
          typeof payload.detail === "string"
            ? payload.detail
            : `Password reset failed (${response.status})`
        );
      }
      setCompleted(true);
      setPassword("");
      setConfirmPassword("");
    } catch (resetError) {
      setError(
        resetError instanceof Error
          ? resetError.message
          : "Could not reset your password."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Head>
        <title>Reset password · UPI Shield</title>
        <meta name="referrer" content="no-referrer" />
        <meta name="robots" content="noindex, nofollow" />
      </Head>
      <main className="verification-message">
        <section className="verification-card">
          <span className="brand-mark">U</span>
          <div className="login-card-kicker">ACCOUNT RECOVERY</div>
          <h1>Choose a new password</h1>
          {completed ? (
            <>
              <div className="verification-success" role="status">
                Your password has been updated. Existing sessions have been
                signed out.
              </div>
              <Link className="login-submit" href="/login">
                Go to sign in
              </Link>
            </>
          ) : !router.isReady ? (
            <p>Loading your reset link…</p>
          ) : !token ? (
            <>
              <p>This reset link is missing or invalid. Request a new link.</p>
              <Link className="verification-back" href="/login">
                Back to sign in
              </Link>
            </>
          ) : (
            <>
              <p>
                Choose a password with at least 12 characters. This reset link
                can only be used once.
              </p>
              <form className="login-form" onSubmit={submit}>
                <label htmlFor="new-password">New password</label>
                <div className="login-input-wrap">
                  <input
                    id="new-password"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={12}
                    maxLength={128}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                </div>
                <label htmlFor="confirm-new-password">Confirm new password</label>
                <div className="login-input-wrap">
                  <input
                    id="confirm-new-password"
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={12}
                    maxLength={128}
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                  />
                </div>
                {error && (
                  <div className="login-error" role="alert">
                    {error}
                  </div>
                )}
                <button
                  className="login-submit"
                  type="submit"
                  disabled={loading}
                >
                  {loading ? "Updating…" : "Update password"}
                  {!loading && <span aria-hidden="true">→</span>}
                </button>
              </form>
            </>
          )}
        </section>
      </main>
    </>
  );
}
