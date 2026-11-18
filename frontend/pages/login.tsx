import Head from "next/head";
import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/router";
import { Analyst, useAuth } from "./_app";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type AuthResponse = {
  user: Analyst;
};

function formatApiDetail(detail: unknown): string | null {
  if (typeof detail === "string") return detail;
  if (!Array.isArray(detail)) return null;

  const messages = detail.flatMap((item: unknown) => {
    if (typeof item !== "object" || item === null || !("msg" in item)) {
      return [];
    }
    const message = item.msg;
    if (typeof message !== "string") return [];
    const location =
      "loc" in item && Array.isArray(item.loc)
        ? item.loc
            .filter((part: unknown): part is string => typeof part === "string")
            .join(".")
        : "";
    return [location ? `${location}: ${message}` : message];
  });
  return messages.length > 0 ? messages.join("; ") : null;
}

export default function Login() {
  const router = useRouter();
  const { setUser, serviceError } = useAuth();
  const [isRegistering, setIsRegistering] = useState(false);
  const [isRequestingReset, setIsRequestingReset] = useState(false);
  const [resetRequestSent, setResetRequestSent] = useState(false);
  const [verificationPending, setVerificationPending] = useState(false);
  const [verificationComplete, setVerificationComplete] = useState(false);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [fullName, setFullName] = useState("");
  const [mobileNumber, setMobileNumber] = useState("");
  const [accountType, setAccountType] = useState<
    "" | "student" | "professional"
  >("");
  const [studentIdCard, setStudentIdCard] = useState<File | null>(null);
  const [profileDetails, setProfileDetails] = useState({
    academic_session: "",
    institution: "",
    department: "",
    course: "",
    study_year: "",
    employer: "",
    job_title: "",
    employment_type: "",
    employee_id: "",
  });
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

    if (!accountType) {
      setError("Select whether this is a student or professional account.");
      return;
    }
    if (isRegistering && password !== confirmPassword) {
      setError("Your passwords do not match.");
      return;
    }
    if (isRegistering && accountType === "student" && !studentIdCard) {
      setError("Upload your student ID card.");
      return;
    }
    if (
      isRegistering &&
      studentIdCard &&
      studentIdCard.size > 5 * 1024 * 1024
    ) {
      setError("Student ID cards must be 5 MB or smaller.");
      return;
    }

    setLoading(true);
    try {
      const options: RequestInit = {
        method: "POST",
        credentials: "include",
      };
      if (isRegistering) {
        const formData = new FormData();
        formData.append("full_name", fullName);
        formData.append("mobile_number", mobileNumber);
        formData.append("email", email);
        formData.append("password", password);
        formData.append("account_type", accountType);
        const fields: (keyof typeof profileDetails)[] =
          accountType === "student"
            ? [
                "academic_session",
                "institution",
                "department",
                "course",
                "study_year",
              ]
            : [
                "employer",
                "department",
                "job_title",
                "employment_type",
                "employee_id",
              ];
        fields.forEach((field) =>
          formData.append(field, profileDetails[field])
        );
        if (studentIdCard) formData.append("student_id_card", studentIdCard);
        options.body = formData;
      } else {
        options.headers = { "Content-Type": "application/json" };
        options.body = JSON.stringify({ account_type: accountType, email, password });
      }

      const response = await fetch(
        `${API}/auth/${isRegistering ? "register" : "login"}`,
        options
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
          formatApiDetail(payload.detail) ??
            `Could not ${isRegistering ? "create account" : "sign in"} (${response.status})`
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

  async function requestPasswordReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setResetRequestSent(false);
    setLoading(true);
    try {
      const response = await fetch(`${API}/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(
          response.status === 404
            ? "Password reset is not available on the configured API yet. Update the backend deployment and try again."
            : formatApiDetail(payload.detail) ??
                `Password reset request failed (${response.status})`
        );
      }
      setResetRequestSent(true);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Could not request a password reset."
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
          <p>We’re setting up your account.</p>
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
            <div className="login-card-kicker">ALMOST DONE</div>
            <h1>Confirm your email</h1>
            <p>
              We sent a link to <strong>{email}</strong>. Open it to confirm
              your email before signing in.
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
        <title>
          {isRegistering
            ? "Create account"
            : isRequestingReset
              ? "Forgot password"
              : "Sign in"}{" "}
          · UPI Shield
        </title>
        <meta
          name="description"
          content="Sign in to your UPI Shield account."
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
              A SAFER WAY TO CHECK WEBSITES
            </div>
            <h1>
              Check before you trust.
              <br />
              <span>Spot warning signs early.</span>
            </h1>
            <p>
              Check websites for warning signs, see what looks unusual, and
              review the reasons in plain language.
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
              <span className="orbit-label">WEBSITE CHECKS</span>
            </div>
            <span className="orbit-node orbit-node-a">UPI</span>
            <span className="orbit-node orbit-node-b">LINK</span>
            <span className="orbit-node orbit-node-c">WEB</span>
            <span className="orbit-node orbit-node-d">SAFE</span>
            <div className="signal-card">
              <span className="signal-card-icon">↗</span>
              <span>
                <strong>Website checks</strong>
                <small>Clear results. Simple reasons.</small>
              </span>
              <span className="signal-card-status" />
            </div>
          </div>

          <div className="showcase-footer">
            <span>            CHECK ONLY WEBSITES YOU HAVE PERMISSION TO TEST</span>
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
              SECURE ACCOUNT
            </span>
          </div>

          <div className="login-card">
            {verificationComplete && (
              <div className="verification-success" role="status">
                Email confirmed. You can now sign in.
              </div>
            )}
            <div className="login-card-kicker">
              {isRegistering
                ? "CREATE YOUR ACCOUNT"
                : isRequestingReset
                  ? "ACCOUNT RECOVERY"
                  : "WELCOME BACK"}
            </div>
            <h2>
              {isRegistering
                ? "Create your account"
                : isRequestingReset
                  ? "Reset your password"
                  : "Sign in"}
            </h2>
            <p className="login-intro">
              {isRegistering
                ? "Tell us whether you are a student or a working professional."
                : isRequestingReset
                  ? "Enter the email address on your account. If it exists, we’ll send a one-time reset link."
                  : "Choose the account type you used when you signed up."}
            </p>

            {isRequestingReset ? (
              <form className="login-form" onSubmit={requestPasswordReset}>
                <label htmlFor="reset-email">Email address</label>
                <div className="login-input-wrap">
                  <input
                    id="reset-email"
                    type="email"
                    autoComplete="email"
                    required
                    maxLength={254}
                    placeholder="you@organization.com"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                  />
                </div>
                {resetRequestSent && (
                  <div className="verification-success" role="status">
                    If an account exists for that email, a reset link will be
                    sent. Check your inbox and spam folder.
                  </div>
                )}
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
                  {loading ? "Sending…" : "Send reset link"}
                  {!loading && <span aria-hidden="true">→</span>}
                </button>
              </form>
            ) : (
            <form className="login-form" onSubmit={submit}>
              <label htmlFor="account-type">Who is this account for?</label>
              <select
                id="account-type"
                className="account-type-select"
                required
                value={accountType}
                onChange={(event) => {
                  setAccountType(event.target.value as typeof accountType);
                  setStudentIdCard(null);
                }}
              >
                <option value="" disabled>
                  Choose one
                </option>
                <option value="student">Student</option>
                <option value="professional">Working professional</option>
              </select>

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

                  {accountType === "student" && (
                    <>
                      <label htmlFor="institution">School, college, or university</label>
                      <div className="login-input-wrap">
                        <input
                          id="institution"
                          required
                          maxLength={160}
                          value={profileDetails.institution}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              institution: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <label htmlFor="academic-session">School year or session</label>
                      <div className="login-input-wrap">
                        <input
                          id="academic-session"
                          required
                          maxLength={40}
                          placeholder="e.g. 2026–2027"
                          value={profileDetails.academic_session}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              academic_session: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <label htmlFor="student-department">Department or field of study</label>
                      <div className="login-input-wrap">
                        <input
                          id="student-department"
                          required
                          maxLength={120}
                          value={profileDetails.department}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              department: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <label htmlFor="course">Course or program</label>
                      <div className="login-input-wrap">
                        <input
                          id="course"
                          required
                          maxLength={160}
                          value={profileDetails.course}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              course: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <label htmlFor="study-year">Current year of study</label>
                      <div className="login-input-wrap">
                        <input
                          id="study-year"
                          required
                          maxLength={40}
                          placeholder="e.g. 2nd year"
                          value={profileDetails.study_year}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              study_year: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <label htmlFor="student-id-card">Upload your student ID card</label>
                      <div className="login-input-wrap login-file-input-wrap">
                        <input
                          id="student-id-card"
                          type="file"
                          accept="image/png,image/jpeg,application/pdf"
                          required
                          onChange={(event) =>
                            setStudentIdCard(event.target.files?.[0] ?? null)
                          }
                        />
                      </div>
                      <p className="password-hint">
                        Use a PNG, JPEG, or PDF file up to 5 MB. Only you can
                        view this file after signing in.
                      </p>
                    </>
                  )}

                  {accountType === "professional" && (
                    <>
                      <label htmlFor="employer">Company or employer</label>
                      <div className="login-input-wrap">
                        <input
                          id="employer"
                          required
                          maxLength={160}
                          value={profileDetails.employer}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              employer: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <label htmlFor="professional-department">Department or team</label>
                      <div className="login-input-wrap">
                        <input
                          id="professional-department"
                          required
                          maxLength={120}
                          value={profileDetails.department}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              department: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <label htmlFor="job-title">Job title</label>
                      <div className="login-input-wrap">
                        <input
                          id="job-title"
                          required
                          maxLength={120}
                          value={profileDetails.job_title}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              job_title: event.target.value,
                            }))
                          }
                        />
                      </div>
                      <label htmlFor="employment-type">Work arrangement</label>
                      <select
                        id="employment-type"
                        className="account-type-select"
                        required
                        value={profileDetails.employment_type}
                        onChange={(event) =>
                          setProfileDetails((details) => ({
                            ...details,
                            employment_type: event.target.value,
                          }))
                        }
                      >
                        <option value="" disabled>
                          Choose one
                        </option>
                        <option>Full-time</option>
                        <option>Part-time</option>
                        <option>Contract</option>
                        <option>Internship</option>
                        <option>Self-employed</option>
                      </select>
                      <label htmlFor="employee-id">Employee or staff ID</label>
                      <div className="login-input-wrap">
                        <input
                          id="employee-id"
                          required
                          maxLength={80}
                          value={profileDetails.employee_id}
                          onChange={(event) =>
                            setProfileDetails((details) => ({
                              ...details,
                              employee_id: event.target.value,
                            }))
                          }
                        />
                      </div>
                    </>
                  )}
                </>
              )}
              <label htmlFor="analyst-email">Email address</label>
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
                  <span className="password-note">AT LEAST 12 CHARACTERS</span>
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
                    Use 12 or more characters to help keep your account safe.
                  </p>
                </>
              )}

              {serviceError && (
                <div className="login-error" role="status">
                  <span aria-hidden="true">!</span>
                  We can’t check your sign-in right now. Please try again in a
                  moment.
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
                    ? "Create account"
                    : "Sign in"}
                {!loading && <span aria-hidden="true">→</span>}
              </button>
            </form>
            )}

            <div className="login-switch">
              {isRequestingReset
                ? "Remembered your password?"
                : isRegistering
                  ? "Already have an account?"
                  : "New here?"}
              <button
                type="button"
                onClick={() => {
                  setError("");
                  if (isRequestingReset) {
                    setIsRequestingReset(false);
                    setResetRequestSent(false);
                    setIsRegistering(false);
                  } else {
                    setIsRegistering((registering) => !registering);
                  }
                }}
              >
                {isRequestingReset
                  ? "Back to sign in"
                  : isRegistering
                    ? "Sign in"
                    : "Create an account"}
              </button>
            </div>
            {!isRegistering && !isRequestingReset && (
              <div className="login-switch">
                <button
                  type="button"
                  onClick={() => {
                    setError("");
                    setResetRequestSent(false);
                    setIsRegistering(false);
                    setIsRequestingReset(true);
                  }}
                >
                  Forgot password?
                </button>
              </div>
            )}
          </div>

          <div className="login-legal">
            <span>© 2026 UPI Shield</span>
            <span>
              <span className="legal-dot" />
              Secure access to your account
            </span>
          </div>
        </section>
      </main>
    </>
  );
}
