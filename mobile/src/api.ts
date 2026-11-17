import * as SecureStore from "expo-secure-store";

const API_URL_KEY = "upi-shield-api-url";
const SESSION_KEY = "upi-shield-session-token";

export type Analyst = {
  id: number;
  email: string;
  full_name: string;
  account_type: "student" | "professional";
};

export type RiskReport = {
  url?: string;
  input_type?: string;
  payee_vpa?: string;
  payee_name?: string | null;
  amount?: string | null;
  currency?: string | null;
  risk_score?: number | null;
  risk_level?: string;
  known_threat?: boolean;
  signals?: string[];
  scope?: string;
  checked_at?: string;
};

export type RiskResult = {
  status: "blocked" | "unknown" | "unavailable";
  verdict: string | null;
  score: number | null;
  score_label: string | null;
  risk_level?: string;
  reason: string | null;
  report: RiskReport;
};

export type Dashboard = {
  user: Analyst;
  totals: {
    detections: number;
    phishing: number;
    suspicious: number;
  };
  recent: Array<{
    id: number;
    url: string;
    brand: string | null;
    score: number;
    verdict: string;
    created_at: string | null;
  }>;
};

export function normalizeApiUrl(value: string): string {
  const parsed = new URL(value.trim());
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Use an http:// or https:// API address.");
  }
  if (
    parsed.protocol !== "https:" &&
    !["localhost", "127.0.0.1"].includes(parsed.hostname)
  ) {
    throw new Error("Use HTTPS for any API server outside this device.");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("Enter only the API base address, without credentials or a path.");
  }
  return parsed.href.replace(/\/+$/, "");
}

export async function readSavedApiUrl(): Promise<string> {
  return (await SecureStore.getItemAsync(API_URL_KEY)) ?? "";
}

export async function saveApiUrl(value: string): Promise<string> {
  const normalized = normalizeApiUrl(value);
  await SecureStore.setItemAsync(API_URL_KEY, normalized);
  return normalized;
}

export async function readSessionToken(): Promise<string | null> {
  return SecureStore.getItemAsync(SESSION_KEY);
}

async function request<T>(
  apiUrl: string,
  path: string,
  token?: string | null,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(`${apiUrl}${path}`, {
    ...init,
    headers,
  });
  const text = await response.text();
  let payload: Record<string, unknown> = {};
  if (text) {
    try {
      payload = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error(`The API returned an invalid response (${response.status}).`);
    }
  }
  if (!response.ok) {
    const detail = payload.detail;
    const message =
      typeof detail === "string"
        ? detail
        : response.status === 401
          ? "Your sign-in has expired. Sign in again."
          : `Request failed (${response.status}).`;
    throw new Error(message);
  }
  return payload as T;
}

export async function login(
  apiUrl: string,
  email: string,
  password: string,
  accountType: Analyst["account_type"],
): Promise<{ user: Analyst; sessionToken: string }> {
  const response = await request<{
    user: Analyst;
    session_token: string;
  }>(apiUrl, "/mobile/auth/login", null, {
    method: "POST",
    body: JSON.stringify({
      email: email.trim(),
      password,
      account_type: accountType,
    }),
  });
  await SecureStore.setItemAsync(SESSION_KEY, response.session_token);
  return { user: response.user, sessionToken: response.session_token };
}

export async function getAnalyst(
  apiUrl: string,
  token: string,
): Promise<Analyst> {
  const response = await request<{ user: Analyst }>(
    apiUrl,
    "/auth/me",
    token,
  );
  return response.user;
}

export async function logout(apiUrl: string, token: string): Promise<void> {
  try {
    await request<void>(apiUrl, "/mobile/auth/logout", token, {
      method: "POST",
    });
  } finally {
    await SecureStore.deleteItemAsync(SESSION_KEY);
  }
}

export async function getDashboard(
  apiUrl: string,
  token: string,
): Promise<Dashboard> {
  return request<Dashboard>(apiUrl, "/mobile/dashboard", token);
}

export async function checkLink(
  apiUrl: string,
  token: string,
  target: string,
): Promise<RiskResult> {
  const value = target.trim();
  if (value.toLowerCase().startsWith("upi://")) {
    return request<RiskResult>(apiUrl, "/mobile/check-qr", token, {
      method: "POST",
      body: JSON.stringify({ payload: value }),
    });
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Enter or scan a complete web link.");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only web links and supported UPI payment QR codes can be checked.");
  }
  return request<RiskResult>(apiUrl, "/browser/check", token, {
    method: "POST",
    body: JSON.stringify({ url: parsed.href }),
  });
}

export async function checkQr(
  apiUrl: string,
  token: string,
  payload: string,
): Promise<RiskResult> {
  return request<RiskResult>(apiUrl, "/mobile/check-qr", token, {
    method: "POST",
    body: JSON.stringify({ payload }),
  });
}
