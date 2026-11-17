import { CameraView, useCameraPermissions } from "expo-camera";
import { StatusBar } from "expo-status-bar";
import { useShareIntent } from "expo-share-intent";
import { useEffect, useMemo, useState } from "react";
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import {
  Analyst,
  checkLink,
  checkQr,
  Dashboard,
  getAnalyst,
  getDashboard,
  login,
  logout,
  readSavedApiUrl,
  readSessionToken,
  RiskResult,
  saveApiUrl,
} from "./src/api";

type Screen = "dashboard" | "check" | "scan" | "settings";

function extractSharedLink(value: string | null | undefined): string {
  if (!value) return "";
  const trimmed = value.trim();
  try {
    const parsed = new URL(trimmed);
    if (["http:", "https:", "upi:"].includes(parsed.protocol)) return parsed.href;
  } catch {
    const match = trimmed.match(/(?:https?:\/\/|upi:\/\/)[^\s<>"']+/i);
    if (match) return match[0].replace(/[),.!?]+$/, "");
  }
  return "";
}

export default function App() {
  const { hasShareIntent, shareIntent, resetShareIntent } = useShareIntent();
  const [cameraPermission, requestCameraPermission] = useCameraPermissions();
  const [apiUrl, setApiUrl] = useState("");
  const [apiInput, setApiInput] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<Analyst | null>(null);
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [accountType, setAccountType] =
    useState<Analyst["account_type"]>("professional");
  const [target, setTarget] = useState("");
  const [result, setResult] = useState<RiskResult | null>(null);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanned, setScanned] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let active = true;
    async function restore() {
      try {
        const [savedUrl, savedToken] = await Promise.all([
          readSavedApiUrl(),
          readSessionToken(),
        ]);
        if (!active) return;
        setApiUrl(savedUrl);
        setApiInput(savedUrl);
        if (savedUrl && savedToken) {
          setToken(savedToken);
          const analyst = await getAnalyst(savedUrl, savedToken);
          if (active) setUser(analyst);
        }
      } catch {
        if (active) setError("Could not reconnect. Check the API address and sign in again.");
      } finally {
        if (active) setReady(true);
      }
    }
    void restore();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!hasShareIntent) return;
    const shared = extractSharedLink(shareIntent.webUrl ?? shareIntent.text);
    if (shared) {
      setTarget(shared);
      setResult(null);
      setScreen("check");
      setNotice("Shared link received. Tap Check link to review it.");
    } else if (shareIntent.files?.length) {
      setNotice("Image sharing is not supported yet. Use Scan QR to scan a code with your camera.");
    }
    resetShareIntent();
  }, [hasShareIntent, resetShareIntent, shareIntent]);

  useEffect(() => {
    if (!user || !token || !apiUrl) return;
    let active = true;
    getDashboard(apiUrl, token)
      .then((data) => {
        if (active) setDashboard(data);
      })
      .catch((dashboardError: unknown) => {
        if (active) {
          setError(
            dashboardError instanceof Error
              ? dashboardError.message
              : "Could not load the dashboard.",
          );
        }
      });
    return () => {
      active = false;
    };
  }, [apiUrl, token, user]);

  const title = useMemo(() => {
    if (screen === "check") return "Check a link";
    if (screen === "scan") return "Scan a QR code";
    if (screen === "settings") return "Settings";
    return "UPI Shield";
  }, [screen]);

  async function handleLogin() {
    setError("");
    setNotice("");
    setBusy(true);
    try {
      const savedUrl = await saveApiUrl(apiInput);
      setApiUrl(savedUrl);
      const session = await login(savedUrl, email, password, accountType);
      setToken(session.sessionToken);
      setUser(session.user);
      setPassword("");
      setScreen("dashboard");
    } catch (loginError: unknown) {
      setError(
        loginError instanceof Error
          ? loginError.message
          : "Could not sign in.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleCheckLink(value = target) {
    if (!token || !apiUrl) return;
    setError("");
    setNotice("");
    setBusy(true);
    setResult(null);
    try {
      setResult(await checkLink(apiUrl, token, value));
    } catch (checkError: unknown) {
      setError(
        checkError instanceof Error
          ? checkError.message
          : "Could not check this link.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleQrScan(data: string) {
    if (!token || !apiUrl || scanned) return;
    setScanned(true);
    setError("");
    setNotice("");
    setBusy(true);
    setResult(null);
    try {
      setResult(await checkQr(apiUrl, token, data));
    } catch (checkError: unknown) {
      setError(
        checkError instanceof Error
          ? checkError.message
          : "Could not check this QR code.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    if (apiUrl && token) {
      await logout(apiUrl, token).catch(() => undefined);
    }
    setToken(null);
    setUser(null);
    setDashboard(null);
    setPassword("");
    setScreen("dashboard");
  }

  async function saveSettings() {
    setError("");
    try {
      const savedUrl = await saveApiUrl(apiInput);
      setApiUrl(savedUrl);
      setNotice("API address saved.");
    } catch (settingsError: unknown) {
      setError(
        settingsError instanceof Error
          ? settingsError.message
          : "Could not save settings.",
      );
    }
  }

  function onBarcodeScanned({ data }: { data: string }) {
    void handleQrScan(data);
  }

  if (!ready) {
    return (
      <View style={styles.centered}>
        <ActivityIndicator color={colors.mint} size="large" />
        <Text style={styles.muted}>Opening UPI Shield…</Text>
      </View>
    );
  }

  if (!user || !token) {
    return (
      <ScrollView
        contentContainerStyle={styles.loginPage}
        keyboardShouldPersistTaps="handled"
      >
        <StatusBar style="light" />
        <View style={styles.brandMark}>
          <Text style={styles.brandLetter}>U</Text>
        </View>
        <Text style={styles.brandTitle}>UPI Shield</Text>
        <Text style={styles.loginSubtitle}>
          Check payment links and QR codes before you continue.
        </Text>

        <Text style={styles.label}>Secure API address (HTTPS)</Text>
        <TextInput
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          onChangeText={setApiInput}
          placeholder="https://api.your-domain.com"
          placeholderTextColor={colors.placeholder}
          style={styles.input}
          value={apiInput}
        />
        <Text style={styles.hint}>
          Use the public HTTPS address of your deployed UPI Shield backend, not localhost.
        </Text>

        <Text style={styles.label}>Account type</Text>
        <View style={styles.segmentRow}>
          <Segment
            active={accountType === "student"}
            label="Student"
            onPress={() => setAccountType("student")}
          />
          <Segment
            active={accountType === "professional"}
            label="Professional"
            onPress={() => setAccountType("professional")}
          />
        </View>

        <Text style={styles.label}>Email</Text>
        <TextInput
          autoCapitalize="none"
          autoComplete="email"
          keyboardType="email-address"
          onChangeText={setEmail}
          placeholder="you@example.com"
          placeholderTextColor={colors.placeholder}
          style={styles.input}
          value={email}
        />
        <Text style={styles.label}>Password</Text>
        <TextInput
          autoCapitalize="none"
          onChangeText={setPassword}
          placeholder="Your password"
          placeholderTextColor={colors.placeholder}
          secureTextEntry
          style={styles.input}
          value={password}
        />

        {error ? <Message tone="error" text={error} /> : null}
        <PrimaryButton
          disabled={busy}
          label={busy ? "Signing in…" : "Sign in"}
          onPress={() => void handleLogin()}
        />
        <Text style={styles.hint}>
          Create and verify your account on the UPI Shield web dashboard first.
        </Text>
      </ScrollView>
    );
  }

  return (
    <View style={styles.app}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <View>
          <Text style={styles.headerKicker}>UPI SHIELD</Text>
          <Text style={styles.headerTitle}>{title}</Text>
        </View>
        <Text style={styles.avatar}>
          {user.full_name.trim().charAt(0).toUpperCase() || "U"}
        </Text>
      </View>

      <ScrollView
        contentContainerStyle={styles.content}
        keyboardShouldPersistTaps="handled"
      >
        {error ? <Message tone="error" text={error} /> : null}
        {notice ? <Message tone="info" text={notice} /> : null}

        {screen === "dashboard" ? (
          <DashboardView
            dashboard={dashboard}
            email={user.email}
            onRefresh={() => {
              if (token) {
                void getDashboard(apiUrl, token)
                  .then(setDashboard)
                  .catch((refreshError: unknown) =>
                    setError(
                      refreshError instanceof Error
                        ? refreshError.message
                        : "Could not refresh the dashboard.",
                    ),
                  );
              }
            }}
          />
        ) : null}

        {screen === "check" ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Paste or share a link</Text>
            <Text style={styles.bodyText}>
              Web links and UPI payment links can be checked. The link is sent to your configured API.
            </Text>
            <TextInput
              autoCapitalize="none"
              autoCorrect={false}
              multiline
              onChangeText={setTarget}
              placeholder="https://… or upi://pay?…"
              placeholderTextColor={colors.placeholder}
              style={[styles.input, styles.multiline]}
              value={target}
            />
            <PrimaryButton
              disabled={busy || !target.trim()}
              label={busy ? "Checking…" : "Check link"}
              onPress={() => void handleCheckLink()}
            />
            <RiskCard result={result} />
          </View>
        ) : null}

        {screen === "scan" ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Scan before paying</Text>
            <Text style={styles.bodyText}>
              Point the camera at a QR code. UPI Shield checks web links or the payee address in supported UPI payment QR codes.
            </Text>
            {!cameraPermission?.granted ? (
              <PrimaryButton
                label="Allow camera and scan"
                onPress={() => void requestCameraPermission()}
              />
            ) : (
              <>
                <View style={styles.cameraFrame}>
                  <CameraView
                    barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
                    onBarcodeScanned={scanned ? undefined : onBarcodeScanned}
                    style={StyleSheet.absoluteFill}
                  />
                </View>
                {busy ? (
                  <ActivityIndicator color={colors.mint} size="large" />
                ) : null}
                <PrimaryButton
                  label={scanned ? "Scan another QR" : "Reset scanner"}
                  onPress={() => {
                    setScanned(false);
                    setResult(null);
                    setError("");
                  }}
                  secondary
                />
              </>
            )}
            <RiskCard result={result} />
          </View>
        ) : null}

        {screen === "settings" ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Connection</Text>
            <Text style={styles.bodyText}>
              Point the app to your trusted UPI Shield backend. HTTPS is required for public use.
            </Text>
            <Text style={styles.label}>API base address</Text>
            <TextInput
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
              onChangeText={setApiInput}
              placeholder="https://api.your-domain.com"
              placeholderTextColor={colors.placeholder}
              style={styles.input}
              value={apiInput}
            />
            <PrimaryButton label="Save API address" onPress={() => void saveSettings()} />
            <Text style={styles.profileEmail}>{user.email}</Text>
            <PrimaryButton label="Sign out" onPress={() => void handleLogout()} secondary />
            <Text style={styles.hint}>
              QR payloads and links are sent to this server for checking. Only use an API you trust.
            </Text>
          </View>
        ) : null}
      </ScrollView>

      <View style={styles.tabBar}>
        <Tab active={screen === "dashboard"} label="Home" onPress={() => setScreen("dashboard")} />
        <Tab active={screen === "check"} label="Link" onPress={() => setScreen("check")} />
        <Tab active={screen === "scan"} label="Scan QR" onPress={() => setScreen("scan")} />
        <Tab active={screen === "settings"} label="Settings" onPress={() => setScreen("settings")} />
      </View>
    </View>
  );
}

function DashboardView({
  dashboard,
  email,
  onRefresh,
}: {
  dashboard: Dashboard | null;
  email: string;
  onRefresh: () => void;
}) {
  return (
    <>
      <View style={styles.welcomeCard}>
        <Text style={styles.welcomeKicker}>SIGNED IN</Text>
        <Text style={styles.welcomeTitle}>Welcome back</Text>
        <Text style={styles.bodyText}>{email}</Text>
      </View>
      <View style={styles.statsRow}>
        <Stat label="Checks" value={dashboard?.totals.detections ?? "—"} />
        <Stat label="Phishing" value={dashboard?.totals.phishing ?? "—"} danger />
        <Stat label="Suspicious" value={dashboard?.totals.suspicious ?? "—"} warning />
      </View>
      <View style={styles.card}>
        <View style={styles.rowBetween}>
          <Text style={styles.cardTitle}>Recent detections</Text>
          <Pressable onPress={onRefresh}>
            <Text style={styles.linkText}>Refresh</Text>
          </Pressable>
        </View>
        {!dashboard ? (
          <Text style={styles.bodyText}>Loading dashboard…</Text>
        ) : dashboard.recent.length === 0 ? (
          <Text style={styles.bodyText}>No saved detections yet.</Text>
        ) : (
          dashboard.recent.map((item) => (
            <View key={item.id} style={styles.detectionRow}>
              <View style={styles.flex}>
                <Text numberOfLines={1} style={styles.detectionUrl}>{item.url}</Text>
                <Text style={styles.detectionMeta}>
                  {item.verdict} · {Math.round(item.score * 100)} / 100 risk score
                </Text>
              </View>
              <RiskDot verdict={item.verdict} />
            </View>
          ))
        )}
        <Text style={styles.hint}>
          One-time link and QR checks are not saved to this detection list.
        </Text>
      </View>
      <Text style={styles.disclaimer}>
        A low or unknown result is not proof that a link, QR code, or payee is safe.
      </Text>
    </>
  );
}

function RiskCard({ result }: { result: RiskResult | null }) {
  if (!result) return null;
  const score =
    typeof result.score === "number"
      ? `${Math.round(Math.max(0, Math.min(1, result.score)) * 100)} / 100`
      : "Not available";
  const title =
    result.status === "blocked"
      ? result.verdict === "phishing"
        ? "High-risk match"
        : "Risk signal found"
      : result.status === "unknown"
        ? "No known threat match"
        : "Check unavailable";
  const signals = result.report?.signals ?? [];

  return (
    <View style={[styles.reportCard, result.status === "blocked" && styles.reportDanger]}>
      <Text style={styles.reportEyebrow}>UPI SHIELD CHECK</Text>
      <Text style={styles.reportTitle}>{title}</Text>
      <Text style={styles.score}>{score}</Text>
      <Text style={styles.scoreLabel}>
        {result.score_label || "Risk score unavailable"} · not a probability
      </Text>
      {result.reason ? <Text style={styles.bodyText}>{result.reason}</Text> : null}
      {result.report?.payee_name || result.report?.payee_vpa ? (
        <View style={styles.payeeBox}>
          <Text style={styles.payeeText}>
            Payee: {result.report.payee_name || "Name not provided"}
          </Text>
          {result.report.payee_vpa ? (
            <Text style={styles.payeeText}>UPI ID: {result.report.payee_vpa}</Text>
          ) : null}
          {result.report.amount ? (
            <Text style={styles.payeeText}>
              Amount: {result.report.amount} {result.report.currency || ""}
            </Text>
          ) : null}
        </View>
      ) : null}
      {signals.map((signal, index) => (
        <Text key={`${index}-${signal}`} style={styles.signal}>• {signal}</Text>
      ))}
      {result.report?.scope ? (
        <Text style={styles.reportScope}>{result.report.scope}</Text>
      ) : null}
    </View>
  );
}

function Segment({
  active,
  label,
  onPress,
}: {
  active: boolean;
  label: string;
  onPress: () => void;
}) {
  return (
    <Pressable
      onPress={onPress}
      style={[styles.segment, active && styles.segmentActive]}
    >
      <Text style={[styles.segmentText, active && styles.segmentTextActive]}>{label}</Text>
    </Pressable>
  );
}

function PrimaryButton({
  disabled,
  label,
  onPress,
  secondary = false,
}: {
  disabled?: boolean;
  label: string;
  onPress: () => void;
  secondary?: boolean;
}) {
  return (
    <Pressable
      disabled={disabled}
      onPress={onPress}
      style={[
        styles.button,
        secondary && styles.buttonSecondary,
        disabled && styles.buttonDisabled,
      ]}
    >
      <Text style={[styles.buttonText, secondary && styles.buttonSecondaryText]}>
        {label}
      </Text>
    </Pressable>
  );
}

function Message({ text, tone }: { text: string; tone: "error" | "info" }) {
  return (
    <View style={[styles.message, tone === "error" ? styles.errorMessage : styles.infoMessage]}>
      <Text style={styles.messageText}>{text}</Text>
    </View>
  );
}

function Stat({
  danger = false,
  label,
  value,
  warning = false,
}: {
  danger?: boolean;
  label: string;
  value: number | string;
  warning?: boolean;
}) {
  return (
    <View style={styles.stat}>
      <Text style={[styles.statValue, danger && styles.dangerText, warning && styles.warningText]}>
        {value}
      </Text>
      <Text style={styles.statLabel}>{label}</Text>
    </View>
  );
}

function RiskDot({ verdict }: { verdict: string }) {
  return (
    <View
      style={[
        styles.riskDot,
        verdict === "phishing" ? styles.dotDanger : styles.dotWarning,
      ]}
    />
  );
}

function Tab({
  active,
  label,
  onPress,
}: {
  active: boolean;
  label: string;
  onPress: () => void;
}) {
  return (
    <Pressable onPress={onPress} style={styles.tab}>
      <Text style={[styles.tabLabel, active && styles.tabLabelActive]}>{label}</Text>
      {active ? <View style={styles.tabIndicator} /> : null}
    </Pressable>
  );
}

const colors = {
  background: "#0d1523",
  panel: "#172438",
  panelAlt: "#1d2b40",
  border: "#2b3b52",
  mint: "#8fe0bc",
  text: "#eef3fa",
  muted: "#a8b7cc",
  placeholder: "#72839b",
  gold: "#ffcf70",
  red: "#ff9393",
};

const styles = StyleSheet.create({
  app: { flex: 1, backgroundColor: colors.background },
  centered: {
    flex: 1,
    gap: 14,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.background,
  },
  loginPage: {
    flexGrow: 1,
    justifyContent: "center",
    padding: 24,
    paddingTop: 54,
    paddingBottom: 48,
    backgroundColor: colors.background,
  },
  brandMark: {
    width: 52,
    height: 52,
    borderRadius: 16,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: colors.mint,
    marginBottom: 14,
  },
  brandLetter: { color: "#10231b", fontSize: 28, fontWeight: "900" },
  brandTitle: { color: colors.text, fontSize: 32, fontWeight: "800" },
  loginSubtitle: { color: colors.muted, fontSize: 15, lineHeight: 23, marginTop: 8, marginBottom: 28 },
  header: {
    minHeight: 94,
    paddingHorizontal: 20,
    paddingTop: 30,
    paddingBottom: 14,
    alignItems: "center",
    justifyContent: "space-between",
    flexDirection: "row",
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  headerKicker: { color: colors.mint, fontSize: 10, fontWeight: "800", letterSpacing: 1.5 },
  headerTitle: { color: colors.text, fontSize: 23, fontWeight: "800", marginTop: 4 },
  avatar: {
    width: 42,
    height: 42,
    borderRadius: 21,
    overflow: "hidden",
    textAlign: "center",
    textAlignVertical: "center",
    color: colors.text,
    backgroundColor: colors.panelAlt,
    fontSize: 18,
    fontWeight: "800",
  },
  content: { padding: 18, paddingBottom: 30, gap: 14 },
  label: { color: colors.text, fontSize: 13, fontWeight: "700", marginBottom: 7, marginTop: 14 },
  input: {
    minHeight: 50,
    paddingHorizontal: 14,
    paddingVertical: 12,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    backgroundColor: colors.panel,
    color: colors.text,
    fontSize: 15,
  },
  multiline: { minHeight: 106, textAlignVertical: "top", marginTop: 16, marginBottom: 14 },
  hint: { color: colors.muted, fontSize: 12, lineHeight: 18, marginTop: 9 },
  bodyText: { color: colors.muted, fontSize: 14, lineHeight: 21, marginTop: 8 },
  muted: { color: colors.muted, fontSize: 14 },
  card: {
    padding: 17,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 17,
    backgroundColor: colors.panel,
    marginBottom: 2,
  },
  cardTitle: { color: colors.text, fontSize: 17, fontWeight: "800" },
  welcomeCard: {
    padding: 20,
    borderWidth: 1,
    borderColor: "#315548",
    borderRadius: 17,
    backgroundColor: "#162d2b",
  },
  welcomeKicker: { color: colors.mint, fontWeight: "800", letterSpacing: 1.3, fontSize: 10 },
  welcomeTitle: { color: colors.text, fontWeight: "800", fontSize: 23, marginTop: 8 },
  statsRow: { flexDirection: "row", gap: 9 },
  stat: {
    flex: 1,
    minHeight: 84,
    justifyContent: "center",
    alignItems: "center",
    padding: 9,
    borderRadius: 14,
    backgroundColor: colors.panel,
    borderWidth: 1,
    borderColor: colors.border,
  },
  statValue: { color: colors.mint, fontSize: 22, fontWeight: "900" },
  statLabel: { color: colors.muted, fontSize: 11, marginTop: 5 },
  dangerText: { color: colors.red },
  warningText: { color: colors.gold },
  rowBetween: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  linkText: { color: colors.mint, fontWeight: "700" },
  detectionRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 12,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: colors.border,
  },
  flex: { flex: 1 },
  detectionUrl: { color: colors.text, fontWeight: "700", fontSize: 13 },
  detectionMeta: { color: colors.muted, fontSize: 11, marginTop: 5, textTransform: "capitalize" },
  riskDot: { width: 10, height: 10, borderRadius: 5 },
  dotDanger: { backgroundColor: colors.red },
  dotWarning: { backgroundColor: colors.gold },
  disclaimer: { color: colors.muted, fontSize: 12, lineHeight: 18, paddingHorizontal: 3 },
  segmentRow: { flexDirection: "row", gap: 10 },
  segment: {
    flex: 1,
    minHeight: 44,
    justifyContent: "center",
    alignItems: "center",
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 11,
    backgroundColor: colors.panel,
  },
  segmentActive: { borderColor: colors.mint, backgroundColor: "#1c3937" },
  segmentText: { color: colors.muted, fontSize: 13, fontWeight: "700" },
  segmentTextActive: { color: colors.mint },
  button: {
    minHeight: 50,
    marginTop: 14,
    justifyContent: "center",
    alignItems: "center",
    borderRadius: 12,
    backgroundColor: colors.mint,
  },
  buttonSecondary: { backgroundColor: colors.panelAlt, borderWidth: 1, borderColor: colors.border },
  buttonDisabled: { opacity: 0.55 },
  buttonText: { color: "#11251c", fontSize: 15, fontWeight: "800" },
  buttonSecondaryText: { color: colors.text },
  reportCard: {
    padding: 16,
    marginTop: 18,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 14,
    backgroundColor: "#111c2c",
  },
  reportDanger: { borderColor: "#8f5258", backgroundColor: "#2d202b" },
  reportEyebrow: { color: colors.mint, fontSize: 10, fontWeight: "800", letterSpacing: 1.2 },
  reportTitle: { color: colors.text, fontSize: 19, fontWeight: "800", marginTop: 7 },
  score: { color: colors.gold, fontSize: 27, fontWeight: "900", marginTop: 10 },
  scoreLabel: { color: colors.muted, fontSize: 11, marginTop: 1, marginBottom: 8 },
  signal: { color: colors.text, fontSize: 13, lineHeight: 20, marginTop: 6 },
  reportScope: { color: colors.muted, fontSize: 11, lineHeight: 17, marginTop: 13 },
  payeeBox: { padding: 11, marginTop: 10, borderRadius: 10, backgroundColor: colors.panelAlt },
  payeeText: { color: colors.text, fontSize: 12, lineHeight: 19 },
  cameraFrame: {
    height: 310,
    marginTop: 16,
    overflow: "hidden",
    borderRadius: 15,
    backgroundColor: "#03070d",
  },
  tabBar: {
    minHeight: 66,
    flexDirection: "row",
    alignItems: "stretch",
    justifyContent: "space-around",
    paddingBottom: 6,
    borderTopWidth: 1,
    borderTopColor: colors.border,
    backgroundColor: "#101a29",
  },
  tab: { flex: 1, alignItems: "center", justifyContent: "center", gap: 5 },
  tabLabel: { color: colors.muted, fontSize: 11, fontWeight: "700" },
  tabLabelActive: { color: colors.mint },
  tabIndicator: { width: 19, height: 3, borderRadius: 2, backgroundColor: colors.mint },
  message: { padding: 12, borderRadius: 10, marginBottom: 8 },
  errorMessage: { backgroundColor: "#3d242b", borderWidth: 1, borderColor: "#79454d" },
  infoMessage: { backgroundColor: "#203342", borderWidth: 1, borderColor: "#3a5c70" },
  messageText: { color: colors.text, fontSize: 13, lineHeight: 19 },
  profileEmail: { color: colors.text, marginTop: 20, fontWeight: "700" },
});
