"use client";

import React, { useState, useEffect, useCallback, FormEvent } from "react";
import {
  Shield,
  Key,
  Users,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Plus,
  RefreshCw,
  Power,
  Laptop,
  Calendar,
  Search,
  Trash2,
  Check,
  Building,
  Mail,
  FileText,
  RotateCcw,
  Lock,
  LogOut,
  Sparkles,
  ExternalLink,
  ChevronRight,
  UserCheck,
  Activity,
  Cpu,
  Terminal,
  Radio,
  Globe,
} from "lucide-react";
import { License, LicensePlan, LicenseStats } from "@/lib/types";

// Master Admin Access Credentials
const DEFAULT_ADMIN_USER = "admin";
const DEFAULT_ADMIN_PASS = "aegis@2026";
const AUTH_STORAGE_KEY = "aegis_cloud_admin_auth";

export default function LicensePortalDashboard() {
  // ── Authentication State ──────────────────────────────────────────────────
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [authChecking, setAuthChecking] = useState<boolean>(true);
  const [isAuthenticating, setIsAuthenticating] = useState<boolean>(false);
  const [authProgress, setAuthProgress] = useState<number>(0);
  const [authStepText, setAuthStepText] = useState<string>("");
  const [loginUsername, setLoginUsername] = useState<string>("");
  const [loginPassword, setLoginPassword] = useState<string>("");
  const [loginError, setLoginError] = useState<string>("");

  // ── Live UTC Clock ────────────────────────────────────────────────────────
  const [utcClock, setUtcClock] = useState<string>("");

  // ── Toast Notification State ──────────────────────────────────────────────
  const [toastMessage, setToastMessage] = useState<{ text: string; type: "success" | "info" | "warn" } | null>(null);

  // ── Data State ────────────────────────────────────────────────────────────
  const [licenses, setLicenses] = useState<License[]>([]);
  const [stats, setStats] = useState<LicenseStats>({
    total: 0,
    active: 0,
    expiringSoon: 0,
    revoked: 0,
    connectedDevices: 0,
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // ── Form State ────────────────────────────────────────────────────────────
  const [clientName, setClientName] = useState("");
  const [organization, setOrganization] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [plan, setPlan] = useState<LicensePlan>("30_days");
  const [maxDevices, setMaxDevices] = useState(1);
  const [notes, setNotes] = useState("");
  const [generating, setGenerating] = useState(false);

  // ── Success Generated Callout ──────────────────────────────────────────────
  const [recentlyGenerated, setRecentlyGenerated] = useState<License | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedSummary, setCopiedSummary] = useState(false);

  // ── Search & Filter ───────────────────────────────────────────────────────
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "expiring" | "revoked">("all");

  const showToast = useCallback((text: string, type: "success" | "info" | "warn" = "success") => {
    setToastMessage({ text, type });
    setTimeout(() => {
      setToastMessage(null);
    }, 3200);
  }, []);

  // Update live clock
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcClock(now.toISOString().replace("T", "  ").substring(0, 19) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Check stored session on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(AUTH_STORAGE_KEY);
      if (stored === "authenticated") {
        setIsAuthenticated(true);
      }
    } catch {
      // Ignore localStorage read errors in SSR
    } finally {
      setAuthChecking(false);
    }
  }, []);

  // Cyber Animated Login Sequence
  const handleLogin = (e: FormEvent) => {
    e.preventDefault();
    setLoginError("");

    const trimmedUser = loginUsername.trim().toLowerCase();
    const trimmedPass = loginPassword.trim();

    if (
      (trimmedUser === DEFAULT_ADMIN_USER || trimmedUser === "frazcodes") &&
      (trimmedPass === DEFAULT_ADMIN_PASS || trimmedPass === "aegis2026")
    ) {
      setIsAuthenticating(true);
      setAuthProgress(15);
      setAuthStepText("VERIFYING MASTER CRYPTOGRAPHIC KEY...");

      setTimeout(() => {
        setAuthProgress(45);
        setAuthStepText("ESTABLISHING ENCRYPTED LINK TO FIREBASE CLOUD...");
      }, 400);

      setTimeout(() => {
        setAuthProgress(80);
        setAuthStepText("DECRYPTING CLIENT HARDWARE VAULT...");
      }, 850);

      setTimeout(() => {
        setAuthProgress(100);
        setAuthStepText("ACCESS GRANTED. INITIALIZING SOC COCKPIT...");
      }, 1250);

      setTimeout(() => {
        setIsAuthenticating(false);
        setIsAuthenticated(true);
        try {
          localStorage.setItem(AUTH_STORAGE_KEY, "authenticated");
        } catch {
          // ignore
        }
        showToast("Welcome Master Operator. SOC Cockpit Initialized.", "success");
      }, 1600);
    } else {
      setLoginError("ACCESS DENIED: Invalid Master Administrator credentials.");
    }
  };

  const handleLogout = () => {
    try {
      localStorage.removeItem(AUTH_STORAGE_KEY);
    } catch {
      // ignore
    }
    setIsAuthenticated(false);
    setLoginUsername("");
    setLoginPassword("");
    setRecentlyGenerated(null);
    showToast("Master Session Terminated.", "info");
  };

  const fetchLicenses = useCallback(async () => {
    try {
      const res = await fetch("/api/licenses");
      const data = await res.json();
      if (data.success) {
        setLicenses(data.licenses);
        setStats(data.stats);
      }
    } catch (err) {
      console.error("Failed fetching licenses:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      fetchLicenses();
    }
  }, [isAuthenticated, fetchLicenses]);

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchLicenses();
    showToast("License Vault Synchronized with Firebase.", "info");
  };

  const handleCreateLicense = async (e: FormEvent) => {
    e.preventDefault();
    if (!clientName.trim()) return;

    setGenerating(true);
    try {
      const res = await fetch("/api/licenses", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          clientName,
          organization,
          contactEmail,
          plan,
          maxDevices,
          notes,
        }),
      });

      const data = await res.json();
      if (data.success && data.license) {
        setRecentlyGenerated(data.license);
        // Reset form
        setClientName("");
        setOrganization("");
        setContactEmail("");
        setNotes("");
        setPlan("30_days");
        fetchLicenses();
        showToast(`License Key Issued for ${data.license.clientName}`, "success");
      }
    } catch (err) {
      console.error("Failed creating license:", err);
      showToast("Error generating license key.", "warn");
    } finally {
      setGenerating(false);
    }
  };

  const handleAction = async (key: string, action: string, extendDays = 30) => {
    try {
      const res = await fetch("/api/licenses/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, action, extendDays }),
      });
      const data = await res.json();
      if (data.success) {
        fetchLicenses();
        if (action === "extend") {
          showToast(`License extended by +${extendDays} days.`, "success");
        } else if (action === "reset_hwid") {
          showToast("Hardware Lock unbinded successfully.", "info");
        } else if (action === "revoke") {
          showToast("License revoked. Station access blocked.", "warn");
        } else if (action === "activate") {
          showToast("License reactivated. Station access restored.", "success");
        } else if (action === "delete") {
          showToast("License permanently deleted.", "warn");
        }
      }
    } catch (err) {
      console.error(`Action ${action} failed:`, err);
    }
  };

  const copyToClipboard = (text: string, type: "key" | "summary") => {
    navigator.clipboard.writeText(text);
    if (type === "key") {
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
      showToast("License key copied to clipboard!", "success");
    } else {
      setCopiedSummary(true);
      setTimeout(() => setCopiedSummary(false), 2000);
      showToast("Deployment instructions copied!", "info");
    }
  };

  const calculateDays = (expiresAt: string) => {
    const diff = new Date(expiresAt).getTime() - Date.now();
    return Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
  };

  const filteredLicenses = licenses.filter((lic: License) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      lic.clientName.toLowerCase().includes(q) ||
      lic.organization.toLowerCase().includes(q) ||
      lic.key.toLowerCase().includes(q) ||
      (lic.machineHostname && lic.machineHostname.toLowerCase().includes(q));

    const isExpired = new Date(lic.expiresAt).getTime() <= Date.now();
    const daysLeft = calculateDays(lic.expiresAt);

    if (!matchesSearch) return false;

    if (statusFilter === "active") return lic.isActive && !isExpired;
    if (statusFilter === "expiring") return lic.isActive && !isExpired && daysLeft <= 7;
    if (statusFilter === "revoked") return !lic.isActive || isExpired;
    return true;
  });

  // ──────────────────────────────────────────────────────────────────────────
  // VIEW 1: Master Admin Authentication Screen (Cyber Glassmorphism)
  // ──────────────────────────────────────────────────────────────────────────
  if (authChecking) {
    return (
      <div className="min-h-screen bg-[#030712] flex items-center justify-center">
        <div className="w-10 h-10 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#030712] cyber-grid text-slate-100 flex items-center justify-center p-4 relative overflow-hidden selection:bg-cyan-500 selection:text-black">
        {/* Animated Cyber Scanning Line */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          <div className="w-full h-1 bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent animate-scanline opacity-75"></div>
        </div>

        {/* Ambient Glowing Glass Orbs */}
        <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none -translate-x-1/2 -translate-y-1/2" />
        <div className="absolute bottom-1/4 right-1/4 w-[550px] h-[550px] bg-blue-600/15 rounded-full blur-[160px] pointer-events-none translate-x-1/2 translate-y-1/2" />
        <div className="absolute top-1/2 left-1/2 w-80 h-80 bg-indigo-500/10 rounded-full blur-[120px] pointer-events-none -translate-x-1/2 -translate-y-1/2" />

        {/* Master Admin Glassmorphism Card */}
        <div className="w-full max-w-md relative z-10 glass-panel rounded-3xl p-8 sm:p-10 shadow-2xl shadow-cyan-950/60 border border-cyan-500/30">
          {/* Cyber HUD Corner Accents */}
          <div className="absolute top-3 left-3 w-3 h-3 border-t-2 border-l-2 border-cyan-400"></div>
          <div className="absolute top-3 right-3 w-3 h-3 border-t-2 border-r-2 border-cyan-400"></div>
          <div className="absolute bottom-3 left-3 w-3 h-3 border-b-2 border-l-2 border-cyan-400"></div>
          <div className="absolute bottom-3 right-3 w-3 h-3 border-b-2 border-r-2 border-cyan-400"></div>

          {/* If Currently Running Cyber Authentication Sequence */}
          {isAuthenticating ? (
            <div className="py-8 flex flex-col items-center text-center space-y-6 animate-in fade-in zoom-in-95 duration-300">
              <div className="relative">
                <div className="w-20 h-20 rounded-2xl bg-gradient-to-tr from-cyan-500/20 via-emerald-500/20 to-blue-500/30 border-2 border-cyan-400/80 flex items-center justify-center shadow-2xl shadow-cyan-500/40 animate-pulse">
                  <Shield className="w-10 h-10 text-cyan-300" />
                </div>
              </div>

              <div>
                <h2 className="text-xl font-black text-cyan-300 tracking-widest uppercase">
                  ACCESS GRANTED
                </h2>
                <p className="text-[11px] font-mono text-emerald-400 mt-1 tracking-wider">
                  MASTER SECURITY CLEARANCE: LEVEL 5
                </p>
              </div>

              {/* Progress Bar */}
              <div className="w-full space-y-2">
                <div className="w-full bg-slate-950/80 rounded-full h-2.5 overflow-hidden border border-cyan-500/40 p-0.5">
                  <div
                    className="bg-gradient-to-r from-cyan-400 via-emerald-400 to-cyan-300 h-full rounded-full transition-all duration-300 shadow-[0_0_12px_rgba(56,189,248,0.8)]"
                    style={{ width: `${authProgress}%` }}
                  ></div>
                </div>
                <div className="flex justify-between text-[10px] font-mono text-slate-400">
                  <span className="text-cyan-400">{authStepText}</span>
                  <span className="font-bold text-slate-300">{authProgress}%</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-[10px] font-mono text-slate-400 text-left w-full space-y-1">
                <div className="text-emerald-400">✓ RSA-256 JWT Signed: OK</div>
                <div className="text-cyan-400">✓ Handshake: aegis-license-system</div>
                <div className="text-slate-500">&gt; Loading Cockpit Dashboards...</div>
              </div>
            </div>
          ) : (
            <>
              {/* Top Badge & Glow Icon */}
              <div className="flex flex-col items-center text-center mb-8">
                <div className="relative mb-4">
                  <div className="absolute inset-0 bg-cyan-400/30 rounded-2xl blur-xl animate-pulse"></div>
                  <div className="relative w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-500/20 via-blue-600/30 to-blue-900/40 border border-cyan-400/60 flex items-center justify-center shadow-xl shadow-cyan-500/20">
                    <Shield className="w-8 h-8 text-cyan-300" />
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <h1 className="text-2xl font-black tracking-wider text-slate-100">
                    AEGIS IDPS
                  </h1>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-700/60">
                    SOC v2.4
                  </span>
                </div>
                <p className="text-xs font-semibold uppercase tracking-widest text-cyan-400 mt-1">
                  Cloud License Operations Portal
                </p>
                <div className="mt-3 inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-slate-950/80 border border-slate-800 text-[11px] text-slate-300 font-mono">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  <span>RESTRICTED MASTER CONSOLE</span>
                </div>
              </div>

              {/* Login Form */}
              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                    Administrator ID
                  </label>
                  <div className="relative">
                    <Users className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
                    <input
                      type="text"
                      required
                      placeholder="e.g. admin"
                      value={loginUsername}
                      onChange={(e: any) => setLoginUsername(e.target.value)}
                      className="w-full bg-slate-950/90 border border-slate-700/80 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/30 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                    Master Cryptographic Passcode
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
                    <input
                      type="password"
                      required
                      placeholder="••••••••••••"
                      value={loginPassword}
                      onChange={(e: any) => setLoginPassword(e.target.value)}
                      className="w-full bg-slate-950/90 border border-slate-700/80 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/30 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition font-mono"
                    />
                  </div>
                </div>

                {loginError && (
                  <div className="p-3 rounded-xl bg-red-950/80 border border-red-500/50 text-red-300 text-xs flex items-center space-x-2 animate-in fade-in">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                    <span>{loginError}</span>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full py-3.5 rounded-xl bg-gradient-to-r from-cyan-400 via-sky-500 to-blue-600 hover:from-cyan-300 hover:to-blue-500 text-slate-950 font-black text-sm tracking-wider uppercase shadow-lg shadow-cyan-500/25 hover:shadow-cyan-400/40 transition-all duration-200 flex items-center justify-center space-x-2 mt-6 cursor-pointer"
                >
                  <Key className="w-4 h-4" />
                  <span>Authenticate Operator</span>
                </button>
              </form>

              {/* Demo Credentials Quick-Fill helper */}
              <div className="mt-6 pt-5 border-t border-slate-800/80 text-center">
                <button
                  type="button"
                  onClick={() => {
                    setLoginUsername("admin");
                    setLoginPassword("aegis@2026");
                  }}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 underline underline-offset-4 transition font-mono"
                >
                  [⚡ Click to Pre-fill Master Credentials: admin / aegis@2026]
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // VIEW 2: Ultra-Premium Cyber SOC Dashboard
  // ──────────────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#030712] cyber-grid text-slate-100 p-4 sm:p-6 md:p-8 relative overflow-hidden selection:bg-cyan-500 selection:text-black">
      {/* Floating Interactive Toast Notification */}
      {toastMessage && (
        <div className="fixed top-6 right-6 z-50 animate-in slide-in-from-top-4 fade-in duration-300">
          <div className="glass-panel px-4 py-3 rounded-2xl flex items-center space-x-3 shadow-2xl border border-cyan-400/40">
            {toastMessage.type === "success" && <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />}
            {toastMessage.type === "info" && <Sparkles className="w-5 h-5 text-cyan-400 shrink-0" />}
            {toastMessage.type === "warn" && <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />}
            <span className="text-xs font-semibold text-slate-100">{toastMessage.text}</span>
          </div>
        </div>
      )}

      {/* Background Ambient Radial Glows */}
      <div className="absolute top-0 left-1/4 w-[650px] h-[450px] bg-cyan-600/10 rounded-full blur-[150px] pointer-events-none -translate-y-1/2" />
      <div className="absolute top-1/3 right-0 w-[550px] h-[550px] bg-blue-600/10 rounded-full blur-[170px] pointer-events-none translate-x-1/3" />
      <div className="absolute bottom-0 left-1/3 w-[650px] h-[450px] bg-indigo-600/10 rounded-full blur-[150px] pointer-events-none translate-y-1/3" />

      <div className="max-w-7xl mx-auto space-y-8 relative z-10">
        {/* ── Top Cyber HUD Bar ───────────────────────────────────────────────── */}
        <header className="glass-panel rounded-2xl p-4 sm:px-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4 border border-cyan-500/25">
          <div className="flex items-center space-x-3.5">
            <div className="relative">
              <div className="absolute inset-0 bg-cyan-400/25 rounded-xl blur-md animate-pulse"></div>
              <div className="relative w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-500/20 via-blue-600/30 to-blue-900/40 border border-cyan-400/40 flex items-center justify-center shadow-lg shadow-cyan-500/20 shrink-0">
                <Shield className="w-6 h-6 text-cyan-300" />
              </div>
            </div>

            <div>
              <div className="flex items-center space-x-2.5">
                <h1 className="text-lg md:text-xl font-black tracking-wider text-slate-100">
                  AEGIS IDPS
                </h1>
                <span className="px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider rounded-md bg-cyan-950 text-cyan-300 border border-cyan-700/60 shadow-[0_0_10px_rgba(6,182,212,0.3)]">
                  CLOUD LICENSE COMMAND
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Hardware ID Binding, Node Cryptographic Key Issuance &amp; Real-time Firebase Firestore Sync
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Live Cloud Status */}
            <div className="flex items-center space-x-2 text-xs font-mono bg-slate-950/80 border border-slate-800 px-3.5 py-1.5 rounded-xl text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="text-emerald-400 font-bold">FIREBASE CLOUD: LIVE</span>
            </div>

            {/* Live Clock Pill */}
            <div className="hidden lg:flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-950/80 border border-slate-800 text-xs font-mono text-cyan-400">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span>{utcClock}</span>
            </div>

            {/* Manual Refresh Button */}
            <button
              onClick={handleManualRefresh}
              disabled={refreshing}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/60 text-xs text-slate-200 font-semibold transition cursor-pointer"
              title="Refresh Licenses"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
              <span>Sync</span>
            </button>

            {/* Master Admin Operator Pill */}
            <div className="hidden sm:flex items-center space-x-2 px-3.5 py-1.5 rounded-xl bg-cyan-950/50 border border-cyan-700/50 text-xs text-cyan-300 font-bold">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Master Admin</span>
            </div>

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl bg-red-950/50 hover:bg-red-900/60 border border-red-800/50 text-xs text-red-300 font-bold transition cursor-pointer"
              title="Sign Out"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>
          </div>
        </header>

        {/* ── 4 Cyber Metric HUD Cards ───────────────────────────────────────── */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {/* Card 1: Total Issued */}
          <div className="glass-panel p-5 rounded-2xl group hover:border-cyan-400/80 hover:shadow-[0_0_25px_rgba(6,182,212,0.2)] transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-cyan-300">Total Issued</span>
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Key className="w-4 h-4 text-cyan-400" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight text-slate-100">{stats.total}</div>
            <p className="text-[11px] text-slate-400 mt-1">Cryptographic Node Keys</p>
          </div>

          {/* Card 2: Active Deployments */}
          <div className="glass-panel p-5 rounded-2xl group hover:border-emerald-400/80 hover:shadow-[0_0_25px_rgba(16,185,129,0.2)] transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-300">Active Nodes</span>
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-400/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight text-emerald-400">{stats.active}</div>
            <p className="text-[11px] text-slate-400 mt-1">Operational SOC Stations</p>
          </div>

          {/* Card 3: Expiring Soon */}
          <div className="glass-panel p-5 rounded-2xl group hover:border-amber-400/80 hover:shadow-[0_0_25px_rgba(245,158,11,0.2)] transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-amber-300">Expiring Soon</span>
              <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-400/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Clock className="w-4 h-4 text-amber-400" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight text-amber-400">{stats.expiringSoon}</div>
            <p className="text-[11px] text-slate-400 mt-1">&lt; 7 Days Remaining</p>
          </div>

          {/* Card 4: Bound HWID Machines */}
          <div className="glass-panel p-5 rounded-2xl group hover:border-indigo-400/80 hover:shadow-[0_0_25px_rgba(99,102,241,0.2)] transition-all">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-indigo-300">Bound Workstations</span>
              <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-400/30 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Laptop className="w-4 h-4 text-indigo-400" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight text-indigo-300">{stats.connectedDevices}</div>
            <p className="text-[11px] text-slate-400 mt-1">Locked Machine HWIDs</p>
          </div>
        </section>

        {/* ── Key Issuance Panel (Glassmorphism Form) ────────────────────────── */}
        <section className="glass-panel rounded-3xl p-6 sm:p-8 shadow-2xl relative overflow-hidden border border-cyan-500/30">
          <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

          <div className="flex items-center space-x-3 mb-2">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/15 border border-cyan-400/40 flex items-center justify-center shadow-[0_0_15px_rgba(6,182,212,0.3)]">
              <Key className="w-5 h-5 text-cyan-300" />
            </div>
            <h2 className="text-base sm:text-lg font-black text-slate-100 tracking-wide uppercase">
              ISSUE NEW CLIENT NODE LICENSE
            </h2>
          </div>
          <p className="text-xs text-slate-400 mb-6 max-w-2xl">
            Select duration and client identity. The system cryptographically generates a unique 16-character license key formatted in 4-character blocks, instantly synchronized with Firebase Firestore.
          </p>

          <form onSubmit={handleCreateLicense} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              {/* Field 1: Client Name */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Client Full Name <span className="text-cyan-400">*</span>
                </label>
                <div className="relative">
                  <Users className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    required
                    placeholder="e.g. Ahmad Faraz"
                    value={clientName}
                    onChange={(e: any) => setClientName(e.target.value)}
                    className="w-full bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/25 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 2: Organization */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Organization / Lab / Institution
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    placeholder="e.g. Aegis Cyber Defense Lab"
                    value={organization}
                    onChange={(e: any) => setOrganization(e.target.value)}
                    className="w-full bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/25 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 3: Contact Email */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Contact Email / Phone
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    placeholder="e.g. operator@domain.com"
                    value={contactEmail}
                    onChange={(e: any) => setContactEmail(e.target.value)}
                    className="w-full bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/25 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>
            </div>

            {/* Interactive Validity Plan Selector */}
            <div>
              <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2.5">
                License Validity Duration
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
                {[
                  { id: "7_days", label: "7 Days", desc: "Pilot Trial" },
                  { id: "30_days", label: "30 Days", desc: "Monthly Standard" },
                  { id: "90_days", label: "90 Days", desc: "Quarterly Evaluation" },
                  { id: "1_year", label: "1 Year", desc: "Annual Enterprise" },
                  { id: "lifetime", label: "Lifetime", desc: "Perpetual License" },
                ].map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setPlan(item.id as LicensePlan)}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                      plan === item.id
                        ? "bg-cyan-950/70 border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)] text-cyan-300"
                        : "bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <div className="text-xs font-black">{item.label}</div>
                    <div className="text-[10px] opacity-75">{item.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {/* Field 5: Max Allowed Devices */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Allowed Machines (Hardware Lock)
                </label>
                <div className="relative">
                  <Laptop className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
                  <select
                    value={maxDevices}
                    onChange={(e: any) => setMaxDevices(parseInt(e.target.value, 10))}
                    className="w-full bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/25 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 outline-none transition cursor-pointer"
                  >
                    <option value={1}>1 Machine (Single Workstation Lock)</option>
                    <option value={3}>3 Machines (Small Lab Cluster)</option>
                    <option value={5}>5 Machines (SOC Team Cluster)</option>
                  </select>
                </div>
              </div>

              {/* Field 6: Internal Notes */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Operational Reference Notes
                </label>
                <div className="relative">
                  <FileText className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    placeholder="e.g. FYP External Evaluator / Node #01"
                    value={notes}
                    onChange={(e: any) => setNotes(e.target.value)}
                    className="w-full bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/25 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>
            </div>

            {/* Action Submit Button */}
            <div className="pt-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <button
                type="submit"
                disabled={generating || !clientName.trim()}
                className="flex items-center justify-center space-x-2 px-8 py-3.5 rounded-xl bg-gradient-to-r from-cyan-400 via-sky-500 to-blue-600 hover:from-cyan-300 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-black text-sm tracking-wide shadow-lg shadow-cyan-500/25 hover:shadow-cyan-400/40 transition cursor-pointer"
              >
                <Key className="w-4 h-4" />
                <span>{generating ? "Encrypting & Registering on Cloud..." : "⚡ Auto-Generate & Issue License Key"}</span>
              </button>

              <span className="text-xs text-slate-400 font-mono">
                Auto-syncs to Firebase Firestore Project: <span className="text-cyan-400">aegis-license-system</span>
              </span>
            </div>
          </form>

          {/* ── Generated Key Result Banner (Holographic Callout) ───────────── */}
          {recentlyGenerated && (
            <div className="mt-8 p-6 rounded-2xl bg-cyan-950/50 border-2 border-cyan-400/80 shadow-[0_0_30px_rgba(6,182,212,0.35)] animate-in fade-in slide-in-from-top-3 duration-300 relative">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2 mb-1.5">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span className="text-xs font-black text-cyan-300 uppercase tracking-widest">
                      Node License Successfully Registered &amp; Encrypted
                    </span>
                  </div>
                  <div className="text-2xl sm:text-3xl font-mono font-black text-cyan-200 tracking-widest text-shadow">
                    {recentlyGenerated.key}
                  </div>
                  <div className="text-xs text-slate-300 mt-1.5">
                    Assigned: <strong className="text-slate-100">{recentlyGenerated.clientName}</strong> ({recentlyGenerated.organization || "Direct Client"}) · Valid until: {new Date(recentlyGenerated.expiresAt).toLocaleDateString()}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2.5">
                  <button
                    onClick={() => copyToClipboard(recentlyGenerated.key, "key")}
                    className="flex items-center space-x-1.5 px-4 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-black text-xs transition shadow-md shadow-cyan-400/30 cursor-pointer"
                  >
                    {copiedKey ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey ? "Copied!" : "Copy Key"}</span>
                  </button>

                  <button
                    onClick={() => {
                      const text = `AEGIS IDPS ACTIVATION CREDENTIALS:\nClient: ${recentlyGenerated.clientName}\nLicense Key: ${recentlyGenerated.key}\nExpiry Date: ${new Date(recentlyGenerated.expiresAt).toLocaleDateString()}\n\nInstructions: Launch Aegis IDPS on your PC, paste this 16-character key into the unified login card, and click 'AUTHORIZE & ENTER CONSOLE'.`;
                      copyToClipboard(text, "summary");
                    }}
                    className="flex items-center space-x-1.5 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition cursor-pointer"
                  >
                    {copiedSummary ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSummary ? "Copied Message!" : "Copy Instructions"}</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ── Active Licenses Management Table (Glassmorphism) ───────────────── */}
        <section className="glass-panel rounded-3xl p-6 sm:p-8 shadow-2xl border border-cyan-500/25">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h2 className="text-base sm:text-lg font-black text-slate-100 tracking-wide uppercase flex items-center space-x-2">
                <span>DEPLOYED CLIENT NODES</span>
                <span className="text-xs font-normal text-cyan-400 font-mono">({filteredLicenses.length} matching)</span>
              </h2>
              <p className="text-xs text-slate-400">
                Live monitoring of issued licenses, bound hardware fingerprints, and instantaneous access control.
              </p>
            </div>

            {/* Filter and Search Bar */}
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search client, key, HWID..."
                  value={searchQuery}
                  onChange={(e: any) => setSearchQuery(e.target.value)}
                  className="bg-slate-950/90 border border-slate-700/80 focus:border-cyan-400 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 outline-none w-56 transition"
                />
              </div>

              <div className="flex rounded-xl bg-slate-950/90 p-1 border border-slate-800 text-xs">
                {(["all", "active", "expiring", "revoked"] as const).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setStatusFilter(filter)}
                    className={`px-3 py-1 rounded-lg font-bold capitalize transition cursor-pointer ${
                      statusFilter === filter
                        ? "bg-cyan-500 text-slate-950 shadow-[0_0_10px_rgba(6,182,212,0.4)]"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Table Container */}
          <div className="overflow-x-auto rounded-2xl border border-slate-800/80 bg-slate-950/70">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/90 text-slate-400 uppercase text-[11px] font-black tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-4 text-cyan-300">Client &amp; Organization</th>
                  <th className="py-3.5 px-4 text-cyan-300">License Key</th>
                  <th className="py-3.5 px-4 text-cyan-300">Remaining</th>
                  <th className="py-3.5 px-4 text-cyan-300">Expiry Date</th>
                  <th className="py-3.5 px-4 text-cyan-300">Bound Workstation (HWID)</th>
                  <th className="py-3.5 px-4 text-cyan-300">Node Status</th>
                  <th className="py-3.5 px-4 text-right text-cyan-300">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {loading ? (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-slate-500 font-mono">
                      Querying Firebase Firestore database...
                    </td>
                  </tr>
                ) : filteredLicenses.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-slate-500">
                      No licenses found matching your filter.
                    </td>
                  </tr>
                ) : (
                  filteredLicenses.map((lic: License) => {
                    const daysLeft = calculateDays(lic.expiresAt);
                    const isExpired = new Date(lic.expiresAt).getTime() <= Date.now();

                    return (
                      <tr key={lic.key} className="hover:bg-cyan-950/20 transition">
                        {/* Client Name & Org */}
                        <td className="py-3.5 px-4">
                          <div className="font-bold text-slate-100">{lic.clientName}</div>
                          <div className="text-[11px] text-slate-400">{lic.organization}</div>
                          {lic.contactEmail && (
                            <div className="text-[10px] text-slate-500 font-mono">{lic.contactEmail}</div>
                          )}
                        </td>

                        {/* License Key */}
                        <td className="py-3.5 px-4 font-mono font-bold text-cyan-300">
                          <div className="flex items-center space-x-1.5">
                            <span>{lic.key}</span>
                            <button
                              onClick={() => copyToClipboard(lic.key, "key")}
                              title="Copy Key"
                              className="text-slate-500 hover:text-cyan-400 transition cursor-pointer"
                            >
                              <Copy className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>

                        {/* Remaining Days Badge */}
                        <td className="py-3.5 px-4">
                          {!lic.isActive ? (
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-red-950/80 text-red-400 border border-red-800/50">
                              BLOCKED
                            </span>
                          ) : isExpired ? (
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-red-950/80 text-red-400 border border-red-800/50">
                              EXPIRED
                            </span>
                          ) : daysLeft <= 7 ? (
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-950/80 text-amber-400 border border-amber-800/50 shadow-[0_0_10px_rgba(245,158,11,0.2)]">
                              ⚠️ {daysLeft} Days
                            </span>
                          ) : (
                            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]">
                              🟢 {daysLeft} Days
                            </span>
                          )}
                        </td>

                        {/* Expiry Date */}
                        <td className="py-3.5 px-4 text-slate-300 font-mono">
                          {new Date(lic.expiresAt).toLocaleDateString()}
                        </td>

                        {/* Bound Machine */}
                        <td className="py-3.5 px-4">
                          {lic.hardwareId ? (
                            <div className="flex items-center space-x-1.5 text-slate-200">
                              <Laptop className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                              <span className="font-mono text-[11px] text-cyan-300" title={lic.hardwareId}>
                                {lic.machineHostname || lic.hardwareId.substring(0, 14) + "..."}
                              </span>
                            </div>
                          ) : (
                            <span className="text-slate-500 italic text-[11px]">
                              Waiting for node activation...
                            </span>
                          )}
                        </td>

                        {/* Status */}
                        <td className="py-3.5 px-4">
                          {!lic.isActive ? (
                            <span className="inline-flex items-center space-x-1 text-red-400 font-bold">
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Revoked</span>
                            </span>
                          ) : isExpired ? (
                            <span className="inline-flex items-center space-x-1 text-red-400 font-bold">
                              <AlertTriangle className="w-3.5 h-3.5" />
                              <span>Expired</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 text-emerald-400 font-bold">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Active</span>
                            </span>
                          )}
                        </td>

                        {/* Actions */}
                        <td className="py-3.5 px-4 text-right">
                          <div className="flex items-center justify-end space-x-1.5">
                            {/* Toggle Active / Revoke */}
                            {lic.isActive ? (
                              <button
                                onClick={() => handleAction(lic.key, "revoke")}
                                title="Revoke Node Access"
                                className="px-2.5 py-1 rounded-lg bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/50 text-[11px] font-bold transition cursor-pointer"
                              >
                                Revoke
                              </button>
                            ) : (
                              <button
                                onClick={() => handleAction(lic.key, "activate")}
                                title="Restore Node Access"
                                className="px-2.5 py-1 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/50 text-[11px] font-bold transition cursor-pointer"
                              >
                                Enable
                              </button>
                            )}

                            {/* Extend +30 Days */}
                            <button
                              onClick={() => handleAction(lic.key, "extend", 30)}
                              title="Extend subscription by +30 Days"
                              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-bold transition cursor-pointer"
                            >
                              +30d
                            </button>

                            {/* Unlock HWID */}
                            {lic.hardwareId && (
                              <button
                                onClick={() => handleAction(lic.key, "reset_hwid")}
                                title="Unlock machine binding so client can switch PC"
                                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
                              >
                                <RotateCcw className="w-3.5 h-3.5" />
                              </button>
                            )}

                            {/* Delete */}
                            <button
                              onClick={() => {
                                if (confirm(`Permanently delete license for ${lic.clientName}?`)) {
                                  handleAction(lic.key, "delete");
                                }
                              }}
                              title="Permanently Delete License"
                              className="p-1.5 rounded-lg hover:bg-red-950/80 text-slate-500 hover:text-red-400 transition cursor-pointer"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
