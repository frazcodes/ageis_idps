"use client";

import React, { useState, useEffect, useCallback } from "react";
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
  const [loginUsername, setLoginUsername] = useState<string>("");
  const [loginPassword, setLoginPassword] = useState<string>("");
  const [loginError, setLoginError] = useState<string>("");
  const [loginLoading, setLoginLoading] = useState<boolean>(false);

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

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    setLoginLoading(true);

    setTimeout(() => {
      const trimmedUser = loginUsername.trim().toLowerCase();
      const trimmedPass = loginPassword.trim();

      if (
        (trimmedUser === DEFAULT_ADMIN_USER || trimmedUser === "frazcodes") &&
        (trimmedPass === DEFAULT_ADMIN_PASS || trimmedPass === "aegis2026")
      ) {
        setIsAuthenticated(true);
        try {
          localStorage.setItem(AUTH_STORAGE_KEY, "authenticated");
        } catch {
          // ignore
        }
      } else {
        setLoginError("Invalid Administrator credentials. Please verify username and master key.");
      }
      setLoginLoading(false);
    }, 400);
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
  };

  const handleCreateLicense = async (e: React.FormEvent) => {
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
      }
    } catch (err) {
      console.error("Failed creating license:", err);
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
    } else {
      setCopiedSummary(true);
      setTimeout(() => setCopiedSummary(false), 2000);
    }
  };

  const calculateDays = (expiresAt: string) => {
    const diff = new Date(expiresAt).getTime() - Date.now();
    return Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
  };

  const filteredLicenses = licenses.filter((lic) => {
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
  // VIEW 1: Master Admin Authentication Screen (Glassmorphism)
  // ──────────────────────────────────────────────────────────────────────────
  if (authChecking) {
    return (
      <div className="min-h-screen bg-[#030712] flex items-center justify-center">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#030712] text-slate-100 flex items-center justify-center p-4 relative overflow-hidden selection:bg-cyan-500 selection:text-black">
        {/* Ambient Glowing Glass Orbs */}
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-600/15 rounded-full blur-[120px] pointer-events-none -translate-x-1/2 -translate-y-1/2" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-600/15 rounded-full blur-[140px] pointer-events-none translate-x-1/2 translate-y-1/2" />
        <div className="absolute top-1/2 left-1/2 w-64 h-64 bg-indigo-500/10 rounded-full blur-[100px] pointer-events-none -translate-x-1/2 -translate-y-1/2" />

        {/* Master Admin Glassmorphism Card */}
        <div className="w-full max-w-md relative z-10 backdrop-blur-2xl bg-slate-900/70 border border-slate-700/60 rounded-3xl p-8 sm:p-10 shadow-2xl shadow-cyan-950/40">
          {/* Top Badge & Glow Icon */}
          <div className="flex flex-col items-center text-center mb-8">
            <div className="relative mb-4">
              <div className="absolute inset-0 bg-cyan-500/30 rounded-2xl blur-lg animate-pulse"></div>
              <div className="relative w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-500/20 via-blue-600/30 to-blue-900/40 border border-cyan-400/40 flex items-center justify-center shadow-xl">
                <Shield className="w-8 h-8 text-cyan-400" />
              </div>
            </div>

            <h1 className="text-2xl font-black tracking-wider text-slate-100 mb-1">
              AEGIS IDPS
            </h1>
            <p className="text-xs font-semibold uppercase tracking-widest text-cyan-400">
              Cloud License Operations Portal
            </p>
            <div className="mt-3 inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700/60 text-[11px] text-slate-400 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>RESTRICTED MASTER CONSOLE</span>
            </div>
          </div>

          {/* Login Form */}
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                Administrator Username
              </label>
              <div className="relative">
                <Users className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  type="text"
                  required
                  placeholder="Enter administrator ID"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  className="w-full bg-slate-950/70 border border-slate-700/70 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 outline-none transition"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                Master Security Key / Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full bg-slate-950/70 border border-slate-700/70 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 outline-none transition"
                />
              </div>
            </div>

            {loginError && (
              <div className="p-3 rounded-xl bg-red-950/60 border border-red-800/50 text-red-300 text-xs flex items-center space-x-2 animate-in fade-in">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{loginError}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loginLoading}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-black text-sm tracking-wider uppercase shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30 transition-all duration-200 flex items-center justify-center space-x-2 mt-6 cursor-pointer"
            >
              {loginLoading ? (
                <div className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></div>
              ) : (
                <>
                  <Key className="w-4 h-4" />
                  <span>Authenticate Operator</span>
                </>
              )}
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
              className="text-[11px] text-cyan-400/80 hover:text-cyan-300 underline underline-offset-2 transition"
            >
              Click here to pre-fill Master Admin Credentials
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // VIEW 2: Ultra-Premium Glassmorphism Operations Dashboard
  // ──────────────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#030712] text-slate-100 p-4 sm:p-6 md:p-8 relative overflow-hidden selection:bg-cyan-500 selection:text-black">
      {/* Background Ambient Radial Glows */}
      <div className="absolute top-0 left-1/4 w-[600px] h-[400px] bg-cyan-600/10 rounded-full blur-[140px] pointer-events-none -translate-y-1/2" />
      <div className="absolute top-1/3 right-0 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[160px] pointer-events-none translate-x-1/3" />
      <div className="absolute bottom-0 left-1/3 w-[600px] h-[400px] bg-indigo-600/10 rounded-full blur-[140px] pointer-events-none translate-y-1/3" />

      <div className="max-w-7xl mx-auto space-y-8 relative z-10">
        {/* ── Top Navigation Bar ─────────────────────────────────────────────── */}
        <header className="backdrop-blur-xl bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4 sm:px-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4 shadow-xl shadow-cyan-950/10">
          <div className="flex items-center space-x-3.5">
            <div className="w-11 h-11 rounded-xl bg-gradient-to-tr from-cyan-500/20 via-blue-600/30 to-blue-900/40 border border-cyan-400/30 flex items-center justify-center shadow-lg shadow-cyan-500/10 shrink-0">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center space-x-2.5">
                <h1 className="text-lg md:text-xl font-black tracking-wider text-slate-100">
                  AEGIS IDPS
                </h1>
                <span className="px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider rounded-md bg-cyan-950/80 text-cyan-400 border border-cyan-700/50">
                  CLOUD LICENSE PORTAL
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Centralized SOC node licensing, hardware lock enforcement & subscription management
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Live Cloud Status */}
            <div className="flex items-center space-x-2 text-xs font-mono bg-slate-950/80 border border-slate-800 px-3 py-1.5 rounded-xl text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>FIREBASE CLOUD: LIVE</span>
            </div>

            {/* Manual Refresh Button */}
            <button
              onClick={handleManualRefresh}
              disabled={refreshing}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/60 text-xs text-slate-200 font-semibold transition"
              title="Refresh Licenses"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
              <span>Refresh</span>
            </button>

            {/* Master Admin Operator Pill */}
            <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-cyan-950/40 border border-cyan-700/40 text-xs text-cyan-300 font-medium">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Master Admin</span>
            </div>

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-red-950/40 hover:bg-red-900/50 border border-red-800/40 text-xs text-red-300 font-semibold transition cursor-pointer"
              title="Sign Out"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>
          </div>
        </header>

        {/* ── Stats Metric Cards (Glassmorphism) ─────────────────────────────── */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="backdrop-blur-xl bg-slate-900/60 border border-slate-800/80 hover:border-cyan-500/40 transition-all duration-300 p-5 rounded-2xl shadow-lg group">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider">Total Issued</span>
              <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Key className="w-4 h-4 text-cyan-400" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight text-slate-100">{stats.total}</div>
            <p className="text-[11px] text-slate-400 mt-1">Cryptographic node keys</p>
          </div>

          <div className="backdrop-blur-xl bg-slate-900/60 border border-slate-800/80 hover:border-emerald-500/40 transition-all duration-300 p-5 rounded-2xl shadow-lg group">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider">Active Deployments</span>
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight text-emerald-400">{stats.active}</div>
            <p className="text-[11px] text-slate-400 mt-1">Operational IDPS instances</p>
          </div>

          <div className="backdrop-blur-xl bg-slate-900/60 border border-slate-800/80 hover:border-amber-500/40 transition-all duration-300 p-5 rounded-2xl shadow-lg group">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider">Expiring Soon</span>
              <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Clock className="w-4 h-4 text-amber-400" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight text-amber-400">{stats.expiringSoon}</div>
            <p className="text-[11px] text-slate-400 mt-1">Under 7 days remaining</p>
          </div>

          <div className="backdrop-blur-xl bg-slate-900/60 border border-slate-800/80 hover:border-blue-500/40 transition-all duration-300 p-5 rounded-2xl shadow-lg group">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider">Bound Machines</span>
              <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center group-hover:scale-110 transition-transform">
                <Laptop className="w-4 h-4 text-blue-400" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight text-blue-400">{stats.connectedDevices}</div>
            <p className="text-[11px] text-slate-400 mt-1">Locked Hardware ID fingerprints</p>
          </div>
        </section>

        {/* ── Issue License Form (Glassmorphism Card) ────────────────────────── */}
        <section className="backdrop-blur-2xl bg-gradient-to-b from-slate-900/80 to-slate-950/80 border border-slate-800/90 rounded-3xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

          <div className="flex items-center space-x-3 mb-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Key className="w-4 h-4 text-cyan-400" />
            </div>
            <h2 className="text-base sm:text-lg font-black text-slate-100 tracking-wide uppercase">
              GENERATE NEW CLIENT LICENSE
            </h2>
          </div>
          <p className="text-xs text-slate-400 mb-6 max-w-2xl">
            Register a new client node. Clicking auto-generate generates an authenticated 16-character key bound to their organization and chosen validity period, instantly saved to Firebase Firestore.
          </p>

          <form onSubmit={handleCreateLicense} className="space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Field 1: Client Name */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Client Full Name <span className="text-cyan-400">*</span>
                </label>
                <div className="relative">
                  <Users className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    required
                    placeholder="e.g. Ahmad Faraz"
                    value={clientName}
                    onChange={(e) => setClientName(e.target.value)}
                    className="w-full bg-slate-950/70 border border-slate-700/70 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 2: Organization */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Organization / Lab / Institution
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    placeholder="e.g. Aegis Cyber Defense Lab"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    className="w-full bg-slate-950/70 border border-slate-700/70 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 3: Contact Email */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Contact Email / Phone
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    placeholder="e.g. operator@domain.com"
                    value={contactEmail}
                    onChange={(e) => setContactEmail(e.target.value)}
                    className="w-full bg-slate-950/70 border border-slate-700/70 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 4: Plan / Duration */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  License Validity Plan
                </label>
                <div className="relative">
                  <Calendar className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <select
                    value={plan}
                    onChange={(e) => setPlan(e.target.value as LicensePlan)}
                    className="w-full bg-slate-950/70 border border-slate-700/70 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 outline-none transition cursor-pointer"
                  >
                    <option value="7_days">7 Days (Short Evaluation Trial)</option>
                    <option value="30_days">30 Days (Standard Monthly Trial)</option>
                    <option value="90_days">90 Days (Quarterly License)</option>
                    <option value="1_year">1 Year (Annual Full Subscription)</option>
                    <option value="lifetime">Lifetime Access (Perpetual)</option>
                  </select>
                </div>
              </div>

              {/* Field 5: Max Allowed Devices */}
              <div>
                <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Allowed Workstations (HWID Lock)
                </label>
                <div className="relative">
                  <Laptop className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <select
                    value={maxDevices}
                    onChange={(e) => setMaxDevices(parseInt(e.target.value, 10))}
                    className="w-full bg-slate-950/70 border border-slate-700/70 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 outline-none transition cursor-pointer"
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
                  <FileText className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
                  <input
                    type="text"
                    placeholder="e.g. FYP External Evaluator / Node #01"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    className="w-full bg-slate-950/70 border border-slate-700/70 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>
            </div>

            {/* Action Submit Button */}
            <div className="pt-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <button
                type="submit"
                disabled={generating || !clientName.trim()}
                className="flex items-center justify-center space-x-2 px-7 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-black text-sm tracking-wide shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30 transition cursor-pointer"
              >
                <Key className="w-4 h-4" />
                <span>{generating ? "Registering on Cloud..." : "⚡ Auto-Generate & Issue License Key"}</span>
              </button>

              <span className="text-xs text-slate-500 font-mono">
                Direct OAuth2 Sync to Firebase Firestore Project: aegis-license-system
              </span>
            </div>
          </form>

          {/* ── Generated Key Result Banner (Glassmorphism Callout) ─────────── */}
          {recentlyGenerated && (
            <div className="mt-6 p-5 rounded-2xl bg-cyan-950/40 border border-cyan-500/50 animate-in fade-in slide-in-from-top-2 duration-300 shadow-xl shadow-cyan-950/30">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2 mb-1.5">
                    <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-black text-cyan-300 uppercase tracking-widest">
                      New License Issued Successfully
                    </span>
                  </div>
                  <div className="text-xl sm:text-2xl font-mono font-black text-cyan-200 tracking-wider">
                    {recentlyGenerated.key}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    Client: <strong className="text-slate-200">{recentlyGenerated.clientName}</strong> ({recentlyGenerated.organization || "Direct Client"}) · Valid until: {new Date(recentlyGenerated.expiresAt).toLocaleDateString()}
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => copyToClipboard(recentlyGenerated.key, "key")}
                    className="flex items-center space-x-1.5 px-4 py-2.5 rounded-xl bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-black text-xs transition shadow-md shadow-cyan-400/20 cursor-pointer"
                  >
                    {copiedKey ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey ? "Copied!" : "Copy Key"}</span>
                  </button>

                  <button
                    onClick={() => {
                      const text = `AEGIS IDPS ACTIVATION CREDENTIALS:\nClient: ${recentlyGenerated.clientName}\nLicense Key: ${recentlyGenerated.key}\nExpiry Date: ${new Date(recentlyGenerated.expiresAt).toLocaleDateString()}\n\nInstructions: Launch the Aegis IDPS application on your PC, paste this 16-character key into the unified login card, and click 'AUTHORIZE & ENTER CONSOLE'.`;
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
        <section className="backdrop-blur-2xl bg-slate-900/60 border border-slate-800/80 rounded-3xl p-6 sm:p-8 shadow-2xl">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h2 className="text-base sm:text-lg font-black text-slate-100 tracking-wide uppercase flex items-center space-x-2">
                <span>REGISTERED CLIENT NODES</span>
                <span className="text-xs font-normal text-slate-400 font-mono">({filteredLicenses.length} matching)</span>
              </h2>
              <p className="text-xs text-slate-400">
                Live monitoring of issued licenses, bound hardware fingerprints, and instantaneous access control.
              </p>
            </div>

            {/* Filter and Search Bar */}
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search client, key, HWID..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-slate-950/80 border border-slate-700/80 focus:border-cyan-400 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 outline-none w-56 transition"
                />
              </div>

              <div className="flex rounded-xl bg-slate-950/80 p-1 border border-slate-800 text-xs">
                {(["all", "active", "expiring", "revoked"] as const).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setStatusFilter(filter)}
                    className={`px-3 py-1 rounded-lg font-semibold capitalize transition cursor-pointer ${
                      statusFilter === filter
                        ? "bg-cyan-500 text-slate-950 shadow-sm"
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
          <div className="overflow-x-auto rounded-2xl border border-slate-800/80 bg-slate-950/50">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/90 text-slate-400 uppercase text-[11px] font-bold tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-4">Client & Organization</th>
                  <th className="py-3.5 px-4">License Key</th>
                  <th className="py-3.5 px-4">Remaining</th>
                  <th className="py-3.5 px-4">Expiry Date</th>
                  <th className="py-3.5 px-4">Bound HWID</th>
                  <th className="py-3.5 px-4">Status</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
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
                  filteredLicenses.map((lic) => {
                    const daysLeft = calculateDays(lic.expiresAt);
                    const isExpired = new Date(lic.expiresAt).getTime() <= Date.now();

                    return (
                      <tr key={lic.key} className="hover:bg-slate-800/30 transition">
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
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-950/80 text-red-400 border border-red-800/40">
                              BLOCKED
                            </span>
                          ) : isExpired ? (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-950/80 text-red-400 border border-red-800/40">
                              EXPIRED
                            </span>
                          ) : daysLeft <= 7 ? (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-950/80 text-amber-400 border border-amber-800/40">
                              ⚠️ {daysLeft} Days
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/40">
                              🟢 {daysLeft} Days
                            </span>
                          )}
                        </td>

                        {/* Expiry Date */}
                        <td className="py-3.5 px-4 text-slate-400 font-mono">
                          {new Date(lic.expiresAt).toLocaleDateString()}
                        </td>

                        {/* Bound Machine */}
                        <td className="py-3.5 px-4">
                          {lic.hardwareId ? (
                            <div className="flex items-center space-x-1.5 text-slate-300">
                              <Laptop className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                              <span className="font-mono text-[11px]" title={lic.hardwareId}>
                                {lic.machineHostname || lic.hardwareId.substring(0, 14) + "..."}
                              </span>
                            </div>
                          ) : (
                            <span className="text-slate-500 italic text-[11px]">
                              Waiting for activation...
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
                                <RotateCcw className="w-3 h-3" />
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
                              <Trash2 className="w-3 h-3" />
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
