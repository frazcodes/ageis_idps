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
} from "lucide-react";
import { License, LicensePlan, LicenseStats } from "@/lib/types";

export default function LicensePortalDashboard() {
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

  // Form State
  const [clientName, setClientName] = useState("");
  const [organization, setOrganization] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [plan, setPlan] = useState<LicensePlan>("30_days");
  const [maxDevices, setMaxDevices] = useState(1);
  const [notes, setNotes] = useState("");
  const [generating, setGenerating] = useState(false);

  // Success Generated Box State
  const [recentlyGenerated, setRecentlyGenerated] = useState<License | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedSummary, setCopiedSummary] = useState(false);

  // Search & Filter
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "expiring" | "revoked">("all");

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
    fetchLicenses();
  }, [fetchLicenses]);

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
        // Clear form fields
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

  // Helper calculation for days remaining
  const calculateDays = (expiresAt: string) => {
    const diff = new Date(expiresAt).getTime() - Date.now();
    return Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
  };

  // Filtered list
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

  return (
    <div className="min-h-screen bg-[#030712] text-slate-100 p-4 md:p-8">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* ── Top Header ──────────────────────────────────────────────────────── */}
        <header className="flex flex-col md:flex-row md:items-center md:justify-between pb-6 border-b border-slate-800/80 gap-4">
          <div className="flex items-center space-x-3">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 via-blue-600/30 to-blue-900/40 border border-cyan-500/30 flex items-center justify-center shadow-lg shadow-cyan-500/10">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl md:text-2xl font-black tracking-wider text-slate-100">
                  AEGIS IDPS
                </h1>
                <span className="px-2 py-0.5 text-xs font-semibold uppercase tracking-wider rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  CLOUD LICENSE PORTAL
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Centralized SOC client licensing, hardware lock binding, and subscription enforcement
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2 text-xs font-mono bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg text-slate-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>FIREBASE CLOUD SYNC: ACTIVE</span>
            </div>

            <button
              onClick={handleManualRefresh}
              disabled={refreshing}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 font-medium transition"
              title="Refresh Licenses"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
              <span>Refresh</span>
            </button>
          </div>
        </header>

        {/* ── Stats Row ───────────────────────────────────────────────────────── */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 shadow-md">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Total Issued</span>
              <Key className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold tracking-tight text-slate-100">{stats.total}</div>
            <p className="text-[11px] text-slate-400 mt-1">Registered license keys</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 shadow-md">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Active Clients</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold tracking-tight text-emerald-400">{stats.active}</div>
            <p className="text-[11px] text-slate-400 mt-1">Operational IDPS instances</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 shadow-md">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Expiring Soon</span>
              <Clock className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold tracking-tight text-amber-400">{stats.expiringSoon}</div>
            <p className="text-[11px] text-slate-400 mt-1">Less than 7 days remaining</p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 shadow-md">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-medium uppercase tracking-wider">Connected PCs</span>
              <Laptop className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-bold tracking-tight text-blue-400">{stats.connectedDevices}</div>
            <p className="text-[11px] text-slate-400 mt-1">Bound to Hardware IDs</p>
          </div>
        </section>

        {/* ── DEDICATED FORM: Issue New License (Direct on Page, No Popups!) ─── */}
        <section className="rounded-2xl bg-gradient-to-b from-slate-900/90 to-[#0A0F1D] border border-cyan-900/40 p-6 shadow-xl relative overflow-hidden">
          <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

          <div className="flex items-center space-x-2.5 mb-2">
            <Key className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-bold text-slate-100 tracking-wide">
              GENERATE NEW CLIENT LICENSE
            </h2>
          </div>
          <p className="text-xs text-slate-400 mb-6 max-w-2xl">
            Fill in the client details below. Clicking auto-generate creates a cryptographically unique 16-character key bound to their organization and chosen validity period.
          </p>

          <form onSubmit={handleCreateLicense} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Field 1: Client Name */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Client Full Name <span className="text-cyan-400">*</span>
                </label>
                <div className="relative">
                  <Users className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    required
                    placeholder="e.g. Muhammad Ali"
                    value={clientName}
                    onChange={(e) => setClientName(e.target.value)}
                    className="w-full bg-[#030712] border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 2: Organization */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Organization / University / Lab
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="e.g. Cyber Security Lab - FAST"
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    className="w-full bg-[#030712] border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 3: Contact Email / Phone */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Contact Email / Phone
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="e.g. client@organization.com"
                    value={contactEmail}
                    onChange={(e) => setContactEmail(e.target.value)}
                    className="w-full bg-[#030712] border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 4: Plan / Duration */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  License Validity Plan
                </label>
                <div className="relative">
                  <Calendar className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <select
                    value={plan}
                    onChange={(e) => setPlan(e.target.value as LicensePlan)}
                    className="w-full bg-[#030712] border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 outline-none transition cursor-pointer"
                  >
                    <option value="7_days">7 Days (Short Pilot / Evaluation)</option>
                    <option value="30_days">30 Days (Standard Monthly Trial)</option>
                    <option value="90_days">90 Days (Quarterly License)</option>
                    <option value="1_year">1 Year (Annual Full Subscription)</option>
                    <option value="lifetime">Lifetime Access (Perpetual)</option>
                  </select>
                </div>
              </div>

              {/* Field 5: Max Allowed Devices */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Allowed Machines (Hardware Lock)
                </label>
                <div className="relative">
                  <Laptop className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <select
                    value={maxDevices}
                    onChange={(e) => setMaxDevices(parseInt(e.target.value, 10))}
                    className="w-full bg-[#030712] border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 outline-none transition cursor-pointer"
                  >
                    <option value={1}>1 Machine (Single Workstation Lock)</option>
                    <option value={3}>3 Machines (Small Lab Cluster)</option>
                    <option value={5}>5 Machines (SOC Team Cluster)</option>
                  </select>
                </div>
              </div>

              {/* Field 6: Internal Notes */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Admin Internal Notes / Reference
                </label>
                <div className="relative">
                  <FileText className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="e.g. FYP External Evaluator / Batch 2026"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    className="w-full bg-[#030712] border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none transition"
                  />
                </div>
              </div>
            </div>

            {/* Action Submit Button */}
            <div className="pt-2 flex items-center justify-between">
              <button
                type="submit"
                disabled={generating || !clientName.trim()}
                className="flex items-center space-x-2 px-6 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-bold text-sm shadow-lg shadow-cyan-600/20 transition cursor-pointer"
              >
                <Key className="w-4 h-4" />
                <span>{generating ? "Generating License..." : "⚡ Auto-Generate & Issue License Key"}</span>
              </button>

              <span className="text-xs text-slate-500 hidden sm:inline">
                Instant registration on Firebase Firestore cloud
              </span>
            </div>
          </form>

          {/* ── Generated Key Result Banner ─────────────────────────────────── */}
          {recentlyGenerated && (
            <div className="mt-6 p-4 rounded-xl bg-cyan-950/40 border border-cyan-500/40 animate-in fade-in slide-in-from-top-2 duration-300">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <div className="flex items-center space-x-2 mb-1">
                    <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold text-cyan-300 uppercase tracking-wider">
                      License Successfully Generated!
                    </span>
                  </div>
                  <div className="text-lg md:text-xl font-mono font-black text-cyan-200 tracking-wider">
                    {recentlyGenerated.key}
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5">
                    Assigned to: <strong className="text-slate-200">{recentlyGenerated.clientName}</strong> ({recentlyGenerated.organization}) · Expires: {new Date(recentlyGenerated.expiresAt).toLocaleDateString()}
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => copyToClipboard(recentlyGenerated.key, "key")}
                    className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-900 font-bold text-xs transition"
                  >
                    {copiedKey ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey ? "Copied!" : "Copy Key"}</span>
                  </button>

                  <button
                    onClick={() => {
                      const text = `AEGIS IDPS ACTIVATION DETAILS:\nClient: ${recentlyGenerated.clientName}\nLicense Key: ${recentlyGenerated.key}\nExpiry: ${new Date(recentlyGenerated.expiresAt).toLocaleDateString()}\n\nInstructions: Enter this 16-character key when launching Aegis IDPS on your PC.`;
                      copyToClipboard(text, "summary");
                    }}
                    className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition"
                  >
                    {copiedSummary ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSummary ? "Copied Summary!" : "Copy Client Message"}</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ── Active Licenses Management Table ───────────────────────────────── */}
        <section className="rounded-2xl bg-slate-900/40 border border-slate-800 p-6 shadow-xl">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h2 className="text-lg font-bold text-slate-100 tracking-wide flex items-center space-x-2">
                <span>ACTIVE CLIENT LICENSES</span>
                <span className="text-xs font-normal text-slate-400">({filteredLicenses.length} matching)</span>
              </h2>
              <p className="text-xs text-slate-400">
                Monitor live expiration dates, bound hardware machines, and control client access instantly.
              </p>
            </div>

            {/* Filter and Search Bar */}
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Search client, key, machine..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-[#030712] border border-slate-800 focus:border-cyan-500 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-600 outline-none w-52 transition"
                />
              </div>

              <div className="flex rounded-lg bg-slate-950 p-1 border border-slate-800 text-xs">
                {(["all", "active", "expiring", "revoked"] as const).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => setStatusFilter(filter)}
                    className={`px-2.5 py-1 rounded font-medium capitalize transition ${
                      statusFilter === filter
                        ? "bg-cyan-600 text-slate-900 font-bold"
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
          <div className="overflow-x-auto rounded-xl border border-slate-800/80 bg-[#020617]">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[11px] font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Client & Organization</th>
                  <th className="py-3 px-4">License Key</th>
                  <th className="py-3 px-4">Remaining</th>
                  <th className="py-3 px-4">Expiry Date</th>
                  <th className="py-3 px-4">Bound PC (HWID)</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {loading ? (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-slate-500">
                      Loading license records from cloud...
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
                      <tr key={lic.key} className="hover:bg-slate-900/40 transition">
                        {/* Client Name & Org */}
                        <td className="py-3.5 px-4">
                          <div className="font-semibold text-slate-100">{lic.clientName}</div>
                          <div className="text-[11px] text-slate-400">{lic.organization}</div>
                          {lic.contactEmail && (
                            <div className="text-[10px] text-slate-500">{lic.contactEmail}</div>
                          )}
                        </td>

                        {/* License Key */}
                        <td className="py-3.5 px-4 font-mono font-bold text-cyan-300">
                          <div className="flex items-center space-x-1.5">
                            <span>{lic.key}</span>
                            <button
                              onClick={() => copyToClipboard(lic.key, "key")}
                              title="Copy Key"
                              className="text-slate-500 hover:text-cyan-400 transition"
                            >
                              <Copy className="w-3 h-3" />
                            </button>
                          </div>
                        </td>

                        {/* Remaining Days Badge */}
                        <td className="py-3.5 px-4">
                          {!lic.isActive ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950/80 text-red-400 border border-red-800/40">
                              BLOCKED
                            </span>
                          ) : isExpired ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950/80 text-red-400 border border-red-800/40">
                              EXPIRED
                            </span>
                          ) : daysLeft <= 7 ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-400 border border-amber-800/40">
                              ⚠️ {daysLeft} Days
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800/40">
                              🟢 {daysLeft} Days
                            </span>
                          )}
                        </td>

                        {/* Expiry Date */}
                        <td className="py-3.5 px-4 text-slate-400">
                          {new Date(lic.expiresAt).toLocaleDateString()}
                        </td>

                        {/* Bound Machine */}
                        <td className="py-3.5 px-4">
                          {lic.hardwareId ? (
                            <div className="flex items-center space-x-1.5 text-slate-300">
                              <Laptop className="w-3.5 h-3.5 text-blue-400" />
                              <span className="font-mono text-[11px]" title={lic.hardwareId}>
                                {lic.machineHostname || lic.hardwareId.substring(0, 14) + "..."}
                              </span>
                            </div>
                          ) : (
                            <span className="text-slate-500 italic text-[11px]">
                              Waiting for 1st launch...
                            </span>
                          )}
                        </td>

                        {/* Status */}
                        <td className="py-3.5 px-4">
                          {!lic.isActive ? (
                            <span className="inline-flex items-center space-x-1 text-red-400 font-semibold">
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Revoked</span>
                            </span>
                          ) : isExpired ? (
                            <span className="inline-flex items-center space-x-1 text-red-400 font-semibold">
                              <AlertTriangle className="w-3.5 h-3.5" />
                              <span>Expired</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 text-emerald-400 font-semibold">
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
                                title="Revoke Client Access"
                                className="px-2 py-1 rounded bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/50 text-[11px] font-semibold transition"
                              >
                                Revoke
                              </button>
                            ) : (
                              <button
                                onClick={() => handleAction(lic.key, "activate")}
                                title="Restore Client Access"
                                className="px-2 py-1 rounded bg-emerald-950/60 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/50 text-[11px] font-semibold transition"
                              >
                                Enable
                              </button>
                            )}

                            {/* Extend +30 Days */}
                            <button
                              onClick={() => handleAction(lic.key, "extend", 30)}
                              title="Extend license by +30 Days"
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-semibold transition"
                            >
                              +30d
                            </button>

                            {/* Unlock HWID */}
                            {lic.hardwareId && (
                              <button
                                onClick={() => handleAction(lic.key, "reset_hwid")}
                                title="Unlock machine binding so client can switch PC"
                                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
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
                              className="p-1 rounded hover:bg-red-950 text-slate-500 hover:text-red-400 transition"
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

