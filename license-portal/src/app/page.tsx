"use client";

import React, { useState, useEffect, useCallback, useRef, FormEvent } from "react";
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
  Eye,
  EyeOff,
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
  Sun,
  Moon,
  Palette,
  Volume2,
  VolumeX,
} from "lucide-react";
import { License, LicensePlan, LicenseStats } from "@/lib/types";

// Master Admin Access Credentials
const DEFAULT_ADMIN_USER = "admin";
const DEFAULT_ADMIN_PASS = "aegis@2026";
const AUTH_STORAGE_KEY = "aegis_cloud_admin_auth";
const THEME_STORAGE_KEY = "aegis_theme_mode";

type ThemeMode = "dark" | "blue" | "light";

// ── Interactive Animated Cyber Canvas Background Component ─────────────────
function CyberBackgroundCanvas({ theme }: { theme: ThemeMode }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener("resize", handleResize);

    // Nodes constellation
    const nodeCount = Math.min(55, Math.floor((width * height) / 22000));
    const nodes: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      color: string;
    }> = [];

    const darkColors = ["#00F0FF", "#38BDF8", "#10B981", "#818CF8", "#06B6D4"];
    const blueColors = ["#60A5FA", "#38BDF8", "#34D399", "#818CF8", "#93C5FD"];
    const lightColors = ["#0284C7", "#2563EB", "#059669", "#4F46E5", "#0891B2"];

    const activeColors = theme === "light" ? lightColors : theme === "blue" ? blueColors : darkColors;

    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.55,
        vy: (Math.random() - 0.5) * 0.55,
        radius: Math.random() * 2 + 1,
        color: activeColors[Math.floor(Math.random() * activeColors.length)],
      });
    }

    // Floating cyber data tokens
    const tokens = [
      "0xAE71_OK",
      "AEGIS_SOC_V2",
      "RSA256_ACTIVE",
      "FIREBASE_SYNC",
      "NODE_HWID_LOCK",
      "TLS_1.3_ENCRYPTED",
      "SHA256_FINGERPRINT",
      "LEVEL_5_CLEARANCE",
      "SEC_OPS_CLUSTER",
    ];
    const floatingTokens: Array<{
      x: number;
      y: number;
      text: string;
      speed: number;
      opacity: number;
    }> = [];
    for (let i = 0; i < 10; i++) {
      floatingTokens.push({
        x: Math.random() * width,
        y: Math.random() * height,
        text: tokens[Math.floor(Math.random() * tokens.length)],
        speed: Math.random() * 0.45 + 0.2,
        opacity: Math.random() * 0.35 + 0.15,
      });
    }

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      // Draw floating cyber data stream tokens
      ctx.font = "9px 'Consolas', monospace";
      floatingTokens.forEach((token) => {
        const tokenColor =
          theme === "light"
            ? `rgba(2, 132, 199, ${token.opacity * 0.8})`
            : theme === "blue"
            ? `rgba(96, 165, 250, ${token.opacity})`
            : `rgba(0, 240, 255, ${token.opacity})`;

        ctx.fillStyle = tokenColor;
        ctx.fillText(token.text, token.x, token.y);
        token.y -= token.speed;
        if (token.y < -15) {
          token.y = height + 15;
          token.x = Math.random() * width;
        }
      });

      // Update and draw interconnected cyber nodes
      nodes.forEach((node, i) => {
        node.x += node.vx;
        node.y += node.vy;

        if (node.x < 0 || node.x > width) node.vx *= -1;
        if (node.y < 0 || node.y > height) node.vy *= -1;

        // Draw node dot
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.shadowColor = node.color;
        ctx.shadowBlur = theme === "light" ? 2 : 5;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Draw connections between nearby nodes
        for (let j = i + 1; j < nodes.length; j++) {
          const other = nodes[j];
          const dx = node.x - other.x;
          const dy = node.y - other.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 130) {
            ctx.beginPath();
            ctx.moveTo(node.x, node.y);
            ctx.lineTo(other.x, other.y);
            const alpha = (1 - dist / 130) * (theme === "light" ? 0.2 : 0.22);
            const strokeColor =
              theme === "light"
                ? `rgba(2, 132, 199, ${alpha})`
                : theme === "blue"
                ? `rgba(96, 165, 250, ${alpha})`
                : `rgba(56, 189, 248, ${alpha})`;

            ctx.strokeStyle = strokeColor;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      });

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener("resize", handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, [theme]);

  return <canvas ref={canvasRef} className="absolute inset-0 pointer-events-none z-0" />;
}

// ── Cyber Sound & Voice Synthesis System ───────────────────────────────────
function playCyberWelcomeAudio(isMuted: boolean) {
  if (isMuted) return;
  try {
    // 1. Futuristic Sci-Fi Synth Chord via Web Audio API
    const AudioContextClass =
      typeof window !== "undefined" &&
      ((window as any).AudioContext || (window as any).webkitAudioContext);
    if (AudioContextClass) {
      const audioCtx = new AudioContextClass();
      if (audioCtx.state === "suspended") {
        audioCtx.resume();
      }

      // Harmonic futuristic chord: E4, A4, C#5, E5, A5
      const chord = [329.63, 440.0, 554.37, 659.25, 880.0];
      chord.forEach((freq, idx) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();

        osc.type = "sine";
        osc.frequency.setValueAtTime(freq, audioCtx.currentTime + idx * 0.07);

        gain.gain.setValueAtTime(0.0001, audioCtx.currentTime + idx * 0.07);
        gain.gain.exponentialRampToValueAtTime(0.12, audioCtx.currentTime + idx * 0.07 + 0.04);
        gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + idx * 0.07 + 1.2);

        osc.connect(gain);
        gain.connect(audioCtx.destination);

        osc.start(audioCtx.currentTime + idx * 0.07);
        osc.stop(audioCtx.currentTime + idx * 0.07 + 1.3);
      });
    }

    // 2. Cyber AI Voice via Web Speech API
    if (typeof window !== "undefined" && "speechSynthesis" in window) {
      window.speechSynthesis.cancel();
      const utterance = new SpeechSynthesisUtterance("Welcome to Aegis. Master access granted.");
      utterance.rate = 0.92;
      utterance.pitch = 1.05;
      utterance.volume = 1.0;

      const voices = window.speechSynthesis.getVoices();
      const preferred = voices.find(
        (v) =>
          v.lang.startsWith("en") &&
          (v.name.includes("Google") ||
            v.name.includes("Natural") ||
            v.name.includes("Zira") ||
            v.name.includes("Samantha") ||
            v.name.includes("David"))
      );
      if (preferred) {
        utterance.voice = preferred;
      }

      // Slightly delay voice so ascending chime plays first
      setTimeout(() => {
        try {
          window.speechSynthesis.speak(utterance);
        } catch {
          // ignore
        }
      }, 350);
    }
  } catch (err) {
    console.warn("Audio synthesis error:", err);
  }
}

export default function LicensePortalDashboard() {
  // ── Theme State ───────────────────────────────────────────────────────────
  const [theme, setTheme] = useState<ThemeMode>("dark");
  const isLight = theme === "light";
  const [soundMuted, setSoundMuted] = useState<boolean>(false);

  // ── Authentication State ──────────────────────────────────────────────────
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [authChecking, setAuthChecking] = useState<boolean>(true);
  const [isAuthenticating, setIsAuthenticating] = useState<boolean>(false);
  const [authProgress, setAuthProgress] = useState<number>(0);
  const [authStepText, setAuthStepText] = useState<string>("");
  const [loginUsername, setLoginUsername] = useState<string>("");
  const [loginPassword, setLoginPassword] = useState<string>("");
  const [showPassword, setShowPassword] = useState<boolean>(false);
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

  const handleSetTheme = (newTheme: ThemeMode) => {
    setTheme(newTheme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, newTheme);
    } catch {
      // ignore
    }
    showToast(`Visual Theme set to ${newTheme.toUpperCase()}`, "info");
  };

  const toggleSound = () => {
    const next = !soundMuted;
    setSoundMuted(next);
    try {
      localStorage.setItem("aegis_sound_muted", String(next));
    } catch {
      // ignore
    }
    showToast(next ? "Audio & AI voice muted" : "Audio sound & AI voice activated", "info");
  };

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

  // Check stored theme and session on mount
  useEffect(() => {
    try {
      const storedTheme = localStorage.getItem(THEME_STORAGE_KEY) as ThemeMode | null;
      if (storedTheme === "dark" || storedTheme === "blue" || storedTheme === "light") {
        setTheme(storedTheme);
      }

      const storedAuth = localStorage.getItem(AUTH_STORAGE_KEY);
      if (storedAuth === "authenticated") {
        setIsAuthenticated(true);
      }

      const storedMute = localStorage.getItem("aegis_sound_muted");
      if (storedMute === "true") {
        setSoundMuted(true);
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
      setAuthProgress(18);
      setAuthStepText("[0x01] RSA-256 JWT HANDSHAKE INITIALIZING...");

      setTimeout(() => {
        setAuthProgress(48);
        setAuthStepText("[0x02] ESTABLISHING SECURE TLS LINK TO FIREBASE CLUSTER...");
      }, 400);

      setTimeout(() => {
        setAuthProgress(82);
        setAuthStepText("[0x03] DECRYPTING CLIENT HARDWARE ID VAULT...");
      }, 850);

      setTimeout(() => {
        setAuthProgress(100);
        setAuthStepText("[0x04] ACCESS GRANTED. LAUNCHING SOC COCKPIT...");
      }, 1300);

      setTimeout(() => {
        setIsAuthenticating(false);
        setIsAuthenticated(true);
        try {
          localStorage.setItem(AUTH_STORAGE_KEY, "authenticated");
        } catch {
          // ignore
        }
        playCyberWelcomeAudio(soundMuted);
        showToast("Welcome Master Operator. SOC Cockpit Initialized.", "success");
      }, 1700);
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

  // Reusable Theme Toggler Component
  const ThemeToggler = () => (
    <div
      className="flex items-center p-1 rounded-xl border shadow-inner transition-colors"
      style={{ backgroundColor: "var(--toggler-bg)", borderColor: "var(--toggler-border)" }}
    >
      <button
        type="button"
        onClick={() => handleSetTheme("dark")}
        title="Obsidian Dark Mode"
        className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
          theme === "dark"
            ? "bg-slate-900 text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.4)] border border-cyan-500/50"
            : isLight
            ? "text-slate-600 hover:text-slate-900"
            : "text-slate-400 hover:text-slate-200"
        }`}
      >
        <Moon className="w-3.5 h-3.5" />
        <span className="hidden sm:inline">Dark</span>
      </button>

      <button
        type="button"
        onClick={() => handleSetTheme("blue")}
        title="Cyber Navy Blue Mode"
        className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
          theme === "blue"
            ? "bg-blue-900 text-blue-200 shadow-[0_0_14px_rgba(59,130,246,0.5)] border border-blue-400/60"
            : isLight
            ? "text-slate-600 hover:text-slate-900"
            : "text-slate-400 hover:text-slate-200"
        }`}
      >
        <Palette className="w-3.5 h-3.5 text-blue-400" />
        <span className="hidden sm:inline">Blue</span>
      </button>

      <button
        type="button"
        onClick={() => handleSetTheme("light")}
        title="Clean Tech Light Mode"
        className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer ${
          theme === "light"
            ? "bg-white text-sky-800 shadow-md border border-sky-400 font-extrabold"
            : "text-slate-400 hover:text-slate-200"
        }`}
      >
        <Sun className="w-3.5 h-3.5 text-amber-500" />
        <span className="hidden sm:inline">Light</span>
      </button>
    </div>
  );

  // ──────────────────────────────────────────────────────────────────────────
  // VIEW 1: Master Admin Authentication Screen (Interactive Cyber Canvas + HUD)
  // ──────────────────────────────────────────────────────────────────────────
  if (authChecking) {
    return (
      <div
        className={`min-h-screen theme-${theme} flex items-center justify-center`}
        style={{ backgroundColor: "var(--bg-primary)" }}
      >
        <div className="w-10 h-10 rounded-full border-2 border-cyan-500 border-t-transparent animate-spin"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div
        className={`min-h-screen theme-${theme} cyber-grid flex items-center justify-center p-4 relative overflow-hidden transition-colors duration-300 selection:bg-cyan-500 selection:text-black`}
        style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}
      >
        {/* Hardware-accelerated Interactive Cyber Particles Canvas */}
        <CyberBackgroundCanvas theme={theme} />

        {/* Animated Cyber Scanning Laser Line */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden z-0">
          <div
            className={`w-full h-1 animate-scanline opacity-75 ${
              isLight
                ? "bg-gradient-to-r from-transparent via-sky-500/40 to-transparent"
                : "bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent"
            }`}
          ></div>
        </div>

        {/* Theme Switcher & Audio Controls Top-Right on Login Screen */}
        <div className="absolute top-4 right-4 sm:top-6 sm:right-6 z-20 flex items-center space-x-2">
          <ThemeToggler />
          <button
            type="button"
            onClick={toggleSound}
            title={soundMuted ? "Unmute AI Voice & Audio" : "Mute Sound"}
            className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-xl border text-xs font-bold transition cursor-pointer hover:border-cyan-400 shadow-inner"
            style={{
              backgroundColor: "var(--toggler-bg)",
              borderColor: "var(--toggler-border)",
              color: soundMuted ? "var(--text-tertiary)" : "var(--accent-text)",
            }}
          >
            {soundMuted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />}
            <span className="hidden sm:inline">{soundMuted ? "Muted" : "Voice"}</span>
          </button>
        </div>

        {/* Ambient Glowing Glass Orbs */}
        <div className="absolute top-1/4 left-1/4 w-[450px] h-[450px] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none -translate-x-1/2 -translate-y-1/2" />
        <div className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-blue-600/15 rounded-full blur-[160px] pointer-events-none translate-x-1/2 translate-y-1/2" />

        {/* Master Admin Glassmorphism Card */}
        <div className="w-full max-w-md relative z-10 glass-panel rounded-3xl p-7 sm:p-10 shadow-2xl backdrop-blur-3xl">
          {/* Cyber HUD Corner Brackets */}
          <div
            className={`absolute top-3 left-3 w-3.5 h-3.5 border-t-2 border-l-2 ${
              isLight ? "border-sky-500" : "border-cyan-400"
            }`}
          ></div>
          <div
            className={`absolute top-3 right-3 w-3.5 h-3.5 border-t-2 border-r-2 ${
              isLight ? "border-sky-500" : "border-cyan-400"
            }`}
          ></div>
          <div
            className={`absolute bottom-3 left-3 w-3.5 h-3.5 border-b-2 border-l-2 ${
              isLight ? "border-sky-500" : "border-cyan-400"
            }`}
          ></div>
          <div
            className={`absolute bottom-3 right-3 w-3.5 h-3.5 border-b-2 border-r-2 ${
              isLight ? "border-sky-500" : "border-cyan-400"
            }`}
          ></div>

          {/* If Currently Running Cyber Authentication Sequence */}
          {isAuthenticating ? (
            <div className="py-6 flex flex-col items-center text-center space-y-6 animate-in fade-in zoom-in-95 duration-300">
              {/* Rotating Triple Concentric HUD Reactor */}
              <div className="relative w-28 h-28 flex items-center justify-center">
                <div className="absolute inset-0 rounded-full border-2 border-dashed border-cyan-400 animate-[spin_4s_linear_infinite] opacity-80"></div>
                <div className="absolute inset-2 rounded-full border border-emerald-400/70 border-t-transparent animate-[spin_3s_linear_infinite_reverse]"></div>
                <div className="relative w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-500/30 via-emerald-500/30 to-blue-500/40 border border-cyan-300 flex items-center justify-center shadow-[0_0_30px_rgba(6,182,212,0.6)] animate-pulse">
                  <Shield className="w-8 h-8 text-cyan-200" />
                </div>
              </div>

              <div>
                <h2
                  className={`text-xl font-black tracking-widest uppercase ${
                    isLight ? "text-sky-800" : "text-cyan-400"
                  }`}
                >
                  ACCESS GRANTED
                </h2>
                <p className="text-[11px] font-mono text-emerald-600 mt-1 tracking-wider font-bold">
                  MASTER SECURITY CLEARANCE: LEVEL 5
                </p>
              </div>

              {/* Glowing Cyber Progress Bar */}
              <div className="w-full space-y-2">
                <div
                  className="w-full rounded-full h-3 overflow-hidden border p-0.5"
                  style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)" }}
                >
                  <div
                    className="bg-gradient-to-r from-cyan-500 via-emerald-400 to-sky-400 h-full rounded-full transition-all duration-300 shadow-md"
                    style={{ width: `${authProgress}%` }}
                  ></div>
                </div>
                <div className="flex justify-between text-[11px] font-mono" style={{ color: "var(--text-secondary)" }}>
                  <span className={isLight ? "text-sky-700 font-bold" : "text-cyan-400 font-bold"}>
                    {authStepText}
                  </span>
                  <span className="font-extrabold text-emerald-600">{authProgress}%</span>
                </div>
              </div>

              {/* Simulated Cyber Terminal Output */}
              <div
                className="p-3.5 rounded-xl border text-[10px] font-mono text-left w-full space-y-1.5 shadow-inner"
                style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)" }}
              >
                <div className="text-emerald-600 flex items-center space-x-1.5 font-bold">
                  <span className={isLight ? "text-sky-600" : "text-cyan-400"}>&gt;</span>
                  <span>RSA-256 JWT Signed: OK (aegis-license-system)</span>
                </div>
                <div className={isLight ? "text-sky-700 flex items-center space-x-1.5 font-semibold" : "text-cyan-400 flex items-center space-x-1.5"}>
                  <span className={isLight ? "text-sky-600" : "text-cyan-400"}>&gt;</span>
                  <span>Hardware Fingerprint Signature: VERIFIED</span>
                </div>
                <div className="flex items-center space-x-1.5 animate-pulse" style={{ color: "var(--text-tertiary)" }}>
                  <span className={isLight ? "text-sky-600" : "text-cyan-400"}>&gt;</span>
                  <span>Launching SOC Command Cockpit...</span>
                </div>
              </div>
            </div>
          ) : (
            <>
              {/* Top Badge & Glow Icon */}
              <div className="flex flex-col items-center text-center mb-6">
                <div className="relative mb-3.5">
                  <div className="absolute inset-0 bg-cyan-400/30 rounded-2xl blur-xl animate-pulse"></div>
                  <div className="relative w-14 h-14 sm:w-16 sm:h-16 rounded-2xl bg-gradient-to-tr from-cyan-500/20 via-blue-600/30 to-blue-900/40 border border-cyan-400/70 flex items-center justify-center shadow-xl shadow-cyan-500/20">
                    <Shield className="w-7 h-7 sm:w-8 sm:h-8 text-cyan-400" />
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <h1 className="text-2xl font-black tracking-wider" style={{ color: "var(--text-primary)" }}>
                    AEGIS IDPS
                  </h1>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      isLight
                        ? "bg-sky-100 text-sky-800 border border-sky-300"
                        : "bg-cyan-950 text-cyan-400 border border-cyan-700/60 shadow-[0_0_10px_rgba(6,182,212,0.3)]"
                    }`}
                  >
                    SOC v2.4
                  </span>
                </div>
                <p
                  className={`text-xs font-bold uppercase tracking-wider mt-1 ${
                    isLight ? "text-sky-700" : "text-cyan-400"
                  }`}
                >
                  Cloud License Operations Portal
                </p>
                <div
                  className="mt-3 inline-flex items-center space-x-2 px-3 py-1 rounded-full border text-[11px] font-mono"
                  style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-secondary)" }}
                >
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                  <span className="font-semibold">RESTRICTED MASTER CONSOLE</span>
                </div>
              </div>

              {/* Login Form */}
              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "var(--text-secondary)" }}>
                    Administrator ID
                  </label>
                  <div className="relative">
                    <Users className={`w-4 h-4 absolute left-3.5 top-3 ${isLight ? "text-sky-600" : "text-cyan-400"}`} />
                    <input
                      type="text"
                      required
                      placeholder="e.g. admin"
                      value={loginUsername}
                      onChange={(e: any) => setLoginUsername(e.target.value)}
                      style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                      className="w-full border focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-4 py-2.5 text-sm placeholder:text-slate-400 outline-none transition"
                    />
                  </div>
                </div>

                {/* Password field with EYE icon toggle */}
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "var(--text-secondary)" }}>
                    Master Cryptographic Passcode
                  </label>
                  <div className="relative">
                    <Lock className={`w-4 h-4 absolute left-3.5 top-3 ${isLight ? "text-sky-600" : "text-cyan-400"}`} />
                    <input
                      type={showPassword ? "text" : "password"}
                      required
                      placeholder="••••••••••••"
                      value={loginPassword}
                      onChange={(e: any) => setLoginPassword(e.target.value)}
                      style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                      className="w-full border focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-11 py-2.5 text-sm placeholder:text-slate-400 outline-none transition font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3.5 top-2.5 text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition cursor-pointer"
                      title={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {loginError && (
                  <div
                    className={`p-3 rounded-xl border text-xs flex items-center space-x-2 animate-in fade-in ${
                      isLight
                        ? "bg-red-50 border-red-300 text-red-800 font-semibold"
                        : "bg-red-950/80 border-red-500/50 text-red-300"
                    }`}
                  >
                    <AlertTriangle className="w-4 h-4 text-red-500 shrink-0" />
                    <span>{loginError}</span>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-black text-sm tracking-wider uppercase shadow-lg shadow-cyan-500/25 hover:shadow-cyan-400/40 transition-all duration-200 flex items-center justify-center space-x-2 mt-6 cursor-pointer"
                >
                  <Key className="w-4 h-4" />
                  <span>Authenticate Operator</span>
                </button>
              </form>

              {/* Demo Credentials Quick-Fill helper */}
              <div className="mt-6 pt-4 border-t border-slate-300 dark:border-slate-700/60 text-center">
                <button
                  type="button"
                  onClick={() => {
                    setLoginUsername("admin");
                    setLoginPassword("aegis@2026");
                  }}
                  className={`text-[11px] underline underline-offset-4 transition font-mono font-bold ${
                    isLight
                      ? "text-sky-700 hover:text-sky-900"
                      : "text-cyan-400 hover:text-cyan-300"
                  }`}
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
  // VIEW 2: Ultra-Premium Cyber SOC Dashboard (With Tri-Mode Toggler)
  // ──────────────────────────────────────────────────────────────────────────
  return (
    <div
      className={`min-h-screen theme-${theme} cyber-grid p-3.5 sm:p-6 md:p-8 relative overflow-hidden transition-colors duration-300 selection:bg-cyan-500 selection:text-black`}
      style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}
    >
      {/* Background Interactive Cyber Particles Canvas */}
      <CyberBackgroundCanvas theme={theme} />

      {/* Floating Interactive Toast Notification */}
      {toastMessage && (
        <div className="fixed top-5 right-5 z-50 animate-in slide-in-from-top-4 fade-in duration-300">
          <div
            className={`glass-panel px-4 py-3 rounded-2xl flex items-center space-x-3 shadow-2xl border ${
              isLight ? "border-sky-300" : "border-cyan-400/40"
            }`}
          >
            {toastMessage.type === "success" && <CheckCircle2 className="w-5 h-5 text-emerald-500 shrink-0" />}
            {toastMessage.type === "info" && <Sparkles className="w-5 h-5 text-cyan-500 shrink-0" />}
            {toastMessage.type === "warn" && <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0" />}
            <span className="text-xs font-bold" style={{ color: "var(--text-primary)" }}>
              {toastMessage.text}
            </span>
          </div>
        </div>
      )}

      {/* Background Ambient Radial Glows */}
      <div className="absolute top-0 left-1/4 w-[650px] h-[450px] bg-cyan-600/10 rounded-full blur-[150px] pointer-events-none -translate-y-1/2" />
      <div className="absolute top-1/3 right-0 w-[550px] h-[550px] bg-blue-600/10 rounded-full blur-[170px] pointer-events-none translate-x-1/3" />
      <div className="absolute bottom-0 left-1/3 w-[650px] h-[450px] bg-indigo-600/10 rounded-full blur-[150px] pointer-events-none translate-y-1/3" />

      <div className="max-w-7xl mx-auto space-y-6 sm:space-y-8 relative z-10">
        {/* ── Top Cyber HUD Bar ───────────────────────────────────────────────── */}
        <header className="glass-panel rounded-2xl p-4 sm:px-6 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center space-x-3.5">
            <div className="relative">
              <div className="absolute inset-0 bg-cyan-400/25 rounded-xl blur-md animate-pulse"></div>
              <div className="relative w-11 h-11 sm:w-12 sm:h-12 rounded-xl bg-gradient-to-tr from-cyan-500/20 via-blue-600/30 to-blue-900/40 border border-cyan-400/40 flex items-center justify-center shadow-lg shadow-cyan-500/20 shrink-0">
                <Shield className="w-5 h-5 sm:w-6 sm:h-6 text-cyan-400" />
              </div>
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-lg md:text-xl font-black tracking-wider" style={{ color: "var(--text-primary)" }}>
                  AEGIS IDPS
                </h1>
                <span
                  className={`px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider rounded-md ${
                    isLight
                      ? "bg-sky-100 text-sky-800 border border-sky-300"
                      : "bg-cyan-950 text-cyan-300 border border-cyan-700/60 shadow-[0_0_10px_rgba(6,182,212,0.3)]"
                  }`}
                >
                  CLOUD LICENSE COMMAND
                </span>
              </div>
              <p className="text-xs mt-0.5" style={{ color: "var(--text-secondary)" }}>
                Hardware ID Binding, Node Cryptographic Key Issuance &amp; Real-time Firebase Sync
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 sm:gap-3">
            {/* Live Cloud Status */}
            <div
              className="flex items-center space-x-2 text-xs font-mono border px-3 py-1.5 rounded-xl"
              style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)" }}
            >
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span className="text-emerald-600 dark:text-emerald-400 font-bold">FIREBASE: LIVE</span>
            </div>

            {/* Live Clock Pill */}
            <div
              className="hidden lg:flex items-center space-x-1.5 px-3 py-1.5 rounded-xl border text-xs font-mono font-bold"
              style={{
                backgroundColor: "var(--input-bg)",
                borderColor: "var(--input-border)",
                color: isLight ? "#0369a1" : "#22d3ee",
              }}
            >
              <Clock className="w-3.5 h-3.5" style={{ color: "var(--text-tertiary)" }} />
              <span>{utcClock}</span>
            </div>

            {/* Theme Toggler Pill */}
            <ThemeToggler />

            {/* Sound Toggle Pill */}
            <button
              type="button"
              onClick={toggleSound}
              title={soundMuted ? "Unmute AI Voice & Audio" : "Mute Sound"}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl border text-xs font-bold transition cursor-pointer hover:border-cyan-400"
              style={{
                backgroundColor: "var(--input-bg)",
                borderColor: "var(--input-border)",
                color: soundMuted ? "var(--text-tertiary)" : "var(--accent-text)",
              }}
            >
              {soundMuted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />}
              <span className="hidden sm:inline">{soundMuted ? "Muted" : "Voice"}</span>
            </button>

            {/* Manual Refresh Button */}
            <button
              onClick={handleManualRefresh}
              disabled={refreshing}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl border text-xs font-bold transition cursor-pointer hover:border-cyan-400"
              style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
              title="Refresh Licenses"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-cyan-500" : ""}`} />
              <span>Sync</span>
            </button>

            {/* Master Admin Operator Pill */}
            <div
              className={`hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-xl text-xs font-bold ${
                isLight
                  ? "bg-sky-50 border border-sky-300 text-sky-800"
                  : "bg-cyan-950/40 border border-cyan-700/50 text-cyan-400"
              }`}
            >
              <UserCheck className="w-3.5 h-3.5" />
              <span>Master Admin</span>
            </div>

            {/* Logout Button */}
            <button
              onClick={handleLogout}
              className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl text-xs font-bold transition cursor-pointer ${
                isLight
                  ? "bg-red-50 hover:bg-red-100 border border-red-300 text-red-700 shadow-sm"
                  : "bg-red-950/40 hover:bg-red-900/50 border border-red-800/50 text-red-400"
              }`}
              title="Sign Out"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Sign Out</span>
            </button>
          </div>
        </header>

        {/* ── 4 Cyber Metric HUD Cards ───────────────────────────────────────── */}
        <section className="grid grid-cols-2 lg:grid-cols-4 gap-3.5 sm:gap-4">
          {/* Card 1: Total Issued */}
          <div className="glass-panel p-4 sm:p-5 rounded-2xl group hover:border-cyan-400/80 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className={`text-xs font-bold uppercase tracking-wider ${isLight ? "text-sky-800" : "text-cyan-400"}`}>
                Total Issued
              </span>
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform ${
                  isLight ? "bg-sky-50 border border-sky-200 text-sky-700" : "bg-cyan-500/10 border border-cyan-400/30 text-cyan-400"
                }`}
              >
                <Key className="w-4 h-4" />
              </div>
            </div>
            <div className="text-2xl sm:text-3xl font-black tracking-tight" style={{ color: "var(--text-primary)" }}>
              {stats.total}
            </div>
            <p className="text-[11px] mt-1" style={{ color: "var(--text-secondary)" }}>
              Cryptographic Node Keys
            </p>
          </div>

          {/* Card 2: Active Deployments */}
          <div className="glass-panel p-4 sm:p-5 rounded-2xl group hover:border-emerald-400/80 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className={`text-xs font-bold uppercase tracking-wider ${isLight ? "text-emerald-800" : "text-emerald-400"}`}>
                Active Nodes
              </span>
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform ${
                  isLight ? "bg-emerald-50 border border-emerald-200 text-emerald-700" : "bg-emerald-500/10 border border-emerald-400/30 text-emerald-400"
                }`}
              >
                <CheckCircle2 className="w-4 h-4" />
              </div>
            </div>
            <div className={`text-2xl sm:text-3xl font-black tracking-tight ${isLight ? "text-emerald-700" : "text-emerald-400"}`}>
              {stats.active}
            </div>
            <p className="text-[11px] mt-1" style={{ color: "var(--text-secondary)" }}>
              Operational SOC Stations
            </p>
          </div>

          {/* Card 3: Expiring Soon */}
          <div className="glass-panel p-4 sm:p-5 rounded-2xl group hover:border-amber-400/80 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className={`text-xs font-bold uppercase tracking-wider ${isLight ? "text-amber-800" : "text-amber-400"}`}>
                Expiring Soon
              </span>
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform ${
                  isLight ? "bg-amber-50 border border-amber-200 text-amber-700" : "bg-amber-500/10 border border-amber-400/30 text-amber-400"
                }`}
              >
                <Clock className="w-4 h-4" />
              </div>
            </div>
            <div className={`text-2xl sm:text-3xl font-black tracking-tight ${isLight ? "text-amber-700" : "text-amber-400"}`}>
              {stats.expiringSoon}
            </div>
            <p className="text-[11px] mt-1" style={{ color: "var(--text-secondary)" }}>
              &lt; 7 Days Remaining
            </p>
          </div>

          {/* Card 4: Bound HWID Machines */}
          <div className="glass-panel p-4 sm:p-5 rounded-2xl group hover:border-indigo-400/80 transition-all">
            <div className="flex items-center justify-between mb-2">
              <span className={`text-xs font-bold uppercase tracking-wider ${isLight ? "text-indigo-800" : "text-indigo-400"}`}>
                Bound Workstations
              </span>
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform ${
                  isLight ? "bg-indigo-50 border border-indigo-200 text-indigo-700" : "bg-indigo-500/10 border border-indigo-400/30 text-indigo-400"
                }`}
              >
                <Laptop className="w-4 h-4" />
              </div>
            </div>
            <div className={`text-2xl sm:text-3xl font-black tracking-tight ${isLight ? "text-indigo-700" : "text-indigo-400"}`}>
              {stats.connectedDevices}
            </div>
            <p className="text-[11px] mt-1" style={{ color: "var(--text-secondary)" }}>
              Locked Machine HWIDs
            </p>
          </div>
        </section>

        {/* ── Key Issuance Panel (Glassmorphism Form) ────────────────────────── */}
        <section className="glass-panel rounded-3xl p-5 sm:p-8 shadow-2xl relative overflow-hidden">
          <div className="flex items-center space-x-3 mb-2">
            <div
              className={`w-9 h-9 rounded-xl flex items-center justify-center ${
                isLight
                  ? "bg-sky-100 border border-sky-300 text-sky-700"
                  : "bg-cyan-500/15 border border-cyan-400/40 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]"
              }`}
            >
              <Key className="w-5 h-5" />
            </div>
            <h2 className="text-base sm:text-lg font-black tracking-wide uppercase" style={{ color: "var(--text-primary)" }}>
              ISSUE NEW CLIENT NODE LICENSE
            </h2>
          </div>
          <p className="text-xs mb-6 max-w-2xl" style={{ color: "var(--text-secondary)" }}>
            Select duration and client identity. The system cryptographically generates a unique 16-character license key formatted in 4-character blocks, instantly synchronized with Firebase Firestore.
          </p>

          <form onSubmit={handleCreateLicense} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-5">
              {/* Field 1: Client Name */}
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "var(--text-secondary)" }}>
                  Client Full Name <span className="text-cyan-500">*</span>
                </label>
                <div className="relative">
                  <Users className={`w-4 h-4 absolute left-3.5 top-3 ${isLight ? "text-sky-600" : "text-cyan-400"}`} />
                  <input
                    type="text"
                    required
                    placeholder="e.g. Ahmad Faraz"
                    value={clientName}
                    onChange={(e: any) => setClientName(e.target.value)}
                    style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                    className="w-full border focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm placeholder:text-slate-400 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 2: Organization */}
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "var(--text-secondary)" }}>
                  Organization / Lab / Institution
                </label>
                <div className="relative">
                  <Building className={`w-4 h-4 absolute left-3.5 top-3 ${isLight ? "text-sky-600" : "text-cyan-400"}`} />
                  <input
                    type="text"
                    placeholder="e.g. Aegis Cyber Defense Lab"
                    value={organization}
                    onChange={(e: any) => setOrganization(e.target.value)}
                    style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                    className="w-full border focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm placeholder:text-slate-400 outline-none transition"
                  />
                </div>
              </div>

              {/* Field 3: Contact Email */}
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "var(--text-secondary)" }}>
                  Contact Email / Phone
                </label>
                <div className="relative">
                  <Mail className={`w-4 h-4 absolute left-3.5 top-3 ${isLight ? "text-sky-600" : "text-cyan-400"}`} />
                  <input
                    type="text"
                    placeholder="e.g. operator@domain.com"
                    value={contactEmail}
                    onChange={(e: any) => setContactEmail(e.target.value)}
                    style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                    className="w-full border focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm placeholder:text-slate-400 outline-none transition"
                  />
                </div>
              </div>
            </div>

            {/* Interactive Validity Plan Selector */}
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider mb-2.5" style={{ color: "var(--text-secondary)" }}>
                License Validity Duration
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
                {[
                  { id: "7_days", label: "7 Days", desc: "Pilot Trial" },
                  { id: "30_days", label: "30 Days", desc: "Monthly Standard" },
                  { id: "90_days", label: "90 Days", desc: "Quarterly Evaluation" },
                  { id: "1_year", label: "1 Year", desc: "Annual Enterprise" },
                  { id: "lifetime", label: "Lifetime", desc: "Perpetual License" },
                ].map((item) => {
                  const isSelected = plan === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setPlan(item.id as LicensePlan)}
                      className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                        isSelected
                          ? isLight
                            ? "bg-sky-50 border-sky-500 text-sky-950 font-black ring-2 ring-sky-300 shadow-sm"
                            : "bg-cyan-500/20 border-cyan-400 text-cyan-300 shadow-[0_0_15px_rgba(6,182,212,0.3)] font-bold"
                          : isLight
                          ? "border-slate-300 text-slate-700 hover:border-sky-400 hover:text-sky-900 bg-white"
                          : "border-slate-700/60 text-slate-400 hover:border-slate-500 hover:text-slate-200 bg-slate-900/60"
                      }`}
                    >
                      <div className="text-xs font-black">{item.label}</div>
                      <div className="text-[10px] opacity-75">{item.desc}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-5">
              {/* Field 5: Max Allowed Devices */}
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "var(--text-secondary)" }}>
                  Allowed Machines (Hardware Lock)
                </label>
                <div className="relative">
                  <Laptop className={`w-4 h-4 absolute left-3.5 top-3 ${isLight ? "text-sky-600" : "text-cyan-400"}`} />
                  <select
                    value={maxDevices}
                    onChange={(e: any) => setMaxDevices(parseInt(e.target.value, 10))}
                    style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                    className="w-full border focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm outline-none transition cursor-pointer"
                  >
                    <option value={1}>1 Machine (Single Workstation Lock)</option>
                    <option value={3}>3 Machines (Small Lab Cluster)</option>
                    <option value={5}>5 Machines (SOC Team Cluster)</option>
                  </select>
                </div>
              </div>

              {/* Field 6: Internal Notes */}
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider mb-2" style={{ color: "var(--text-secondary)" }}>
                  Operational Reference Notes
                </label>
                <div className="relative">
                  <FileText className={`w-4 h-4 absolute left-3.5 top-3 ${isLight ? "text-sky-600" : "text-cyan-400"}`} />
                  <input
                    type="text"
                    placeholder="e.g. FYP External Evaluator / Node #01"
                    value={notes}
                    onChange={(e: any) => setNotes(e.target.value)}
                    style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                    className="w-full border focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 rounded-xl pl-10 pr-3.5 py-2.5 text-sm placeholder:text-slate-400 outline-none transition"
                  />
                </div>
              </div>
            </div>

            {/* Action Submit Button */}
            <div className="pt-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <button
                type="submit"
                disabled={generating || !clientName.trim()}
                className="flex items-center justify-center space-x-2 px-8 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-black text-sm tracking-wide shadow-lg shadow-cyan-500/25 hover:shadow-cyan-400/40 transition cursor-pointer"
              >
                <Key className="w-4 h-4" />
                <span>{generating ? "Encrypting & Registering on Cloud..." : "⚡ Auto-Generate & Issue License Key"}</span>
              </button>

              <span className="text-xs font-mono" style={{ color: "var(--text-secondary)" }}>
                Auto-syncs to Firebase Firestore:{" "}
                <strong className={isLight ? "text-sky-700" : "text-cyan-400"}>aegis-license-system</strong>
              </span>
            </div>
          </form>

          {/* ── Generated Key Result Banner (Holographic Callout) ───────────── */}
          {recentlyGenerated && (
            <div
              className={`mt-8 p-5 sm:p-6 rounded-2xl border-2 animate-in fade-in slide-in-from-top-3 duration-300 relative ${
                isLight
                  ? "bg-sky-50 border-sky-400 shadow-xl"
                  : "bg-cyan-500/15 border-cyan-400 shadow-[0_0_30px_rgba(6,182,212,0.35)]"
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2 mb-1.5">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                    <span
                      className={`text-xs font-black uppercase tracking-widest ${
                        isLight ? "text-sky-900" : "text-cyan-400"
                      }`}
                    >
                      Node License Successfully Registered &amp; Encrypted
                    </span>
                  </div>
                  <div
                    className={`text-2xl sm:text-3xl font-mono font-black tracking-widest break-all ${
                      isLight ? "text-sky-900" : "text-cyan-300"
                    }`}
                  >
                    {recentlyGenerated.key}
                  </div>
                  <div className="text-xs mt-1.5" style={{ color: "var(--text-secondary)" }}>
                    Assigned: <strong style={{ color: "var(--text-primary)" }}>{recentlyGenerated.clientName}</strong> (
                    {recentlyGenerated.organization || "Direct Client"}) · Valid until:{" "}
                    {new Date(recentlyGenerated.expiresAt).toLocaleDateString()}
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2.5">
                  <button
                    onClick={() => copyToClipboard(recentlyGenerated.key, "key")}
                    className="flex items-center space-x-1.5 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-sky-600 hover:from-cyan-400 hover:to-sky-500 text-white font-black text-xs transition shadow-md cursor-pointer"
                  >
                    {copiedKey ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey ? "Copied!" : "Copy Key"}</span>
                  </button>

                  <button
                    onClick={() => {
                      const text = `AEGIS IDPS ACTIVATION CREDENTIALS:\nClient: ${recentlyGenerated.clientName}\nLicense Key: ${recentlyGenerated.key}\nExpiry Date: ${new Date(recentlyGenerated.expiresAt).toLocaleDateString()}\n\nInstructions: Launch Aegis IDPS on your PC, paste this 16-character key into the unified login card, and click 'AUTHORIZE & ENTER CONSOLE'.`;
                      copyToClipboard(text, "summary");
                    }}
                    className="flex items-center space-x-1.5 px-4 py-2.5 rounded-xl border text-xs font-bold transition cursor-pointer hover:border-cyan-500"
                    style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                  >
                    {copiedSummary ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSummary ? "Copied Message!" : "Copy Instructions"}</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ── Active Licenses Management Table (Glassmorphism) ───────────────── */}
        <section className="glass-panel rounded-3xl p-5 sm:p-8 shadow-2xl">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
            <div>
              <h2 className="text-base sm:text-lg font-black tracking-wide uppercase flex items-center space-x-2" style={{ color: "var(--text-primary)" }}>
                <span>DEPLOYED CLIENT NODES</span>
                <span className={`text-xs font-bold font-mono ${isLight ? "text-sky-700" : "text-cyan-400"}`}>
                  ({filteredLicenses.length} matching)
                </span>
              </h2>
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
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
                  style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                  className="border focus:border-cyan-500 rounded-xl pl-8 pr-3 py-1.5 text-xs placeholder:text-slate-400 outline-none w-56 transition"
                />
              </div>

              <div
                className="flex rounded-xl p-1 border text-xs"
                style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)" }}
              >
                {(["all", "active", "expiring", "revoked"] as const).map((filter) => {
                  const isSelected = statusFilter === filter;
                  return (
                    <button
                      key={filter}
                      onClick={() => setStatusFilter(filter)}
                      className={`px-3 py-1 rounded-lg font-bold capitalize transition cursor-pointer ${
                        isSelected
                          ? "bg-cyan-500 text-slate-950 shadow-md font-black"
                          : isLight
                          ? "text-slate-600 hover:text-sky-800 hover:bg-slate-100"
                          : "text-slate-400 hover:text-cyan-300 hover:bg-slate-800/40"
                      }`}
                    >
                      {filter}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Table Container with Horizontal Scroll for Small Screens */}
          <div
            className="overflow-x-auto rounded-2xl border"
            style={{ backgroundColor: "var(--table-bg)", borderColor: "var(--panel-border)" }}
          >
            <table className="w-full min-w-[850px] text-left text-xs" style={{ color: "var(--text-primary)" }}>
              <thead
                className="uppercase text-[11px] font-black tracking-wider border-b"
                style={{ backgroundColor: "var(--table-header)", borderColor: "var(--table-divide)" }}
              >
                <tr>
                  <th className={`py-3.5 px-4 ${isLight ? "text-sky-900" : "text-cyan-400"}`}>Client &amp; Organization</th>
                  <th className={`py-3.5 px-4 ${isLight ? "text-sky-900" : "text-cyan-400"}`}>License Key</th>
                  <th className={`py-3.5 px-4 ${isLight ? "text-sky-900" : "text-cyan-400"}`}>Remaining</th>
                  <th className={`py-3.5 px-4 ${isLight ? "text-sky-900" : "text-cyan-400"}`}>Expiry Date</th>
                  <th className={`py-3.5 px-4 ${isLight ? "text-sky-900" : "text-cyan-400"}`}>Bound Workstation (HWID)</th>
                  <th className={`py-3.5 px-4 ${isLight ? "text-sky-900" : "text-cyan-400"}`}>Node Status</th>
                  <th className={`py-3.5 px-4 text-right ${isLight ? "text-sky-900" : "text-cyan-400"}`}>Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: "var(--table-divide)" }}>
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

                    // Status Badge Styling Helper
                    let badgeClass = "";
                    let badgeLabel = "";
                    if (!lic.isActive) {
                      badgeLabel = "BLOCKED";
                      badgeClass = isLight
                        ? "bg-red-50 text-red-800 border border-red-300 font-extrabold shadow-sm"
                        : "bg-red-950/80 text-red-400 border border-red-800/60 font-bold shadow-[0_0_10px_rgba(239,68,68,0.2)]";
                    } else if (isExpired) {
                      badgeLabel = "EXPIRED";
                      badgeClass = isLight
                        ? "bg-red-50 text-red-800 border border-red-300 font-extrabold shadow-sm"
                        : "bg-red-950/80 text-red-400 border border-red-800/60 font-bold shadow-[0_0_10px_rgba(239,68,68,0.2)]";
                    } else if (daysLeft <= 7) {
                      badgeLabel = `⚠️ ${daysLeft} Days`;
                      badgeClass = isLight
                        ? "bg-amber-50 text-amber-900 border border-amber-300 font-extrabold shadow-sm"
                        : "bg-amber-950/80 text-amber-400 border border-amber-800/60 font-bold shadow-[0_0_10px_rgba(245,158,11,0.2)]";
                    } else {
                      badgeLabel = `🟢 ${daysLeft} Days`;
                      badgeClass = isLight
                        ? "bg-emerald-50 text-emerald-800 border border-emerald-300 font-extrabold shadow-sm"
                        : "bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 font-bold shadow-[0_0_10px_rgba(16,185,129,0.2)]";
                    }

                    return (
                      <tr
                        key={lic.key}
                        className="transition"
                        style={{
                          backgroundColor: "transparent",
                        }}
                      >
                        {/* Client Name & Org */}
                        <td className="py-3.5 px-4">
                          <div className="font-extrabold" style={{ color: "var(--text-primary)" }}>
                            {lic.clientName}
                          </div>
                          <div className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
                            {lic.organization}
                          </div>
                          {lic.contactEmail && (
                            <div className="text-[10px] font-mono" style={{ color: "var(--text-tertiary)" }}>
                              {lic.contactEmail}
                            </div>
                          )}
                        </td>

                        {/* License Key */}
                        <td className="py-3.5 px-4 font-mono font-bold">
                          <div className="flex items-center space-x-1.5">
                            <span className={isLight ? "text-sky-900 font-black" : "text-cyan-400"}>
                              {lic.key}
                            </span>
                            <button
                              onClick={() => copyToClipboard(lic.key, "key")}
                              title="Copy Key"
                              className="text-slate-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition cursor-pointer"
                            >
                              <Copy className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>

                        {/* Remaining Days Badge */}
                        <td className="py-3.5 px-4">
                          <span className={`px-2.5 py-0.5 rounded-full text-[10px] ${badgeClass}`}>
                            {badgeLabel}
                          </span>
                        </td>

                        {/* Expiry Date */}
                        <td className="py-3.5 px-4 font-mono font-semibold" style={{ color: "var(--text-secondary)" }}>
                          {new Date(lic.expiresAt).toLocaleDateString()}
                        </td>

                        {/* Bound Machine */}
                        <td className="py-3.5 px-4">
                          {lic.hardwareId ? (
                            <div className="flex items-center space-x-1.5">
                              <Laptop className={`w-3.5 h-3.5 shrink-0 ${isLight ? "text-indigo-600" : "text-indigo-400"}`} />
                              <span
                                className={`font-mono text-[11px] font-bold ${isLight ? "text-sky-800" : "text-cyan-400"}`}
                                title={lic.hardwareId}
                              >
                                {lic.machineHostname || lic.hardwareId.substring(0, 14) + "..."}
                              </span>
                            </div>
                          ) : (
                            <span className="italic text-[11px]" style={{ color: "var(--text-tertiary)" }}>
                              Waiting for node activation...
                            </span>
                          )}
                        </td>

                        {/* Status */}
                        <td className="py-3.5 px-4">
                          {!lic.isActive ? (
                            <span className="inline-flex items-center space-x-1 text-red-600 font-extrabold">
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Revoked</span>
                            </span>
                          ) : isExpired ? (
                            <span className="inline-flex items-center space-x-1 text-red-600 font-extrabold">
                              <AlertTriangle className="w-3.5 h-3.5" />
                              <span>Expired</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center space-x-1 text-emerald-600 font-extrabold">
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
                                className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition cursor-pointer ${
                                  isLight
                                    ? "bg-red-50 hover:bg-red-100 text-red-700 border border-red-300 shadow-sm"
                                    : "bg-red-950/60 hover:bg-red-900/60 text-red-300 border border-red-800/50"
                                }`}
                              >
                                Revoke
                              </button>
                            ) : (
                              <button
                                onClick={() => handleAction(lic.key, "activate")}
                                title="Restore Node Access"
                                className={`px-2.5 py-1 rounded-lg text-[11px] font-bold transition cursor-pointer ${
                                  isLight
                                    ? "bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-300 shadow-sm"
                                    : "bg-emerald-950/60 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/50"
                                }`}
                              >
                                Enable
                              </button>
                            )}

                            {/* Extend +30 Days */}
                            <button
                              onClick={() => handleAction(lic.key, "extend", 30)}
                              title="Extend subscription by +30 Days"
                              style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                              className="px-2.5 py-1 rounded-lg border text-[11px] font-bold transition cursor-pointer hover:border-cyan-400"
                            >
                              +30d
                            </button>

                            {/* Unlock HWID */}
                            {lic.hardwareId && (
                              <button
                                onClick={() => handleAction(lic.key, "reset_hwid")}
                                title="Unlock machine binding so client can switch PC"
                                style={{ backgroundColor: "var(--input-bg)", borderColor: "var(--input-border)", color: "var(--text-primary)" }}
                                className="p-1.5 rounded-lg border transition cursor-pointer hover:border-cyan-400"
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
                              className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-red-500/10 transition cursor-pointer"
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
