import fs from "fs";
import path from "path";
import crypto from "crypto";
import { CreateLicenseInput, License, LicensePlan, LicenseStats } from "./types";

let cachedToken: { token: string; expiresAt: number } | null = null;

function getServiceAccountCredentials(): { projectId: string; clientEmail: string; privateKey: string } | null {
  // 1. Check environment variables (ideal for Vercel deployment)
  if (process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
    return {
      projectId: process.env.FIREBASE_PROJECT_ID || process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID || "aegis-license-system",
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    };
  }

  // 2. Check serviceAccountKey.json file in local project
  try {
    const keyPath = path.join(process.cwd(), "serviceAccountKey.json");
    if (fs.existsSync(keyPath)) {
      const raw = JSON.parse(fs.readFileSync(keyPath, "utf8"));
      return {
        projectId: raw.project_id,
        clientEmail: raw.client_email,
        privateKey: raw.private_key,
      };
    }
  } catch (err) {
    // Ignore and fallback
  }

  return null;
}

async function getFirebaseAccessToken(): Promise<{ token: string; projectId: string } | null> {
  const creds = getServiceAccountCredentials();
  if (!creds) return null;

  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.expiresAt > now + 60) {
    return { token: cachedToken.token, projectId: creds.projectId };
  }

  try {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        iss: creds.clientEmail,
        scope: "https://www.googleapis.com/auth/datastore",
        aud: "https://oauth2.googleapis.com/token",
        exp: now + 3600,
        iat: now,
      })
    ).toString("base64url");

    const sign = crypto.createSign("RSA-SHA256");
    sign.update(`${header}.${payload}`);
    const signature = sign.sign(creds.privateKey, "base64url");
    const jwt = `${header}.${payload}.${signature}`;

    const res = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    });

    if (res.ok) {
      const data = await res.json();
      cachedToken = {
        token: data.access_token,
        expiresAt: now + (data.expires_in || 3600),
      };
      return { token: data.access_token, projectId: creds.projectId };
    }
  } catch (err) {
    console.error("Failed obtaining Google OAuth2 access token:", err);
  }

  return null;
}

// Initial in-memory mock fallback data
let inMemoryLicenses: License[] = [];

export function generateLicenseKey(): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const segment = () =>
    Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `AEGIS-${segment()}-${segment()}-${segment()}`;
}

export function computeExpiryDate(plan: LicensePlan): string {
  const now = new Date();
  switch (plan) {
    case "7_days":
      now.setDate(now.getDate() + 7);
      break;
    case "30_days":
      now.setDate(now.getDate() + 30);
      break;
    case "90_days":
      now.setDate(now.getDate() + 90);
      break;
    case "1_year":
      now.setFullYear(now.getFullYear() + 1);
      break;
    case "lifetime":
      now.setFullYear(now.getFullYear() + 10);
      break;
  }
  return now.toISOString();
}

export function getDaysRemaining(expiresAt: string): number {
  const diff = new Date(expiresAt).getTime() - Date.now();
  return Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Real Firebase Cloud Storage Functions
// ─────────────────────────────────────────────────────────────────────────────

export async function getAllLicenses(): Promise<License[]> {
  const auth = await getFirebaseAccessToken();
  if (auth) {
    try {
      const url = `https://firestore.googleapis.com/v1/projects/${auth.projectId}/databases/(default)/documents/licenses`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${auth.token}` },
        cache: "no-store",
      });
      if (res.ok) {
        const data = await res.json();
        if (data.documents && Array.isArray(data.documents)) {
          return data.documents.map((doc: any) => parseFirestoreDocument(doc));
        }
        return [];
      }
    } catch (err) {
      console.error("Firestore fetch failed:", err);
    }
  }
  return [...inMemoryLicenses];
}

export async function getLicenseByKey(key: string): Promise<License | null> {
  const cleanKey = key.trim().toUpperCase();
  const auth = await getFirebaseAccessToken();
  if (auth) {
    try {
      const url = `https://firestore.googleapis.com/v1/projects/${auth.projectId}/databases/(default)/documents/licenses/${cleanKey}`;
      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${auth.token}` },
        cache: "no-store",
      });
      if (res.ok) {
        const doc = await res.json();
        return parseFirestoreDocument(doc);
      }
      if (res.status === 404) return null;
    } catch (err) {
      console.error("Firestore lookup failed:", err);
    }
  }
  return inMemoryLicenses.find((l) => l.key.toUpperCase() === cleanKey) || null;
}

export async function createLicense(input: CreateLicenseInput): Promise<License> {
  const key = generateLicenseKey();
  const now = new Date().toISOString();
  const expiresAt = computeExpiryDate(input.plan);

  const license: License = {
    key,
    clientName: input.clientName.trim(),
    organization: (input.organization || "Independent").trim(),
    contactEmail: (input.contactEmail || "").trim(),
    plan: input.plan,
    createdAt: now,
    expiresAt,
    isActive: true,
    maxDevices: input.maxDevices || 1,
    hardwareId: null,
    machineHostname: null,
    notes: (input.notes || "").trim(),
    activatedAt: null,
    lastCheckedAt: null,
  };

  const auth = await getFirebaseAccessToken();
  if (auth) {
    try {
      const url = `https://firestore.googleapis.com/v1/projects/${auth.projectId}/databases/(default)/documents/licenses/${key}`;
      const firestoreDoc = formatFirestoreDocument(license);
      await fetch(url, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${auth.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(firestoreDoc),
      });
    } catch (err) {
      console.error("Failed saving license to Firestore:", err);
    }
  }

  inMemoryLicenses.unshift(license);
  return license;
}

export async function updateLicense(key: string, updates: Partial<License>): Promise<License | null> {
  const license = await getLicenseByKey(key);
  if (!license) return null;

  const updated: License = { ...license, ...updates };
  const auth = await getFirebaseAccessToken();

  if (auth) {
    try {
      const url = `https://firestore.googleapis.com/v1/projects/${auth.projectId}/databases/(default)/documents/licenses/${key.toUpperCase()}`;
      const firestoreDoc = formatFirestoreDocument(updated);
      await fetch(url, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${auth.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(firestoreDoc),
      });
    } catch (err) {
      console.error("Failed updating license in Firestore:", err);
    }
  }

  const idx = inMemoryLicenses.findIndex((l) => l.key.toUpperCase() === key.toUpperCase());
  if (idx !== -1) {
    inMemoryLicenses[idx] = updated;
  } else {
    inMemoryLicenses.unshift(updated);
  }

  return updated;
}

export async function deleteLicense(key: string): Promise<boolean> {
  const auth = await getFirebaseAccessToken();
  if (auth) {
    try {
      const url = `https://firestore.googleapis.com/v1/projects/${auth.projectId}/databases/(default)/documents/licenses/${key.toUpperCase()}`;
      await fetch(url, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${auth.token}` },
      });
    } catch (err) {
      console.error("Failed deleting license from Firestore:", err);
    }
  }
  inMemoryLicenses = inMemoryLicenses.filter((l) => l.key.toUpperCase() !== key.toUpperCase());
  return true;
}

export async function getLicenseStats(): Promise<LicenseStats> {
  const all = await getAllLicenses();
  const now = Date.now();

  let active = 0;
  let expiringSoon = 0;
  let revoked = 0;
  let connectedDevices = 0;

  for (const l of all) {
    const isExpired = new Date(l.expiresAt).getTime() <= now;
    if (!l.isActive) {
      revoked++;
    } else if (isExpired) {
      // Expired count
    } else {
      active++;
      const days = getDaysRemaining(l.expiresAt);
      if (days <= 7) expiringSoon++;
    }
    if (l.hardwareId) connectedDevices++;
  }

  return {
    total: all.length,
    active,
    expiringSoon,
    revoked,
    connectedDevices,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Firestore Serializers
// ─────────────────────────────────────────────────────────────────────────────

function formatFirestoreDocument(l: License) {
  return {
    fields: {
      key: { stringValue: l.key },
      clientName: { stringValue: l.clientName },
      organization: { stringValue: l.organization },
      contactEmail: { stringValue: l.contactEmail },
      plan: { stringValue: l.plan },
      createdAt: { stringValue: l.createdAt },
      expiresAt: { stringValue: l.expiresAt },
      isActive: { booleanValue: l.isActive },
      maxDevices: { integerValue: l.maxDevices.toString() },
      hardwareId: l.hardwareId ? { stringValue: l.hardwareId } : { nullValue: null },
      machineHostname: l.machineHostname ? { stringValue: l.machineHostname } : { nullValue: null },
      notes: { stringValue: l.notes },
      activatedAt: l.activatedAt ? { stringValue: l.activatedAt } : { nullValue: null },
      lastCheckedAt: l.lastCheckedAt ? { stringValue: l.lastCheckedAt } : { nullValue: null },
    },
  };
}

function parseFirestoreDocument(doc: any): License {
  const f = doc.fields || {};
  return {
    key: f.key?.stringValue || doc.name?.split("/").pop() || "",
    clientName: f.clientName?.stringValue || "Unknown Client",
    organization: f.organization?.stringValue || "Independent",
    contactEmail: f.contactEmail?.stringValue || "",
    plan: (f.plan?.stringValue as LicensePlan) || "30_days",
    createdAt: f.createdAt?.stringValue || new Date().toISOString(),
    expiresAt: f.expiresAt?.stringValue || new Date().toISOString(),
    isActive: f.isActive?.booleanValue ?? true,
    maxDevices: parseInt(f.maxDevices?.integerValue || "1", 10),
    hardwareId: f.hardwareId?.stringValue || null,
    machineHostname: f.machineHostname?.stringValue || null,
    notes: f.notes?.stringValue || "",
    activatedAt: f.activatedAt?.stringValue || null,
    lastCheckedAt: f.lastCheckedAt?.stringValue || null,
  };
}
