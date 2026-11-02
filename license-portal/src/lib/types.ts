export type LicensePlan = "7_days" | "30_days" | "90_days" | "1_year" | "lifetime";

export interface License {
  key: string;
  clientName: string;
  organization: string;
  contactEmail: string;
  plan: LicensePlan;
  createdAt: string;
  expiresAt: string;
  isActive: boolean;
  maxDevices: number;
  hardwareId: string | null;
  machineHostname: string | null;
  notes: string;
  activatedAt: string | null;
  lastCheckedAt: string | null;
}

export interface LicenseStats {
  total: number;
  active: number;
  expiringSoon: number;
  revoked: number;
  connectedDevices: number;
}

export interface CreateLicenseInput {
  clientName: string;
  organization?: string;
  contactEmail?: string;
  plan: LicensePlan;
  maxDevices?: number;
  notes?: string;
}

export interface VerifyLicenseRequest {
  licenseKey: string;
  hardwareId: string;
  machineHostname?: string;
}

export interface VerifyLicenseResponse {
  valid: boolean;
  status: "active" | "expired" | "revoked" | "hwid_mismatch" | "not_found";
  clientName?: string;
  organization?: string;
  expiresAt?: string;
  daysRemaining?: number;
  message: string;
}

