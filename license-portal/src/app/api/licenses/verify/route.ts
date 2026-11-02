import { NextResponse } from "next/server";
import { getDaysRemaining, getLicenseByKey, updateLicense } from "@/lib/licenseStorage";
import { VerifyLicenseRequest, VerifyLicenseResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  try {
    const body: VerifyLicenseRequest = await req.json();
    const { licenseKey, hardwareId, machineHostname } = body;

    if (!licenseKey || !hardwareId) {
      return NextResponse.json<VerifyLicenseResponse>(
        {
          valid: false,
          status: "not_found",
          message: "Missing licenseKey or hardwareId in request",
        },
        { status: 400 }
      );
    }

    const license = await getLicenseByKey(licenseKey);

    if (!license) {
      return NextResponse.json<VerifyLicenseResponse>(
        {
          valid: false,
          status: "not_found",
          message: "License key was not found in the Aegis database",
        },
        { status: 404 }
      );
    }

    // Check if manually revoked by admin
    if (!license.isActive) {
      return NextResponse.json<VerifyLicenseResponse>(
        {
          valid: false,
          status: "revoked",
          clientName: license.clientName,
          organization: license.organization,
          message: "This license key has been revoked by the system administrator",
        },
        { status: 403 }
      );
    }

    // Check expiration
    const daysRemaining = getDaysRemaining(license.expiresAt);
    if (new Date(license.expiresAt).getTime() <= Date.now()) {
      return NextResponse.json<VerifyLicenseResponse>(
        {
          valid: false,
          status: "expired",
          clientName: license.clientName,
          organization: license.organization,
          expiresAt: license.expiresAt,
          daysRemaining: 0,
          message: `This license expired on ${new Date(license.expiresAt).toLocaleDateString()}`,
        },
        { status: 403 }
      );
    }

    // Hardware Lock check
    if (!license.hardwareId) {
      // First activation: bind to this machine!
      await updateLicense(license.key, {
        hardwareId: hardwareId.trim(),
        machineHostname: machineHostname || "Unknown PC",
        activatedAt: new Date().toISOString(),
        lastCheckedAt: new Date().toISOString(),
      });
    } else if (license.hardwareId.toUpperCase() !== hardwareId.trim().toUpperCase()) {
      return NextResponse.json<VerifyLicenseResponse>(
        {
          valid: false,
          status: "hwid_mismatch",
          clientName: license.clientName,
          organization: license.organization,
          message: `License is locked to another machine (Host: ${license.machineHostname || "Registered PC"}). Contact administrator to transfer license.`,
        },
        { status: 403 }
      );
    } else {
      // Periodic check: update lastCheckedAt
      await updateLicense(license.key, {
        lastCheckedAt: new Date().toISOString(),
      });
    }

    return NextResponse.json<VerifyLicenseResponse>({
      valid: true,
      status: "active",
      clientName: license.clientName,
      organization: license.organization,
      expiresAt: license.expiresAt,
      daysRemaining,
      message: `License active for ${license.clientName} (${daysRemaining} days remaining)`,
    });
  } catch (error: any) {
    return NextResponse.json<VerifyLicenseResponse>(
      {
        valid: false,
        status: "not_found",
        message: error.message || "Internal server error during verification",
      },
      { status: 500 }
    );
  }
}

