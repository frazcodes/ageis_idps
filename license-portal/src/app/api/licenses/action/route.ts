import { NextResponse } from "next/server";
import { deleteLicense, getLicenseByKey, getLicenseStats, updateLicense } from "@/lib/licenseStorage";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  try {
    const { key, action, extendDays = 30 } = await req.json();

    if (!key || !action) {
      return NextResponse.json({ success: false, error: "Missing key or action" }, { status: 400 });
    }

    const license = await getLicenseByKey(key);
    if (!license) {
      return NextResponse.json({ success: false, error: "License not found" }, { status: 404 });
    }

    if (action === "revoke") {
      await updateLicense(key, { isActive: false });
    } else if (action === "activate") {
      await updateLicense(key, { isActive: true });
    } else if (action === "extend") {
      const currentExpiry = new Date(license.expiresAt).getTime();
      const baseTime = currentExpiry > Date.now() ? currentExpiry : Date.now();
      const newExpiry = new Date(baseTime + extendDays * 86400000).toISOString();
      await updateLicense(key, { expiresAt: newExpiry, isActive: true });
    } else if (action === "reset_hwid") {
      await updateLicense(key, { hardwareId: null, machineHostname: null });
    } else if (action === "delete") {
      await deleteLicense(key);
    } else {
      return NextResponse.json({ success: false, error: "Invalid action" }, { status: 400 });
    }

    const stats = await getLicenseStats();
    return NextResponse.json({ success: true, message: `Action ${action} succeeded`, stats });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}

