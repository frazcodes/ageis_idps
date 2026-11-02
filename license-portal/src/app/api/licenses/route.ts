import { NextResponse } from "next/server";
import { createLicense, getAllLicenses, getLicenseStats } from "@/lib/licenseStorage";
import { CreateLicenseInput } from "@/lib/types";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const licenses = await getAllLicenses();
    const stats = await getLicenseStats();
    return NextResponse.json({ success: true, licenses, stats });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}

export async function POST(req: Request) {
  try {
    const body: CreateLicenseInput = await req.json();

    if (!body.clientName || body.clientName.trim().length === 0) {
      return NextResponse.json(
        { success: false, error: "Client name is required" },
        { status: 400 }
      );
    }

    const license = await createLicense(body);
    const stats = await getLicenseStats();

    return NextResponse.json({
      success: true,
      message: "License generated successfully",
      license,
      stats,
    });
  } catch (error: any) {
    return NextResponse.json({ success: false, error: error.message }, { status: 500 });
  }
}

