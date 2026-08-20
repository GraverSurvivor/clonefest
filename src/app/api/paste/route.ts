import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "crypto";
import { dbRun, dbGet, purgeExpired, PasteRow } from "@/lib/db";

export async function POST(req: NextRequest) {
  try {
    await purgeExpired();

    const body = await req.json();
    const { payload, burn_on_read, expires_at } = body as {
      payload: string;
      burn_on_read?: boolean;
      expires_at?: number | null;
    };

    if (!payload) {
      return NextResponse.json({ error: "Payload is required" }, { status: 400 });
    }

    const id = randomBytes(8).toString("hex");
    const deletion_token = randomBytes(16).toString("hex");
    const created_at = Date.now();
    const burnVal = burn_on_read ? 1 : 0;
    const expiryVal = expires_at ?? null;

    await dbRun(
      `INSERT INTO pastes (id, payload, burn_on_read, deletion_token, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [id, payload, burnVal, deletion_token, expiryVal, created_at]
    );

    return NextResponse.json({ id, deletion_token, expires_at: expiryVal, burn_on_read: !!burnVal });
  } catch (err) {
    console.error("POST /api/paste error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({ error: "Use GET /api/paste/:id" }, { status: 400 });
}
