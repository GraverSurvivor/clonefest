import { NextRequest, NextResponse } from "next/server";
import { dbGet, dbRun, purgeExpired, PasteRow } from "@/lib/db";

interface RouteContext {
  params: Promise<{ id: string }>;
}

export async function GET(_req: NextRequest, context: RouteContext) {
  try {
    await purgeExpired();
    const { id } = await context.params;

    const row = await dbGet<PasteRow>("SELECT * FROM pastes WHERE id = ?", [id]);

    if (!row) {
      return NextResponse.json(
        { error: "Paste not found or has already expired/been burned." },
        { status: 404 }
      );
    }

    const now = Date.now();
    if (row.expires_at && now > row.expires_at) {
      await dbRun("DELETE FROM pastes WHERE id = ?", [id]);
      return NextResponse.json(
        { error: "Paste not found or has already expired/been burned." },
        { status: 404 }
      );
    }

    const responseData = {
      payload: row.payload,
      created_at: row.created_at,
      expires_at: row.expires_at,
      burn_on_read: !!row.burn_on_read,
    };

    // Delete immediately if burn-on-read
    if (row.burn_on_read) {
      await dbRun("DELETE FROM pastes WHERE id = ?", [id]);
    }

    return NextResponse.json(responseData);
  } catch (err) {
    console.error("GET /api/paste/[id] error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest, context: RouteContext) {
  try {
    const { id } = await context.params;
    const token =
      req.headers.get("x-deletion-token") ??
      new URL(req.url).searchParams.get("token");

    if (!token) {
      return NextResponse.json({ error: "Deletion token is required" }, { status: 400 });
    }

    const row = await dbGet<Pick<PasteRow, "deletion_token">>(
      "SELECT deletion_token FROM pastes WHERE id = ?",
      [id]
    );

    if (!row) {
      return NextResponse.json({ error: "Paste not found" }, { status: 404 });
    }

    if (row.deletion_token !== token) {
      return NextResponse.json({ error: "Invalid deletion token" }, { status: 403 });
    }

    await dbRun("DELETE FROM pastes WHERE id = ?", [id]);
    return NextResponse.json({ success: true, message: "Paste deleted successfully." });
  } catch (err) {
    console.error("DELETE /api/paste/[id] error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
