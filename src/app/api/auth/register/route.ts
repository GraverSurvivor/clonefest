import { randomBytes } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { createSession, hashPassword, normalizeIdentifier, publicUser, setSessionCookie } from "@/lib/auth";
import { dbGet, dbRun, UserRow } from "@/lib/db";

export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as {
      username?: string;
      email?: string;
      password?: string;
      confirmPassword?: string;
      public_key?: string;
      encrypted_private_key?: string;
      key_metadata?: string;
    };

    const username = body.username?.trim() ?? "";
    const email = normalizeIdentifier(body.email ?? "");
    const password = body.password ?? "";

    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
      return NextResponse.json({ error: "Username must be 3-24 letters, numbers, or underscores." }, { status: 400 });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json({ error: "Enter a valid email address." }, { status: 400 });
    }
    if (password.length < 10) {
      return NextResponse.json({ error: "Password must be at least 10 characters." }, { status: 400 });
    }
    if (password !== body.confirmPassword) {
      return NextResponse.json({ error: "Passwords do not match." }, { status: 400 });
    }
    if (!body.public_key || !body.encrypted_private_key || !body.key_metadata) {
      return NextResponse.json({ error: "Encrypted key material is required." }, { status: 400 });
    }

    const duplicate = await dbGet<UserRow>(
      "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
      [username, email]
    );
    if (duplicate?.username.toLowerCase() === username.toLowerCase()) {
      return NextResponse.json({ error: "That username is already registered." }, { status: 409 });
    }
    if (duplicate?.email.toLowerCase() === email) {
      return NextResponse.json({ error: "That email is already registered." }, { status: 409 });
    }

    const now = Date.now();
    const userId = randomBytes(12).toString("hex");
    const passwordHash = await hashPassword(password);
    await dbRun(
      `INSERT INTO users (id, username, email, password_hash, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, username, email, passwordHash, now, now]
    );
    await dbRun(
      `INSERT INTO user_keys (user_id, public_key, encrypted_private_key, key_metadata, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, body.public_key, body.encrypted_private_key, body.key_metadata, now]
    );

    const token = await createSession(userId);
    await setSessionCookie(token);
    const user = await dbGet<UserRow>("SELECT * FROM users WHERE id = ?", [userId]);
    return NextResponse.json({ user: publicUser(user!) });
  } catch (err) {
    console.error("POST /api/auth/register error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
