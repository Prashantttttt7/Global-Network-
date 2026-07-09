import { Router, type IRouter } from "express";
import { eq } from "drizzle-orm";
import bcrypt from "bcryptjs";
import { db, usersTable, withDbRetry } from "@workspace/db";
import { logger } from "../lib/logger";

const router: IRouter = Router();

// ── Admin phone allowlist ──────────────────────────────────────────────────────
// Exact match on the digit-only form of Prashant's phone number.
// Supports E.164 (+919860992546), local (9860992546), or with country code
// prefix (919860992546). No suffix matching — an accidental match is impossible.
const ADMIN_PHONE_DIGITS = new Set([
  "9860992546",    // local 10-digit form
  "919860992546",  // with country code 91
]);

function resolveRole(phone: string): "admin" | "user" {
  const digits = phone.replace(/\D/g, "");
  return ADMIN_PHONE_DIGITS.has(digits) ? "admin" : "user";
}

// ── In-memory rate limiter ─────────────────────────────────────────────────────
// Tracks failed authentication attempts per IP to slow brute-force attacks.
// Each entry resets after WINDOW_MS of inactivity.
const MAX_ATTEMPTS = 10;
const WINDOW_MS = 15 * 60 * 1000; // 15-minute sliding window

interface RateBucket { count: number; resetAt: number }
const rateBuckets = new Map<string, RateBucket>();

// Returns true if the request is allowed; false if the IP is over the limit.
function isRateLimited(ip: string): boolean {
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + WINDOW_MS };
    rateBuckets.set(ip, bucket);
  }
  if (bucket.count >= MAX_ATTEMPTS) return true;
  bucket.count++;
  return false;
}

function clearRateLimit(ip: string) {
  rateBuckets.delete(ip);
}

// Purge stale buckets every 30 minutes to avoid unbounded growth
setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(ip);
  }
}, 30 * 60 * 1000);

// ── Inline validation helpers ──────────────────────────────────────────────────
function parseCheckPhone(body: unknown): { phone: string } | { error: string } {
  if (!body || typeof body !== "object") return { error: "Invalid request body" };
  const { phone } = body as Record<string, unknown>;
  if (typeof phone !== "string" || !phone.trim()) return { error: "Phone is required" };
  return { phone: phone.trim() };
}

function parseLogin(body: unknown): { phone: string; password: string } | { error: string } {
  if (!body || typeof body !== "object") return { error: "Invalid request body" };
  const { phone, password } = body as Record<string, unknown>;
  if (typeof phone !== "string" || !phone.trim()) return { error: "Phone is required" };
  if (typeof password !== "string" || !password) return { error: "Password is required" };
  return { phone: phone.trim(), password };
}

function parseSetPassword(body: unknown): { phone: string; password: string } | { error: string } {
  if (!body || typeof body !== "object") return { error: "Invalid request body" };
  const { phone, password } = body as Record<string, unknown>;
  if (typeof phone !== "string" || !phone.trim()) return { error: "Phone is required" };
  if (typeof password !== "string" || password.length < 8)
    return { error: "Password must be at least 8 characters" };
  return { phone: phone.trim(), password };
}

// ── Session helpers ────────────────────────────────────────────────────────────
// Regenerate the session ID after a privilege boundary (login) to prevent
// session fixation attacks, then populate the new session with user data.
function promoteSession(
  req: import("express").Request,
  userId: number,
  phone: string,
  role: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) { reject(err); return; }
      req.session.userId = userId;
      req.session.phone  = phone;
      req.session.role   = role;
      resolve();
    });
  });
}

// ── Session type augmentation ──────────────────────────────────────────────────
declare module "express-session" {
  interface SessionData {
    userId: number;
    phone: string;
    role: string;
  }
}

// ── POST /auth/check-phone ─────────────────────────────────────────────────────
// Step 1: look up the phone number and tell the client what screen to show next.
// Returns:
//   status = "has_password"  → user exists and has set a password → show Login
//   status = "no_password"   → user exists but no password yet    → show Set Password
//   status = "new_user"      → phone unknown; will register       → show Create Password
router.post("/auth/check-phone", async (req, res): Promise<void> => {
  const clientIp = (req.ip ?? req.socket.remoteAddress ?? "unknown");
  if (isRateLimited(clientIp)) {
    res.status(429).json({ error: "Too many attempts. Please try again later." });
    return;
  }

  const parsed = parseCheckPhone(req.body);
  if ("error" in parsed) { res.status(400).json({ error: parsed.error }); return; }
  const { phone } = parsed;

  try {
    const [user] = await withDbRetry(() =>
      db.select().from(usersTable).where(eq(usersTable.phone, phone))
    );
    if (!user) { res.json({ status: "new_user" }); return; }
    res.json({ status: user.passwordHash ? "has_password" : "no_password" });
  } catch (err) {
    req.log.error({ err }, "check-phone failed");
    res.status(500).json({ error: "Server error" });
  }
});

// ── POST /auth/login ───────────────────────────────────────────────────────────
// Step 2a: for users who already have a password — verify and open a fresh session.
router.post("/auth/login", async (req, res): Promise<void> => {
  const clientIp = (req.ip ?? req.socket.remoteAddress ?? "unknown");
  if (isRateLimited(clientIp)) {
    res.status(429).json({ error: "Too many failed attempts. Please try again later." });
    return;
  }

  const parsed = parseLogin(req.body);
  if ("error" in parsed) { res.status(400).json({ error: parsed.error }); return; }
  const { phone, password } = parsed;

  try {
    const [user] = await withDbRetry(() =>
      db.select().from(usersTable).where(eq(usersTable.phone, phone))
    );

    if (!user || !user.passwordHash) {
      res.status(401).json({ error: "Invalid phone number or password" });
      return;
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      res.status(401).json({ error: "Invalid phone number or password" });
      return;
    }

    // Correct the role for the admin phone on every login (in case it drifted)
    const expectedRole = resolveRole(phone);
    if (user.role !== expectedRole) {
      await db.update(usersTable).set({ role: expectedRole }).where(eq(usersTable.id, user.id));
      user.role = expectedRole;
    }

    // Regenerate session ID before writing user data (session fixation protection)
    await promoteSession(req, user.id, user.phone, user.role);
    clearRateLimit(clientIp); // reset counter on successful login

    req.log.info({ userId: user.id, role: user.role }, "User authenticated via password");

    res.json({
      success: true,
      user: { id: user.id, phone: user.phone, role: user.role, createdAt: user.createdAt.toISOString() },
    });
  } catch (err) {
    req.log.error({ err }, "login failed");
    res.status(500).json({ error: "Server error" });
  }
});

// ── POST /auth/set-password ────────────────────────────────────────────────────
// Step 2b: for NEW users OR existing users who have never set a password.
//
// SECURITY: If the user already has a password, this endpoint returns 409 and
// does nothing. Password reset requires the existing password (use /auth/login)
// — no unauthenticated overwrite is possible.
router.post("/auth/set-password", async (req, res): Promise<void> => {
  const clientIp = (req.ip ?? req.socket.remoteAddress ?? "unknown");
  if (isRateLimited(clientIp)) {
    res.status(429).json({ error: "Too many attempts. Please try again later." });
    return;
  }

  const parsed = parseSetPassword(req.body);
  if ("error" in parsed) { res.status(400).json({ error: parsed.error }); return; }
  const { phone, password } = parsed;
  const role = resolveRole(phone);

  try {
    const [existingUser] = await withDbRetry(() =>
      db.select().from(usersTable).where(eq(usersTable.phone, phone))
    );

    // Block unauthenticated password overwrite: if a password already exists,
    // the user must use /auth/login instead of calling this endpoint again.
    if (existingUser?.passwordHash) {
      res.status(409).json({ error: "Password already set. Please log in instead." });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);

    let user: typeof existingUser;

    if (existingUser) {
      // Existing record with no password — first-time setup, safe to set hash
      const [updated] = await db
        .update(usersTable)
        .set({ passwordHash, role })
        .where(eq(usersTable.id, existingUser.id))
        .returning();
      user = updated;
    } else {
      // Brand-new phone — register the account
      const [created] = await db
        .insert(usersTable)
        .values({ phone, role, passwordHash })
        .returning();
      user = created;
    }

    // Regenerate session ID before writing user data (session fixation protection)
    await promoteSession(req, user.id, user.phone, user.role);
    clearRateLimit(clientIp);

    req.log.info({ userId: user.id, role: user.role }, "Password set, user authenticated");

    res.status(201).json({
      success: true,
      user: { id: user.id, phone: user.phone, role: user.role, createdAt: user.createdAt.toISOString() },
    });
  } catch (err) {
    req.log.error({ err }, "set-password failed");
    res.status(500).json({ error: "Server error" });
  }
});

// ── POST /auth/logout ──────────────────────────────────────────────────────────
router.post("/auth/logout", (req, res): void => {
  req.session.destroy((err) => {
    if (err) logger.error({ err }, "Session destroy error");
  });
  res.json({ success: true });
});

// ── GET /auth/me ───────────────────────────────────────────────────────────────
router.get("/auth/me", async (req, res): Promise<void> => {
  if (!req.session.userId) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }

  try {
    const [user] = await withDbRetry(() =>
      db.select().from(usersTable).where(eq(usersTable.id, req.session.userId!))
    );

    if (!user) {
      req.session.destroy(() => {});
      res.status(401).json({ error: "User not found" });
      return;
    }

    res.json({
      id: user.id,
      phone: user.phone,
      role: user.role,
      createdAt: user.createdAt.toISOString(),
    });
  } catch (err) {
    req.log.error({ err }, "auth/me failed");
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
