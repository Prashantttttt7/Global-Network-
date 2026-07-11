import { Storage } from "@google-cloud/storage";
import { randomUUID } from "crypto";
import fs from "fs";
import path from "path";

// ── GCS setup (used only when DEFAULT_OBJECT_STORAGE_BUCKET_ID is set) ────────

const REPLIT_SIDECAR_ENDPOINT = "http://127.0.0.1:1106";

const storageClient = new Storage({
  credentials: {
    audience: "replit",
    subject_token_type: "access_token",
    token_url: `${REPLIT_SIDECAR_ENDPOINT}/token`,
    type: "external_account",
    credential_source: {
      url: `${REPLIT_SIDECAR_ENDPOINT}/credential`,
      format: { type: "json", subject_token_field_name: "access_token" },
    },
    universe_domain: "googleapis.com",
  },
  projectId: "",
});

function getBucket() {
  const bucketId = process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID;
  if (!bucketId) throw new Error("DEFAULT_OBJECT_STORAGE_BUCKET_ID not set");
  return storageClient.bucket(bucketId);
}

// ── Local-disk fallback (used in dev when GCS is not configured) ──────────────
//
// Files stored locally use the "local/<uuid>.pdf" objectName convention.
// The physical file lives at UPLOADS_DIR/<uuid>.pdf.
// This prefix lets download/delete know which backend to use at read time.

const UPLOADS_DIR = path.resolve(process.cwd(), "uploads");

// Strict allowlist: "local/" followed by a canonical UUID and ".pdf" only.
// This prevents any path traversal attack via a tampered DB filename value.
const LOCAL_NAME_RE = /^local\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.pdf$/;

function isLocal(objectName: string): boolean {
  return objectName.startsWith("local/");
}

function localPath(objectName: string): string {
  if (!LOCAL_NAME_RE.test(objectName)) {
    throw new Error(`Invalid local object name: ${objectName}`);
  }
  // "local/<uuid>.pdf" → UPLOADS_DIR/<uuid>.pdf
  const resolved = path.resolve(UPLOADS_DIR, objectName.slice("local/".length));
  // Belt-and-suspenders: ensure resolved path stays inside UPLOADS_DIR
  if (!resolved.startsWith(UPLOADS_DIR + path.sep) && resolved !== UPLOADS_DIR) {
    throw new Error(`Path traversal detected in object name: ${objectName}`);
  }
  return resolved;
}

// ── Public API ─────────────────────────────────────────────────────────────────

export async function uploadPdf(srcPath: string): Promise<string> {
  if (process.env.DEFAULT_OBJECT_STORAGE_BUCKET_ID) {
    // GCS path — persistent across deployments
    const objectName = `pdfs/${randomUUID()}.pdf`;
    const bucket = getBucket();
    await bucket.upload(srcPath, { destination: objectName });
    return objectName;
  }

  // Local-disk fallback — suitable for dev; files survive process restarts
  // but not Replit redeployments. Add GCS object storage to make uploads
  // permanent in production.
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  const objectName = `local/${randomUUID()}.pdf`;
  fs.copyFileSync(srcPath, localPath(objectName));
  return objectName;
}

export async function downloadPdfToFile(
  objectName: string,
  destPath: string
): Promise<void> {
  if (isLocal(objectName)) {
    fs.copyFileSync(localPath(objectName), destPath);
    return;
  }
  const bucket = getBucket();
  await bucket.file(objectName).download({ destination: destPath });
}

export async function downloadPdfToBuffer(objectName: string): Promise<Buffer> {
  if (isLocal(objectName)) {
    return fs.readFileSync(localPath(objectName));
  }
  const bucket = getBucket();
  const [contents] = await bucket.file(objectName).download();
  return contents;
}

export async function deletePdf(objectName: string): Promise<void> {
  if (isLocal(objectName)) {
    try {
      fs.unlinkSync(localPath(objectName));
    } catch (err: unknown) {
      // Ignore only "file not found" — surface real I/O errors so callers know
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    return;
  }
  try {
    const bucket = getBucket();
    await bucket.file(objectName).delete();
  } catch (err: unknown) {
    // Ignore only GCS 404 — surface other storage errors
    const status = (err as { code?: number }).code;
    if (status !== 404) throw err;
  }
}
