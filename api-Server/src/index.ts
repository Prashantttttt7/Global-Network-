import fs from "fs";
import path from "path";
import app from "./app";
import { logger } from "./lib/logger";

// ── Ensure the local uploads directory exists at startup ───────────────────────
// When GCS object storage is not configured, uploaded PDFs are stored on local
// disk. The directory must exist before any upload requests arrive.
const uploadsDir = path.resolve(process.cwd(), "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });
logger.info({ uploadsDir }, "Upload directory ready");

// ── Start HTTP server ──────────────────────────────────────────────────────────
const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
});
