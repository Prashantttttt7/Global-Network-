import { Router, type IRouter } from "express";
import { eq } from "drizzle-orm";
import { exec } from "child_process";
import { promisify } from "util";
import { randomUUID } from "crypto";
import path from "path";
import fs from "fs";
import os from "os";
import { db, documentsTable, accessLogsTable } from "../db";
import { requireAuth } from "../middlewares/auth";
import { downloadPdfToFile, downloadPdfToBuffer } from "../lib/objectStorage";

const execAsync = promisify(exec);
const router: IRouter = Router();

// List documents accessible to current user
// Any authenticated user can see all documents; the admin grant system is
// preserved in the DB but document listing and viewing is open to all users.
router.get("/documents", requireAuth, async (req, res): Promise<void> => {
  const docs = await db.select().from(documentsTable).orderBy(documentsTable.uploadedAt);

  res.json(
    docs.map((d) => ({
      id: d.id,
      title: d.title,
      description: d.description ?? null,
      pageCount: d.pageCount,
      fileSize: d.fileSize ?? null,
      uploadedAt: d.uploadedAt.toISOString(),
    }))
  );
});

// Get document metadata
router.get("/documents/:id", requireAuth, async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(raw, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid document ID" });
    return;
  }

  const [doc] = await db
    .select()
    .from(documentsTable)
    .where(eq(documentsTable.id, id));

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  res.json({
    id: doc.id,
    title: doc.title,
    description: doc.description ?? null,
    pageCount: doc.pageCount,
    fileSize: doc.fileSize ?? null,
    uploadedAt: doc.uploadedAt.toISOString(),
  });
});

// Get secure view session info
router.get("/documents/:id/view", requireAuth, async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(raw, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid document ID" });
    return;
  }

  const phone = req.session.phone!;

  const [doc] = await db
    .select()
    .from(documentsTable)
    .where(eq(documentsTable.id, id));

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  // Log access
  await db.insert(accessLogsTable).values({
    phone,
    documentId: id,
  });

  res.json({
    documentId: doc.id,
    totalPages: doc.pageCount,
    userPhone: phone,
    sessionToken: `${req.session.userId}-${id}-${Date.now()}`,
  });
});

// Serve raw PDF bytes for client-side rendering
router.get("/documents/:id/pdf", requireAuth, async (req, res): Promise<void> => {
  const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const id = parseInt(rawId, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid document ID" });
    return;
  }

  const [doc] = await db
    .select()
    .from(documentsTable)
    .where(eq(documentsTable.id, id));

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  try {
    const pdfBuffer = await downloadPdfToBuffer(doc.filename);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "inline");
    res.setHeader("Cache-Control", "private, no-store");
    res.send(pdfBuffer);
  } catch (err) {
    req.log.error({ err }, "Failed to stream PDF");
    res.status(500).json({ error: "Failed to retrieve document" });
  }
});

// Get a specific page as a PNG data URL
router.get("/documents/:id/pages/:page", requireAuth, async (req, res): Promise<void> => {
  const rawId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const rawPage = Array.isArray(req.params.page) ? req.params.page[0] : req.params.page;
  const id = parseInt(rawId, 10);
  const page = parseInt(rawPage, 10);

  if (isNaN(id) || isNaN(page) || page < 1) {
    res.status(400).json({ error: "Invalid parameters" });
    return;
  }

  const [doc] = await db
    .select()
    .from(documentsTable)
    .where(eq(documentsTable.id, id));

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  if (page > doc.pageCount) {
    res.status(404).json({ error: "Page not found" });
    return;
  }

  // Download PDF to collision-safe tmp paths for rendering
  const tmpDir = os.tmpdir();
  const tmpId = randomUUID();
  const tmpPdf = path.join(tmpDir, `pdf-${id}-${tmpId}.pdf`);
  const tmpPrefix = path.join(tmpDir, `page-${id}-${page}-${tmpId}`);
  const filesToClean: string[] = [tmpPdf];

  try {
    await downloadPdfToFile(doc.filename, tmpPdf);

    // pdftoppm -r 150 -png -f PAGE -l PAGE input.pdf output_prefix
    await execAsync(
      `pdftoppm -r 150 -png -f ${page} -l ${page} "${tmpPdf}" "${tmpPrefix}"`
    );

    // pdftoppm names files as prefix-NNN.png (zero-padded based on total pages)
    const tmpFiles = fs.readdirSync(tmpDir).filter(
      (f) => f.startsWith(path.basename(tmpPrefix)) && f.endsWith(".png")
    );

    if (tmpFiles.length === 0) {
      res.status(500).json({ error: "Failed to render page" });
      return;
    }

    const pngPath = path.join(tmpDir, tmpFiles[0]);
    filesToClean.push(pngPath);
    const pngBuffer = fs.readFileSync(pngPath);
    const dataUrl = `data:image/png;base64,${pngBuffer.toString("base64")}`;

    res.json({ page, totalPages: doc.pageCount, dataUrl });
  } catch (err) {
    req.log.error({ err }, "Failed to render PDF page");
    res.status(500).json({ error: "Failed to render page" });
  } finally {
    for (const f of filesToClean) {
      if (fs.existsSync(f)) fs.unlinkSync(f);
    }
  }
});

export default router;
