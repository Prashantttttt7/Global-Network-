import { Router, type IRouter } from "express";
import { eq, count, sql } from "drizzle-orm";
import multer from "multer";
import { randomUUID } from "crypto";
import path from "path";
import fs from "fs";
import os from "os";
import { db, documentsTable, accessGrantsTable, usersTable, accessLogsTable } from "@workspace/db";
import { requireAdmin } from "../middlewares/auth";
import {
  AdminGrantAccessBody,
  AdminDeleteDocumentParams,
  AdminRevokeAccessParams,
} from "@workspace/api-zod";
import { uploadPdf, deletePdf } from "../lib/objectStorage";

const router: IRouter = Router();

// Use memory storage — we upload to GCS and never keep the file locally
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === "application/pdf" || file.originalname.endsWith(".pdf")) {
      cb(null, true);
    } else {
      cb(new Error("Only PDF files are allowed"));
    }
  },
});

function getPdfPageCount(buffer: Buffer): number {
  try {
    // Parse /Count from the PDF page tree — the root /Count is the total page count.
    // latin1 preserves all bytes as single chars so regex matching works on binary data.
    const text = buffer.toString("latin1");
    const matches = [...text.matchAll(/\/Count\s+(\d+)/g)];
    if (matches.length > 0) {
      // The largest /Count value is the root page-tree node (total pages).
      return Math.max(...matches.map((m) => parseInt(m[1], 10)));
    }
  } catch {
    // ignore
  }
  return 1;
}

// List all documents (admin)
router.get("/admin/documents", requireAdmin, async (_req, res): Promise<void> => {
  const docs = await db.select().from(documentsTable).orderBy(documentsTable.uploadedAt);

  // Get access counts
  const accessCounts = await db
    .select({
      documentId: accessGrantsTable.documentId,
      cnt: count(accessGrantsTable.id),
    })
    .from(accessGrantsTable)
    .groupBy(accessGrantsTable.documentId);

  const countMap = new Map(accessCounts.map((r) => [r.documentId, Number(r.cnt)]));

  res.json(
    docs.map((d) => ({
      id: d.id,
      title: d.title,
      description: d.description ?? null,
      pageCount: d.pageCount,
      fileSize: d.fileSize ?? null,
      filename: d.filename,
      uploadedAt: d.uploadedAt.toISOString(),
      accessCount: countMap.get(d.id) ?? 0,
    }))
  );
});

// Upload a PDF document (admin)
router.post(
  "/admin/documents",
  requireAdmin,
  upload.single("file"),
  async (req, res): Promise<void> => {
    if (!req.file) {
      res.status(400).json({ error: "PDF file is required" });
      return;
    }

    const { title, description } = req.body as { title?: string; description?: string };
    if (!title) {
      res.status(400).json({ error: "Title is required" });
      return;
    }

    // Write buffer to a collision-safe tmp file (uploadPdf needs a local path)
    const tmpPath = path.join(os.tmpdir(), `upload-${randomUUID()}.pdf`);
    fs.writeFileSync(tmpPath, req.file.buffer);

    let objectName: string;
    try {
      // Parse page count from the in-memory buffer — no system tools needed
      const pageCount = getPdfPageCount(req.file.buffer);
      const fileSize = req.file.size;

      // Upload to object storage (GCS when configured, local disk otherwise)
      objectName = await uploadPdf(tmpPath);

      const [doc] = await db
        .insert(documentsTable)
        .values({
          title,
          description: description || null,
          filename: objectName,
          pageCount,
          fileSize,
        })
        .returning();

      req.log.info({ docId: doc.id, title, objectName }, "Document uploaded");

      res.status(201).json({
        id: doc.id,
        title: doc.title,
        description: doc.description ?? null,
        pageCount: doc.pageCount,
        fileSize: doc.fileSize ?? null,
        filename: doc.filename,
        uploadedAt: doc.uploadedAt.toISOString(),
        accessCount: 0,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Upload failed";
      req.log.error({ err }, "Document upload failed");
      res.status(500).json({ error: message });
    } finally {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    }
  }
);

// Delete a document (admin)
router.delete("/admin/documents/:id", requireAdmin, async (req, res): Promise<void> => {
  const params = AdminDeleteDocumentParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [doc] = await db
    .select()
    .from(documentsTable)
    .where(eq(documentsTable.id, params.data.id));

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  // Delete from GCS object storage
  await deletePdf(doc.filename);

  // Delete access grants
  await db
    .delete(accessGrantsTable)
    .where(eq(accessGrantsTable.documentId, doc.id));

  // Delete document record
  await db.delete(documentsTable).where(eq(documentsTable.id, doc.id));

  req.log.info({ docId: doc.id }, "Document deleted");
  res.sendStatus(204);
});

// List all access grants (admin)
router.get("/admin/access", requireAdmin, async (_req, res): Promise<void> => {
  const grants = await db
    .select({
      id: accessGrantsTable.id,
      documentId: accessGrantsTable.documentId,
      phone: accessGrantsTable.phone,
      grantedAt: accessGrantsTable.grantedAt,
      documentTitle: documentsTable.title,
    })
    .from(accessGrantsTable)
    .leftJoin(documentsTable, eq(accessGrantsTable.documentId, documentsTable.id))
    .orderBy(accessGrantsTable.grantedAt);

  res.json(
    grants.map((g) => ({
      id: g.id,
      documentId: g.documentId,
      documentTitle: g.documentTitle ?? null,
      phone: g.phone,
      grantedAt: g.grantedAt.toISOString(),
    }))
  );
});

// Grant access (admin)
router.post("/admin/access", requireAdmin, async (req, res): Promise<void> => {
  const parsed = AdminGrantAccessBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const { documentId, phone } = parsed.data;

  // Verify document exists
  const [doc] = await db
    .select()
    .from(documentsTable)
    .where(eq(documentsTable.id, documentId));

  if (!doc) {
    res.status(404).json({ error: "Document not found" });
    return;
  }

  const [grant] = await db
    .insert(accessGrantsTable)
    .values({ documentId, phone })
    .returning();

  req.log.info({ documentId, phone }, "Access granted");

  res.status(201).json({
    id: grant.id,
    documentId: grant.documentId,
    documentTitle: doc.title,
    phone: grant.phone,
    grantedAt: grant.grantedAt.toISOString(),
  });
});

// Revoke access (admin)
router.delete("/admin/access/:id", requireAdmin, async (req, res): Promise<void> => {
  const params = AdminRevokeAccessParams.safeParse(req.params);
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [grant] = await db
    .select()
    .from(accessGrantsTable)
    .where(eq(accessGrantsTable.id, params.data.id));

  if (!grant) {
    res.status(404).json({ error: "Access grant not found" });
    return;
  }

  await db.delete(accessGrantsTable).where(eq(accessGrantsTable.id, params.data.id));

  req.log.info({ grantId: params.data.id }, "Access revoked");
  res.sendStatus(204);
});

// Platform stats (admin)
router.get("/admin/stats", requireAdmin, async (_req, res): Promise<void> => {
  const [docCount] = await db
    .select({ cnt: count(documentsTable.id) })
    .from(documentsTable);

  const [studentCount] = await db
    .select({ cnt: count(usersTable.id) })
    .from(usersTable)
    .where(eq(usersTable.role, "student"));

  const [grantCount] = await db
    .select({ cnt: count(accessGrantsTable.id) })
    .from(accessGrantsTable);

  const [viewCount] = await db
    .select({ cnt: count(accessLogsTable.id) })
    .from(accessLogsTable);

  res.json({
    totalDocuments: Number(docCount.cnt),
    totalStudents: Number(studentCount.cnt),
    totalAccessGrants: Number(grantCount.cnt),
    totalViews: Number(viewCount.cnt),
  });
});

// Access log (admin)
router.get("/admin/access-log", requireAdmin, async (_req, res): Promise<void> => {
  const logs = await db
    .select({
      id: accessLogsTable.id,
      phone: accessLogsTable.phone,
      documentId: accessLogsTable.documentId,
      accessedAt: accessLogsTable.accessedAt,
      documentTitle: documentsTable.title,
    })
    .from(accessLogsTable)
    .leftJoin(documentsTable, eq(accessLogsTable.documentId, documentsTable.id))
    .orderBy(sql`${accessLogsTable.accessedAt} DESC`)
    .limit(50);

  res.json(
    logs.map((l) => ({
      id: l.id,
      phone: l.phone,
      documentTitle: l.documentTitle ?? "Unknown",
      documentId: l.documentId,
      accessedAt: l.accessedAt.toISOString(),
    }))
  );
});

export default router;
