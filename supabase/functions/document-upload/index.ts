import { admin, audit, authenticate, cors, json, serve } from "../_shared/common.ts";
const MAX = Number(Deno.env.get("MAX_UPLOAD_BYTES") ?? 10 * 1024 * 1024);
// Server-side signature check; browser MIME/extension are never trusted.
function sniff(b: Uint8Array): string | null {
  if (b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) return "application/pdf";
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  return null;
}
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  const rid = crypto.randomUUID(); const db = admin();
  try {
    const user = await authenticate(req);
    if (!user) return json({ error: "unauthorized", request_id: rid }, 401);
    const form = await req.formData().catch(() => null);
    const file = form?.get("file"); const title = String(form?.get("title") ?? "").trim();
    if (!(file instanceof File) || !title || title.length > 200) return json({ error: "bad_request", request_id: rid }, 400);
    if (file.size === 0 || file.size > MAX) return json({ error: "invalid_size", request_id: rid }, 413);
    const bytes = new Uint8Array(await file.arrayBuffer());
    const mime = sniff(bytes);
    if (!mime) { await audit(db, user.id, null, "upload", "denied", rid, { reason: "bad_signature" }); return json({ error: "unsupported_type", request_id: rid }, 415); }
    const sha = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((x) => x.toString(16).padStart(2, "0")).join("");
    const key = `${user.id}/${crypto.randomUUID()}`; // server-generated, never user-supplied
    const up = await db.storage.from("documents").upload(key, bytes, { contentType: mime, upsert: false });
    if (up.error) return json({ error: "storage_error", request_id: rid }, 502);
    const { data: doc, error } = await db.from("documents").insert({ owner_id: user.id, title, description: String(form?.get("description") ?? "").slice(0, 1000),
      category: String(form?.get("category") ?? "general").slice(0, 60) || "general", original_filename: file.name.slice(0, 200), storage_key: key, mime_type: mime, size_bytes: file.size, sha256: sha }).select("id").single();
    if (error) { await db.storage.from("documents").remove([key]); return json({ error: "db_error", request_id: rid }, 500); } // no orphans
    await audit(db, user.id, doc.id, "upload", "allowed", rid, { size: file.size, mime });
    return json({ id: doc.id, request_id: rid }, 201);
  } catch { return json({ error: "server_error", request_id: rid }, 500); }
});
