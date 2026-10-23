import { admin, audit, authenticate, cors, json, serve, UUID } from "../_shared/common.ts";
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  const rid = crypto.randomUUID();
  const db = admin();
  try {
    const user = await authenticate(req);
    if (!user) { await audit(db, null, null, "download", "denied", rid, { reason: "unauthenticated" }); return json({ error: "unauthorized", request_id: rid }, 401); }
    const id = new URL(req.url).searchParams.get("id") ?? "";
    if (!UUID.test(id)) return json({ error: "bad_request", request_id: rid }, 400);
    // Explicit authorisation BEFORE any privileged (RLS-bypassing) storage access. Evaluated fresh every request.
    const { data: ok, error: permissionError } = await db.rpc("can_access_document", { p_doc: id, p_uid: user.id, p_need: "edit" });
    if (permissionError) {
      await audit(db, user.id, id, "download", "error", rid, { reason: "permission_check_failed" });
      return json({ error: "permission_check_failed", request_id: rid }, 500);
    }
    if (!ok) { await audit(db, user.id, id, "download", "denied", rid, { reason: "download_permission_required" }); return json({ error: "not_found_or_forbidden", request_id: rid }, 403); }
    const { data: doc, error: documentError } = await db.from("documents").select("storage_key,mime_type,original_filename").eq("id", id).single();
    if (documentError || !doc) return json({ error: "document_lookup_failed", request_id: rid }, 500);
    await audit(db, user.id, id, "download", "allowed", rid); // audit first; failure => no bytes
    const { data: blob, error } = await db.storage.from("documents").download(doc.storage_key);
    if (error || !blob) return json({ error: "storage_error", request_id: rid }, 502);
    return new Response(blob, { headers: { ...cors, "Content-Type": doc.mime_type, "X-Content-Type-Options": "nosniff",
      "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(doc.original_filename)}`, "Cache-Control": "no-store" } });
  } catch { return json({ error: "server_error", request_id: rid }, 500); }
});
