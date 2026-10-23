import { admin, audit, authenticate, cors, json, serve, UUID } from "../_shared/common.ts";
// POST { action, document_id, user_id? | email? | all_users?, permission? } — owner only.
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  const rid = crypto.randomUUID(); const db = admin();
  try {
    const user = await authenticate(req);
    if (!user) return json({ error: "unauthorized", request_id: rid }, 401);
    const b = await req.json().catch(() => null);
    const hasOneRecipient = Number(typeof b?.user_id === "string") + Number(typeof b?.email === "string") + Number(b?.all_users === true) === 1;
    if (!b || !UUID.test(b.document_id) || !["grant", "revoke"].includes(b.action) || !hasOneRecipient
        || (b.action === "grant" && !["read", "edit"].includes(b.permission))) return json({ error: "bad_request", request_id: rid }, 400);
    const { data: doc, error: documentError } = await db.from("documents").select("owner_id")
      .eq("id", b.document_id).is("deleted_at", null).maybeSingle();
    if (documentError) return json({ error: "document_lookup_failed", request_id: rid }, 500);
    if (!doc || doc.owner_id !== user.id) { // admin status deliberately NOT sufficient
      await audit(db, user.id, b.document_id, b.action, "denied", rid); return json({ error: "not_found_or_forbidden", request_id: rid }, 403); }
    let targets: { id: string }[] = [];
    if (b.all_users === true) {
      const pageSize = 1000;
      for (let start = 0; ; start += pageSize) {
        const { data, error } = await db.from("profiles").select("id").neq("id", user.id)
          .order("id").range(start, start + pageSize - 1);
        if (error) return json({ error: "recipient_lookup_failed", request_id: rid }, 500);
        targets.push(...(data ?? []));
        if (!data || data.length < pageSize) break;
      }
    } else {
      const query = db.from("profiles").select("id");
      const { data: target, error } = typeof b.user_id === "string"
        ? await query.eq("id", b.user_id).maybeSingle()
        : await query.eq("email", b.email.toLowerCase()).maybeSingle();
      if (error) return json({ error: "recipient_lookup_failed", request_id: rid }, 500);
      if (target && target.id !== user.id) targets = [target];
    }
    if (targets.length === 0) return json({ error: "invalid_target", request_id: rid }, 422);
    const targetIds = targets.map((target) => target.id);
    const { error: sharingError } = await db.rpc("set_document_permissions", {
      p_document: b.document_id,
      p_actor: user.id,
      p_targets: targetIds,
      p_action: b.action,
      p_permission: b.action === "grant" ? b.permission : "read",
    });
    if (sharingError) return json({ error: "sharing_update_failed", request_id: rid }, 500);
    await audit(db, user.id, b.document_id, b.action, "allowed", rid, {
      recipient_count: targetIds.length,
      target_user: targetIds.length === 1 ? targetIds[0] : null,
      all_users: b.all_users === true,
      permission: b.permission ?? null,
    });
    return json({ ok: true, request_id: rid });
  } catch { return json({ error: "server_error", request_id: rid }, 500); }
});
