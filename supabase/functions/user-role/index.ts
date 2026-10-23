import { admin, audit, authenticate, cors, json, serve, UUID } from "../_shared/common.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  const rid = crypto.randomUUID();
  const db = admin();
  try {
    const actor = await authenticate(req);
    if (!actor) return json({ error: "unauthorized", request_id: rid }, 401);
    const { data: adminProfile, error: profileError } = await db.from("profiles")
      .select("role").eq("id", actor.id).maybeSingle();
    if (profileError) return json({ error: "profile_error", request_id: rid }, 500);
    if (adminProfile?.role !== "admin") {
      await audit(db, actor.id, null, "role_change", "denied", rid, { reason: "not_admin" });
      return json({ error: "forbidden", request_id: rid }, 403);
    }
    const body = await req.json().catch(() => null);
    if (!body || !UUID.test(body.user_id) || !["admin", "owner", "viewer"].includes(body.role)) {
      return json({ error: "bad_request", request_id: rid }, 400);
    }
    const { data: target, error: targetError } = await db.from("profiles")
      .select("id,role").eq("id", body.user_id).maybeSingle();
    if (targetError) return json({ error: "profile_error", request_id: rid }, 500);
    if (!target) return json({ error: "user_not_found", request_id: rid }, 404);
    if (target.id === actor.id && body.role !== "admin") {
      return json({ error: "cannot_remove_own_admin_role", request_id: rid }, 409);
    }
    const { error: updateError } = await db.from("profiles")
      .update({ role: body.role, updated_at: new Date().toISOString() }).eq("id", target.id);
    if (updateError) return json({ error: "role_update_failed", request_id: rid }, 500);
    await audit(db, actor.id, null, "role_change", "allowed", rid, {
      target_user: target.id,
      previous_role: target.role,
      new_role: body.role,
    });
    return json({ ok: true, request_id: rid });
  } catch {
    return json({ error: "server_error", request_id: rid }, 500);
  }
});
