import { admin, authenticate, authenticatedClient, cors, json, serve } from "../_shared/common.ts";

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  if (req.method !== "GET") return json({ error: "method_not_allowed" }, 405);
  try {
    const user = await authenticate(req);
    if (!user) return json({ error: "unauthorized" }, 401);
    const query = new URL(req.url).searchParams.get("q")?.trim() ?? "";
    if (query.length < 2 || query.length > 100) return json({ error: "invalid_query" }, 400);
    const { data, error } = await authenticatedClient(req).rpc("search_profiles", { p_query: query });
    if (error) return json({ error: "search_failed" }, 500);
    const db = admin();
    const { data: profile, error: profileError } = await db.from("profiles").select("role").eq("id", user.id).maybeSingle();
    if (profileError || !profile) return json({ error: "profile_lookup_failed" }, 500);
    const users = data ?? [];
    if (profile?.role === "admin" && users.length > 0) {
      const { data: roles, error: roleError } = await db.from("profiles").select("id,role")
        .in("id", users.map((result) => result.id));
      if (roleError) return json({ error: "search_failed" }, 500);
      const roleById = new Map((roles ?? []).map((result) => [result.id, result.role]));
      return json({ users: users.map((result) => ({ ...result, role: roleById.get(result.id) })) });
    }
    return json({ users });
  } catch {
    return json({ error: "server_error" }, 500);
  }
});
