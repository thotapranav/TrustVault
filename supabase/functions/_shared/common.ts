import { createClient } from "npm:@supabase/supabase-js@2";
export const cors = {
  "Access-Control-Allow-Origin": Deno.env.get("ALLOWED_ORIGIN") ?? "http://localhost:5173",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, content-type",
};
const configuredOrigins = (Deno.env.get("ALLOWED_ORIGIN") ?? "http://localhost:5173")
  .split(",").map((origin) => origin.trim()).filter(Boolean);

function corsForRequest(req: Request) {
  const origin = req.headers.get("Origin");
  const localDevelopmentOrigin = origin !== null && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  const allowedOrigin = origin && (configuredOrigins.includes(origin) || localDevelopmentOrigin)
    ? origin
    : configuredOrigins[0] ?? "http://localhost:5173";
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, content-type",
    Vary: "Origin",
  };
}

export function serve(handler: (req: Request) => Promise<Response>) {
  Deno.serve(async (req) => {
    const response = await handler(req);
    const headers = new Headers(response.headers);
    for (const [name, value] of Object.entries(corsForRequest(req))) headers.set(name, value);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  });
}
export const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });
export const admin = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
export const authenticatedClient = (req: Request) => createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_ANON_KEY")!,
  { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } },
);
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Identity comes ONLY from auth.getUser() (server-verified). Never from the body. */
export async function authenticate(req: Request) {
  const auth = req.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  const c = authenticatedClient(req);
  const { data, error } = await c.auth.getUser();
  return error || !data.user ? null : data.user;
}
/** Fail closed: if the audit row can't be written, the caller must NOT return protected data. */
export async function audit(db: ReturnType<typeof admin>, actor: string | null, doc: string | null, action: string, outcome: string, rid: string, details: Record<string, unknown> = {}) {
  const { error } = await db.rpc("log_audit", { p_actor: actor, p_doc: doc, p_action: action, p_outcome: outcome, p_req: rid, p_details: details });
  if (error) throw new Error("audit_failed");
}
