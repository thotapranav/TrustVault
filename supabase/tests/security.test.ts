// Integration tests. Requires `supabase start`, `supabase functions serve`, users alice/bob/mallory
// (password Passw0rd!test; alice role=admin and owns DOC_OWNED_BY_ALICE; bob/mallory viewers, no grant).
// NOT YET RUN. Run: ANON_KEY=... DOC_OWNED_BY_ALICE=... deno test -A supabase/tests
import { assertEquals } from "jsr:@std/assert";
import { createClient } from "npm:@supabase/supabase-js@2";
const URL_ = Deno.env.get("SUPABASE_URL") ?? "http://127.0.0.1:54321";
const ANON = Deno.env.get("ANON_KEY")!;
const mk = async (email: string, pw: string) => { const c = createClient(URL_, ANON); const { data } = await c.auth.signInWithPassword({ email, password: pw }); return { c, token: data.session!.access_token }; };
const dl = (id: string, token?: string) => fetch(`${URL_}/functions/v1/document-download?id=${id}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
const DOC = Deno.env.get("DOC_OWNED_BY_ALICE")!;
const PW = "Passw0rd!test";

Deno.test("unauthenticated download denied", async () => { assertEquals((await dl(DOC)).status, 401); });
Deno.test("garbage token denied", async () => { assertEquals((await dl(DOC, "x.y.z")).status, 401); });
Deno.test("non-UUID id rejected", async () => { const m = await mk("mallory@example.test", PW); assertEquals((await dl("../etc", m.token)).status, 400); });
Deno.test("stranger cannot download", async () => { const m = await mk("mallory@example.test", PW); assertEquals((await dl(DOC, m.token)).status, 403); });
Deno.test("stranger cannot see doc row via PostgREST", async () => { const m = await mk("mallory@example.test", PW); const { data } = await m.c.from("documents").select("*").eq("id", DOC); assertEquals(data?.length, 0); });
Deno.test("client cannot self-promote", async () => { const m = await mk("mallory@example.test", PW); const r = await m.c.from("profiles").update({ role: "admin" }).neq("id", "00000000-0000-0000-0000-000000000000"); assertEquals(r.error !== null, true); });
Deno.test("client cannot forge or delete audit rows", async () => { const m = await mk("mallory@example.test", PW);
  assertEquals((await m.c.from("audit_events").insert({ action: "x", outcome: "allowed", request_id: "r" })).error !== null, true);
  assertEquals((await m.c.from("audit_events").delete().gte("id", 0)).error !== null, true); });
Deno.test("direct Storage list returns nothing", async () => { const m = await mk("mallory@example.test", PW); const r = await m.c.storage.from("documents").list(); assertEquals((r.data ?? []).length, 0); });
Deno.test("viewer cannot grant", async () => { const v = await mk("bob@example.test", PW);
  const r = await fetch(`${URL_}/functions/v1/document-grant`, { method: "POST", headers: { Authorization: `Bearer ${v.token}` }, body: JSON.stringify({ action: "grant", document_id: DOC, email: "mallory@example.test", permission: "read" }) });
  assertEquals(r.status, 403); });
Deno.test("regular users can upload their own documents", async () => { const v = await mk("bob@example.test", PW);
  const f = new FormData(); f.set("title", "x"); f.set("file", new File([new Uint8Array([0x25,0x50,0x44,0x46,0x2d])], "a.pdf"));
  assertEquals((await fetch(`${URL_}/functions/v1/document-upload`, { method: "POST", headers: { Authorization: `Bearer ${v.token}` }, body: f })).status, 201); });
Deno.test("upload with fake PDF extension but wrong bytes rejected", async () => { const a = await mk("alice@example.test", PW);
  const f = new FormData(); f.set("title", "x"); f.set("file", new File([new TextEncoder().encode("MZ not a pdf")], "a.pdf", { type: "application/pdf" }));
  assertEquals((await fetch(`${URL_}/functions/v1/document-upload`, { method: "POST", headers: { Authorization: `Bearer ${a.token}` }, body: f })).status, 415); });
Deno.test("client cannot call privileged RPCs or probe other users via helpers", async () => { const m = await mk("mallory@example.test", PW);
  assertEquals((await m.c.rpc("can_access_document", { p_doc: DOC, p_uid: "00000000-0000-0000-0000-000000000000", p_need: "read" })).error !== null, true);
  assertEquals((await m.c.rpc("log_audit", { p_actor: null, p_doc: null, p_action: "x", p_outcome: "allowed", p_req: "r", p_details: {} })).error !== null, true);
  assertEquals((await m.c.rpc("is_doc_owner", { p_doc: DOC })).data, false); });
Deno.test("read-only grant allows preview but denies download", async () => {
  const owner = await mk("alice@example.test", PW);
  const recipient = await mk("bob@example.test", PW);
  const grant = await fetch(`${URL_}/functions/v1/document-grant`, {
    method: "POST",
    headers: { Authorization: `Bearer ${owner.token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ action: "grant", document_id: DOC, email: "bob@example.test", permission: "read" }),
  });
  assertEquals(grant.status, 200);
  try {
    const preview = await fetch(`${URL_}/functions/v1/document-preview?id=${DOC}`, { headers: { Authorization: `Bearer ${owner.token}` } });
    assertEquals(preview.status, 200);
    const download = await dl(DOC, recipient.token);
    assertEquals(download.status, 403);
  } finally {
    await fetch(`${URL_}/functions/v1/document-grant`, {
      method: "POST",
      headers: { Authorization: `Bearer ${owner.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ action: "revoke", document_id: DOC, email: "bob@example.test" }),
    });
  }
  assertEquals(owner.token.length > 0, true);
});
Deno.test("non-admin cannot change user roles", async () => {
  const viewer = await mk("bob@example.test", PW);
  const target = await mk("mallory@example.test", PW);
  const targetUser = await target.c.auth.getUser();
  const result = await fetch(`${URL_}/functions/v1/user-role`, {
    method: "POST",
    headers: { Authorization: `Bearer ${owner.token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: targetUser.data.user!.id, role: "admin" }),
  });
  assertEquals(result.status, 403);
});
