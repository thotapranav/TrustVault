# TrustVault (Snovasis round 2) - security core

## Implemented
- `supabase/migrations/0001_core.sql`: profiles/documents/document_permissions/audit_events, one-active-grant unique index, RLS (clients SELECT-only; all writes via Edge Functions), append-only audit with SHA-256 hash chain, private `documents` bucket with NO storage policies (clients denied).
- Edge Functions: `document-upload` (signed-in users, size limit, magic-byte sniff, server-generated key, sha256, rollback on DB failure), `document-preview` (read-grant preview), `document-download` (owner/editor only; fresh permission check), `document-grant` (specific or global grant + revoke, owner-only), `users-search`, and `user-role` (admin-only).
- `src/`: React app with sign-in, sign-up, password reset, dashboard, searchable document library, secure upload/download, sharing controls and an audit-history view. The screens use the Supabase Auth, database and Edge Function endpoints described below; this is not a mock-data frontend.
- `supabase/tests/security.test.ts`: integration tests for upload, sharing, role changes, audit integrity and access control.

## Permission model
Every signed-in user can upload and becomes the document owner. Owners share their own documents with one registered account or all currently registered users. A `read` grant permits preview only; an `edit` grant permits preview and download. Admin status does not confer access to other people's documents. Admins can inspect audit history and change user roles. Role is never taken from a request or user metadata; new users are `viewer`.

## Service-role use (RLS bypass)
Only inside Edge Functions, always after verified identity (`auth.getUser`) plus ownership/grant check. The key lives in Edge secrets, never in Vite env.

## Revocation semantics
Revocation sets `revoked_at`. Every download re-checks the DB, so the next request fails. A download already streaming may complete; copies already downloaded cannot be recalled.

## Audit failure behaviour
Fail closed: if the audit insert fails the function returns 500 with no file bytes. Caveat: the "allowed" row is written just before the storage fetch, so a storage failure leaves an allowed row plus a 502.

## Limitations
Hash chain is tamper-evident only; a DB superuser can rewrite and re-hash. Export `row_hash` checkpoints off-system for stronger evidence. No antivirus or content sanitisation.

## Run locally
The frontend is served at `http://localhost:5173`. The Supabase backend must also be running for sign-in, signup, uploads, downloads and sharing to work.

1. Install the Supabase CLI and Docker Desktop, then run `supabase start` from the project directory.
2. Apply the database migration with `supabase db reset`.
3. Create `supabase/.env` for the Edge Functions with `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY`. Use the local values printed by `supabase status`; keep the service-role key only in this functions env file. Localhost and 127.0.0.1 frontend origins on any port are allowed for development. For deployment, set `ALLOWED_ORIGIN` to the exact production origin (multiple comma-separated origins are supported).
4. Start the functions in a separate terminal: `supabase functions serve --env-file supabase/.env`.
5. Copy `.env.example` to `.env` in the project root and set `VITE_SUPABASE_URL=http://127.0.0.1:54321` plus the local anon key from `supabase status`. The browser key is the anon key, never the service-role key.
6. From the project directory run `npm install` and `npm run dev`, then open the local URL printed by Vite. Restart Vite after changing `.env`.
7. Register the designated administrator account from the sign-in page and confirm its email. The `0003_user_sharing_and_admin.sql` migration promotes that exact existing profile; if the migration ran before the account existed, promote it afterward in the Supabase SQL editor with `update public.profiles set role='admin', updated_at=now() where email=lower('pranavthota702@gmail.com');`. Set or reset its password through Supabase Auth; credentials are not stored in source code or migrations. New accounts are viewers by default.
8. Tests: see the setup instructions at the top of `supabase/tests/security.test.ts`.

Without a root `.env`, the app shows the local Supabase setup steps instead of a blank page. Activity history is restricted by database row-level security: users can see their own audit events, document owners can see events for their documents, and administrators can see all events.

## Deploy to hosted Supabase
For a hosted project, sign in with the Supabase CLI and link the project whose URL is configured by `VITE_SUPABASE_URL`. Then apply migrations and deploy the Edge Functions:

```powershell
supabase login
supabase link --project-ref <project-ref>
supabase db push
supabase functions deploy document-upload
supabase functions deploy document-download
supabase functions deploy document-preview
supabase functions deploy document-grant
supabase functions deploy users-search
supabase functions deploy user-role
supabase secrets set ALLOWED_ORIGIN=https://your-app.example.com
```

The Edge Function secrets `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` must be available in the project. Never put the service-role key in the frontend `.env`. A Supabase `NOT_FOUND` response from `/functions/v1/document-upload` means that function has not been deployed to the configured project.

## Limitations
Document editing/deletion, audit export, seed data, and pagination controls are not implemented. The `edit` permission enables downloading but does not edit the file in-app. Global sharing applies to accounts currently registered and does not automatically include future signups. The browser only uses the Supabase anon key; privileged operations go through verified Edge Functions.

## Review fixes in this version
RLS policy recursion (documents<->document_permissions) fixed via security-definer helpers; pgcrypto dependency removed; `verify_jwt=false` so CORS preflight works (each function still verifies the user via `auth.getUser`); TypeScript query-order and form-typing errors fixed.
Second review: audit hash chain made race-free (locked head row); policy helpers no longer accept a user id (cannot be used via RPC to probe other users); UI state cleared on sign-out; field-length caps.
