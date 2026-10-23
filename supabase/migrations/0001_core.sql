create type app_role as enum ('admin','owner','viewer');
create type doc_perm as enum ('read','edit');

create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  display_name text,
  role app_role not null default 'viewer',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
-- Role is ALWAYS 'viewer' at signup; user metadata is ignored.
create function handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into profiles(id, email, display_name) values (new.id, lower(new.email), split_part(new.email,'@',1));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

create table documents (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references profiles(id),
  title text not null check (length(title) between 1 and 200),
  description text,
  original_filename text not null,
  storage_key text not null unique,
  category text not null default 'general',
  mime_type text not null check (mime_type in ('application/pdf','image/png','image/jpeg')),
  size_bytes bigint not null check (size_bytes > 0),
  sha256 text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz
);
create index on documents(owner_id);

create table document_permissions (
  id uuid primary key default gen_random_uuid(),
  document_id uuid not null references documents(id) on delete cascade,
  user_id uuid not null references profiles(id),
  permission doc_perm not null,
  granted_by uuid not null references profiles(id),
  granted_at timestamptz not null default now(),
  revoked_at timestamptz
);
create unique index one_active_grant on document_permissions(document_id, user_id) where revoked_at is null;

create table audit_events (
  id bigint generated always as identity primary key,
  actor_id uuid,
  document_id uuid,
  action text not null,
  outcome text not null check (outcome in ('allowed','denied','error')),
  request_id text not null,
  details jsonb not null default '{}',
  created_at timestamptz not null default now(),
  prev_hash text,
  row_hash text
);

-- Hash chain (tamper-EVIDENT only: a DB superuser can recompute it).
-- A single locked head row serialises writers so chain order == write order.
create table audit_head (id int primary key check (id = 1), last_hash text not null);
insert into audit_head values (1, repeat('0',64));
create function audit_chain() returns trigger language plpgsql security definer set search_path = public as $$
declare p text;
begin
  select last_hash into p from audit_head where id = 1 for update;
  new.prev_hash := p;
  new.created_at := clock_timestamp();
  new.row_hash := encode(sha256(convert_to(new.prev_hash || coalesce(new.actor_id::text,'') || coalesce(new.document_id::text,'')
    || new.action || new.outcome || new.request_id || new.details::text || new.created_at::text, 'UTF8')), 'hex');
  update audit_head set last_hash = new.row_hash where id = 1;
  return new;
end $$;
create trigger audit_chain_t before insert on audit_events for each row execute function audit_chain();
create function audit_immutable() returns trigger language plpgsql as $$
begin raise exception 'audit_events is append-only'; end $$;
create trigger audit_no_upd before update or delete on audit_events for each row execute function audit_immutable();
create trigger audit_no_trunc before truncate on audit_events for each statement execute function audit_immutable();

-- Helpers
-- Policy helpers use auth.uid() internally and take no user argument, so a client calling them via
-- /rest/v1/rpc can only learn facts about ITSELF, never probe other users or documents.
create function is_admin() returns boolean language sql stable security definer set search_path = public as
$$ select exists(select 1 from profiles where id = auth.uid() and role = 'admin') $$;
create function is_doc_owner(p_doc uuid) returns boolean language sql stable security definer set search_path = public as
$$ select exists(select 1 from documents where id = p_doc and owner_id = auth.uid()) $$;
create function has_active_grant(p_doc uuid) returns boolean language sql stable security definer set search_path = public as
$$ select exists(select 1 from document_permissions where document_id = p_doc and user_id = auth.uid() and revoked_at is null) $$;
create function can_access_document(p_doc uuid, p_uid uuid, p_need doc_perm) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from documents d where d.id = p_doc and d.deleted_at is null and (
      d.owner_id = p_uid or exists (
        select 1 from document_permissions g where g.document_id = d.id and g.user_id = p_uid and g.revoked_at is null
          and (p_need = 'read' or g.permission = 'edit'))));
$$;
create function log_audit(p_actor uuid, p_doc uuid, p_action text, p_outcome text, p_req text, p_details jsonb)
returns void language sql security definer set search_path = public as
$$ insert into audit_events(actor_id, document_id, action, outcome, request_id, details) values (p_actor,p_doc,p_action,p_outcome,p_req,coalesce(p_details,'{}')) $$;

-- Lock down: clients get SELECT only (through RLS); all writes go through Edge Functions (service role).
alter table profiles enable row level security;
alter table documents enable row level security;
alter table document_permissions enable row level security;
alter table audit_events enable row level security;
alter table audit_head enable row level security;
revoke all on audit_head from anon, authenticated;
revoke all on profiles, documents, document_permissions, audit_events from anon, authenticated;
grant select on profiles, documents, document_permissions, audit_events to authenticated;
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function can_access_document(uuid,uuid,doc_perm), log_audit(uuid,uuid,text,text,text,jsonb) to service_role;
-- RLS policies call these helpers as the authenticated role, so allow only the read-only checks:
grant execute on function is_admin(), is_doc_owner(uuid), has_active_grant(uuid) to authenticated;

create policy profiles_self on profiles for select to authenticated using (id = auth.uid() or is_admin());
-- Policies use SECURITY DEFINER helpers so documents <-> document_permissions never recurse.
create policy docs_visible on documents for select to authenticated using (
  deleted_at is null and (owner_id = auth.uid() or has_active_grant(id)));
create policy perms_visible on document_permissions for select to authenticated using (
  user_id = auth.uid() or is_doc_owner(document_id));
create policy audit_admin_or_owner on audit_events for select to authenticated using (
  is_admin() or (document_id is not null and is_doc_owner(document_id)));

-- Private bucket. NO policies on storage.objects for it => anon/authenticated are denied everything.
insert into storage.buckets(id, name, public) values ('documents','documents',false) on conflict (id) do update set public = false;
