update public.profiles
set role = 'admin', updated_at = now()
where email = lower('pranavthota702@gmail.com');

create or replace function search_profiles(p_query text)
returns table(id uuid, email text, display_name text)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  q text;
begin
  if auth.uid() is null then
    raise exception 'authentication required';
  end if;
  q := left(trim(coalesce(p_query, '')), 100);
  if length(q) < 2 then
    return;
  end if;
  return query
    select p.id, p.email, p.display_name
    from profiles p
    where p.email ilike '%' || replace(replace(replace(q, '\', '\\'), '%', '\%'), '_', '\_') || '%' escape '\'
       or coalesce(p.display_name, '') ilike '%' || replace(replace(replace(q, '\', '\\'), '%', '\%'), '_', '\_') || '%' escape '\'
    order by p.display_name nulls last, p.email
    limit 20;
end
$$;

revoke all on function search_profiles(text) from public, anon;
grant execute on function search_profiles(text) to authenticated;

create function set_document_permissions(
  p_document uuid,
  p_actor uuid,
  p_targets uuid[],
  p_action text,
  p_permission doc_perm
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_action not in ('grant', 'revoke') or coalesce(cardinality(p_targets), 0) = 0 then
    raise exception 'invalid sharing request';
  end if;
  if exists (select 1 from documents where id = p_document and owner_id = p_actor and deleted_at is null) is not true then
    raise exception 'document owner required';
  end if;
  if p_actor = any(p_targets) or exists (
    select 1 from unnest(p_targets) as recipients(target_id)
    where not exists (select 1 from profiles where id = recipients.target_id)
  ) then
    raise exception 'invalid recipient';
  end if;
  update document_permissions
  set revoked_at = now()
  where document_id = p_document and user_id = any(p_targets) and revoked_at is null;
  if p_action = 'grant' then
    insert into document_permissions(document_id, user_id, permission, granted_by)
    select p_document, target_id, p_permission, p_actor
    from (select distinct unnest(p_targets) as target_id) recipients;
  end if;
end
$$;

revoke all on function set_document_permissions(uuid, uuid, uuid[], text, doc_perm) from public, anon, authenticated;
grant execute on function set_document_permissions(uuid, uuid, uuid[], text, doc_perm) to service_role;
