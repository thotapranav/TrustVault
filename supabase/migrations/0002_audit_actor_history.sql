drop policy if exists audit_admin_or_owner on audit_events;
create policy audit_admin_owner_or_actor on audit_events for select to authenticated using (
  actor_id = auth.uid()
  or is_admin()
  or (document_id is not null and is_doc_owner(document_id))
);
