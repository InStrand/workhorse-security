-- Clean: no privilege reaches the anonymous role.
grant usage on schema public to anon;
grant select on table public.accounts to authenticated;
grant execute on function public.reset_login(uuid) to service_role;
revoke all on table public.accounts from anon;
grant select on table public.anonymous_feedback to authenticated;
