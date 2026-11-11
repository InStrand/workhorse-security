-- Known-bad: privileges granted to the anonymous role.
grant execute on function public.reset_login(uuid) to anon, authenticated;

grant select, insert
  on table public.accounts
  to authenticated, anon;

alter default privileges in schema public grant all on tables to anon;
