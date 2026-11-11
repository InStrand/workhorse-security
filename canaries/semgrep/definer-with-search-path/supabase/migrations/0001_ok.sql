-- Clean: every SECURITY DEFINER definition fixes its search_path, in each place Postgres allows.
create function public.a() returns int language sql security definer set search_path = '' as $$ select 1; $$;

create function public.b() returns int as $fn$ select 1; $fn$
  language sql security definer set search_path = public, pg_temp;

create function public.c() returns int language sql security definer as $$ select 1; $$;
alter function public.c() set search_path = '';

-- Clean: an invoker function needs no search_path for this rule.
create function public.d() returns int language sql as $$ select 1; $$;

create or replace procedure public.e()
language plpgsql
security definer
set search_path = ''
as $$
begin
  null;
end;
$$;
