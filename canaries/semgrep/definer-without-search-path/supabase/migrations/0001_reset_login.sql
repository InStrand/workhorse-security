-- Known-bad: a SECURITY DEFINER function with no search_path, attributes before the body.
-- The comment inside the body must not satisfy the rule.
create or replace function public.reset_login(p_user uuid)
returns void
language plpgsql
security definer
as $$
begin
  -- set search_path = public would not count here
  update accounts set failed_attempts = 0 where id = p_user;
end;
$$;

-- Known-bad: the same defect with the attributes after the body.
create function public.close_account(p_user uuid) returns void as $fn$
begin
  delete from accounts where id = p_user;
end;
$fn$ language plpgsql security definer;
