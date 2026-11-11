# Postgres and Supabase Hunting

#### When to use this file

Reach for this file when the target defines Postgres functions, grants, policies or views in SQL migrations, or runs on Supabase (a `supabase/` directory, PostgREST or RPC calls from clients, Edge Functions). It covers what the database itself lets a caller do. Use `DATA-ISOLATION-AND-LIFECYCLE.md` for tenant isolation across copies of data and `ATTACK-CLASSES.md` for access control in application code.

Split large targets by schema, then by: functions that run with their owner's rights, grants and default privileges, row-level security, views, Edge Functions, and migrations that change deployed objects.

## Core discipline (include in every agent prompt for this domain)

```
- The repository is not the database. A migration can read a deployed function's body, edit it as text and execute the result, and a setting can be changed in a dashboard. State every claim about a deployed function, grant, policy or setting as "per the repository". When the deployed state decides the finding and no catalogue snapshot was supplied, use needs_validation and give the exact catalogue query the owner can run.
- The effective definition of a function, policy or grant is the last statement that touches it when the migrations replay in order. Find the last one. Do not stop at the first match.
- Postgres lets every role execute a new function unless execute is revoked from PUBLIC, and Supabase's default privileges also grant it to the API roles. For each SECURITY DEFINER function in an exposed schema, answer two questions from source: which roles can execute it, and what does it do with its owner's rights.
- The anonymous key is public. Whatever the anon role can select, insert, update, delete or call through the API is reachable by anyone on the internet.
- Row-level security that is enabled is not yet row-level security that enforces the intended rule. Read each policy's command, roles, USING and WITH CHECK. The service role and a table's owner bypass policies.
```

## Privileged function attack classes (subagent_type: `general`)

**Anonymous-executable privileged function**
A SECURITY DEFINER function or procedure in a schema the API exposes, with no revoke of execute from PUBLIC or the anonymous role, and no check of the caller inside the body. Trace what it reads or writes with its owner's rights and which arguments the caller controls.

**Mutable search_path in a privileged function**
A SECURITY DEFINER function with no `set search_path` resolves unqualified names through the caller's search_path. Check whether any calling role can create objects in a schema that would be searched first, and which unqualified tables, functions or operators the body uses.

**NULL and missing-row holes in authentication functions**
A login, token or permission function that compares against a stored value which can be NULL, or that selects a row into variables and continues when no row matches. In SQL a comparison with NULL is neither true nor false, so `if not matches then raise` does not raise. Walk every branch with a NULL input, a NULL stored value and a missing row.

**Dynamic SQL built from caller input**
`execute` on text assembled with `||` or `format('%s')` from an argument, a column the caller can write, or a JSON field. Check `%I` and `%L` use, `quote_ident`, and whether the statement runs with the definer's rights.

**Read-shaped path that writes**
A function, RPC or query endpoint presented as read-only (a name such as get, list, select or query; marked stable; called with GET) that can change state: a volatile function inside, a data-modifying CTE, or caller-supplied SQL passed to `execute`. Check what enforces read-only, and whether it is the statement text or the transaction.

## Grant, policy and view attack classes (subagent_type: `general`)

**Privilege granted to the anonymous role**
`grant` or `alter default privileges` naming the anonymous role on a table, sequence, function or schema objects. For each, find the policy or in-function check that limits what the anonymous caller receives.

**Table in an exposed schema with no enforced policy**
Row-level security not enabled, enabled with no policy for a command the role is granted, or a policy whose expression is always true. Include tables created by later migrations and by `create table as`.

**Policy that trusts caller-editable identity**
A policy or function that reads a claim the user can set (user metadata, a header, a request argument for the user or organisation id) instead of the verified subject.

**View or function that runs as its owner**
A view without `security_invoker`, or a SECURITY DEFINER function that returns rows, exposes a table past its row-level security. Check which roles can select from it.

## Deployed-state attack classes (subagent_type: `general`)

**Function body that exists only in the database**
A migration that calls `pg_get_functiondef`, rewrites the text and executes it, or a function changed by hand. The repository cannot show the current body. Record the function, the migrations that rewrote it, and a needs_validation item asking for the deployed definition.

**Edge Function reachable without a verified caller**
JWT verification switched off in configuration for a function that has no check of its own, a scheduled function that anyone can call because nothing proves the caller is the scheduler, or a function that uses the service role with filters taken from the request.

**Seed or baseline data applied to production**
A seed, baseline or fixture file that a deploy or loader job runs against the production database. Check what it inserts or overwrites and whether it carries credentials or real records.

## Universal moves (apply across the above)

- List every SECURITY DEFINER function with its last definition, its search_path setting, the roles that can execute it and the first line that checks the caller. The gaps in that table are the work list.
- For one protected table, write down each role's path to it: direct API access, each view, each function that returns or changes its rows, each Edge Function that uses the service role.
- Read the grants and default privileges before the policies. A policy cannot protect what a function or view returns as its owner.
- When two migrations disagree, the later one is the truth per the repository. Say which file and line.

## Validation rules (apply before reporting ANY finding here)

1. Name the calling role (anonymous, authenticated, a named application role), the object, the privilege or code path that lets the call through, and the row or state the caller reads or changes.
2. Cite the last definition of every object in the trace, and the grant or default privilege that makes it reachable. A finding that depends on an earlier, superseded definition is rejected.
3. Prove behaviour with a local Postgres and dummy rows only when the sandbox allows it. Never connect to a deployed database.
4. When the deployed catalogue could differ from the repository (rewritten bodies, dashboard settings, hand-applied changes), return `needs_validation` with the catalogue query that settles it.
5. Return `confirmed` only when the repository alone establishes the path and the result.
