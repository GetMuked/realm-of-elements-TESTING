-- Realm of Elements secure authentication migration
-- Run this entire file in Supabase SQL Editor.

create extension if not exists pgcrypto with schema extensions;

-- Keep the existing audit table compatible with this migration.
alter table if exists public.login_history
  add column if not exists staff_username text,
  add column if not exists staff_password text;

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.staff_members (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  rank text not null default 'Staff',
  password_hash text not null,
  strikes integer not null default 0,
  strike_history jsonb not null default '[]'::jsonb,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.staff_sessions (
  token_hash text primary key,
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  staff_id uuid not null references public.staff_members(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;
alter table public.staff_members enable row level security;
alter table public.staff_sessions enable row level security;

-- Login history should never store plaintext staff passwords.
alter table public.login_history drop column if exists staff_password;

create or replace function public.is_roe_admin()
returns boolean
language sql
security definer
set search_path = public, extensions
stable
as $$
  select exists (
    select 1 from public.admin_users
    where user_id = auth.uid()
  );
$$;

create or replace function public.create_staff_member(
  p_username text,
  p_rank text,
  p_password text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  new_id uuid;
  clean_username text := trim(p_username);
begin
  if not public.is_roe_admin() then
    raise exception 'Not authorized';
  end if;

  if clean_username is null or length(clean_username) < 3 or length(clean_username) > 32 then
    raise exception 'Username must be between 3 and 32 characters';
  end if;

  if p_password is null or length(p_password) < 8 or length(p_password) > 128 then
    raise exception 'Password must be between 8 and 128 characters';
  end if;

  if p_rank not in ('Trial Staff', 'Staff', 'Senior Staff') then
    raise exception 'Invalid staff rank';
  end if;

  insert into public.staff_members (username, rank, password_hash)
  values (clean_username, p_rank, extensions.crypt(p_password, extensions.gen_salt('bf', 12)))
  returning id into new_id;

  return jsonb_build_object('id', new_id, 'username', clean_username, 'rank', p_rank);
exception
  when unique_violation then
    raise exception 'That username already has a staff profile.';
end;
$$;

create or replace function public.list_staff_members()
returns table (
  id uuid,
  username text,
  rank text,
  strikes integer,
  strike_history jsonb,
  active boolean
)
language sql
security definer
set search_path = public, extensions
stable
as $$
  select s.id, s.username, s.rank, s.strikes, s.strike_history, s.active
  from public.staff_members s
  where public.is_roe_admin()
    and s.active = true
  order by s.created_at desc;
$$;

create or replace function public.punish_staff_member(
  p_staff_id uuid,
  p_reason text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  new_strikes integer;
  new_history jsonb;
begin
  if not public.is_roe_admin() then
    raise exception 'Not authorized';
  end if;
  if p_reason is null or length(trim(p_reason)) = 0 then
    raise exception 'A reason is required';
  end if;

  update public.staff_members
  set strikes = strikes + 1,
      strike_history = strike_history || jsonb_build_array(
        jsonb_build_object('reason', trim(p_reason), 'date', now())
      )
  where id = p_staff_id and active = true
  returning strikes, strike_history into new_strikes, new_history;

  if new_strikes is null then
    raise exception 'Staff member not found';
  end if;

  return jsonb_build_object('strikes', new_strikes, 'strike_history', new_history);
end;
$$;

create or replace function public.deactivate_staff_member(p_staff_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  changed boolean;
begin
  if not public.is_roe_admin() then
    raise exception 'Not authorized';
  end if;

  update public.staff_members
  set active = false
  where id = p_staff_id and active = true;
  changed := found;

  delete from public.staff_sessions where staff_id = p_staff_id;
  return changed;
end;
$$;

-- Staff authentication is bound to the authenticated Discord/Supabase user,
-- but the Discord identity is intentionally NOT linked to the staff profile.
create or replace function public.verify_staff_login(
  p_username text,
  p_password text,
  p_discord_id text default null,
  p_discord_username text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  member public.staff_members%rowtype;
  raw_token text;
  v_token_hash text;
  ok boolean := false;
begin
  if auth.uid() is null then
    raise exception 'Discord authentication required';
  end if;

  select * into member
  from public.staff_members
  where lower(username) = lower(trim(p_username))
    and active = true
  limit 1;

  if found then
    ok := extensions.crypt(coalesce(p_password, ''), member.password_hash) = member.password_hash;
  end if;

  insert into public.login_history (
    discord_username,
    discord_id,
    login_time,
    result,
    staff_username
  ) values (
    p_discord_username,
    p_discord_id,
    now(),
    case when ok then 'successful' else 'failed' end,
    trim(p_username)
  );

  if not ok then
    return jsonb_build_object('success', false);
  end if;

  raw_token := encode(extensions.gen_random_bytes(32), 'hex');
  v_token_hash := encode(extensions.digest(raw_token, 'sha256'), 'hex');

  insert into public.staff_sessions (token_hash, auth_user_id, staff_id, expires_at)
  values (v_token_hash, auth.uid(), member.id, now() + interval '12 hours');

  return jsonb_build_object(
    'success', true,
    'session_token', raw_token,
    'staff_id', member.id,
    'username', member.username,
    'rank', member.rank,
    'strikes', member.strikes,
    'strike_history', member.strike_history
  );
end;
$$;

create or replace function public.get_staff_session(p_session_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  session_row public.staff_sessions%rowtype;
  member public.staff_members%rowtype;
  v_token_hash text;
begin
  if auth.uid() is null or p_session_token is null then
    return jsonb_build_object('valid', false);
  end if;

  v_token_hash := encode(extensions.digest(p_session_token, 'sha256'), 'hex');

  select * into session_row
  from public.staff_sessions
  where staff_sessions.token_hash = v_token_hash
    and auth_user_id = auth.uid()
    and expires_at > now();

  if not found then
    return jsonb_build_object('valid', false);
  end if;

  select * into member
  from public.staff_members
  where id = session_row.staff_id and active = true;

  if not found then
    delete from public.staff_sessions where staff_sessions.token_hash = v_token_hash;
    return jsonb_build_object('valid', false);
  end if;

  return jsonb_build_object(
    'valid', true,
    'staff_id', member.id,
    'username', member.username,
    'rank', member.rank,
    'strikes', member.strikes,
    'strike_history', member.strike_history
  );
end;
$$;

create or replace function public.logout_staff_session(p_session_token text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_token_hash text;
begin
  if auth.uid() is null or p_session_token is null then
    return false;
  end if;
  v_token_hash := encode(extensions.digest(p_session_token, 'sha256'), 'hex');
  delete from public.staff_sessions
  where staff_sessions.token_hash = v_token_hash
    and auth_user_id = auth.uid();
  return found;
end;
$$;

-- Tighten login-history reads: only authenticated admins may read them.
drop policy if exists "Allow authenticated admins to read login history" on public.login_history;
drop policy if exists "Allow login history inserts" on public.login_history;

-- RPCs above insert login history server-side, so clients do not need direct INSERT access.
-- No public SELECT/INSERT policies are created for login_history.

revoke all on table public.staff_members from anon, authenticated;
revoke all on table public.staff_sessions from anon, authenticated;
revoke all on table public.admin_users from anon, authenticated;

revoke all on function public.create_staff_member(text,text,text) from public;
revoke all on function public.list_staff_members() from public;
revoke all on function public.punish_staff_member(uuid,text) from public;
revoke all on function public.deactivate_staff_member(uuid) from public;
revoke all on function public.verify_staff_login(text,text,text,text) from public;
revoke all on function public.get_staff_session(text) from public;
revoke all on function public.logout_staff_session(text) from public;

-- Authenticated users may invoke these RPCs; each function performs its own authorization.
grant execute on function public.create_staff_member(text,text,text) to authenticated;
grant execute on function public.list_staff_members() to authenticated;
grant execute on function public.punish_staff_member(uuid,text) to authenticated;
grant execute on function public.deactivate_staff_member(uuid) to authenticated;
grant execute on function public.verify_staff_login(text,text,text,text) to authenticated;
grant execute on function public.get_staff_session(text) to authenticated;
grant execute on function public.logout_staff_session(text) to authenticated;

drop function if exists public.admin_can_read_login_history();
create or replace function public.get_login_history()
returns table (
  id bigint,
  discord_username text,
  discord_id text,
  staff_username text,
  login_time timestamptz,
  result text
)
language sql
security definer
set search_path = public, extensions
stable
as $$
  select lh.id, lh.discord_username, lh.discord_id, lh.staff_username, lh.login_time, lh.result
  from public.login_history lh
  where public.is_roe_admin()
  order by lh.login_time desc;
$$;
revoke all on function public.get_login_history() from public;
grant execute on function public.get_login_history() to authenticated;
