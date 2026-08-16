-- HMR Purple Elites — cloud storage schema
-- Run this in the SAME Supabase project you already created for LawShare
-- (Project → SQL Editor → New query). It only adds two new tables —
-- hmr_admins and hmr_state — completely separate from the LawShare
-- tables (profiles/files/file_shares), so this can't affect that app.
--
-- The app's login screen only asks for a password (see index.html).
-- Behind the scenes it signs in as one fixed account. This row must
-- match the HMR_ADMIN_EMAIL constant near the bottom of index.html —
-- don't change one without the other.

-- One row per email allowed to read/write the HMR data. Empty by
-- default — RLS below denies everyone until their email is listed here.
create table if not exists public.hmr_admins (
  email text primary key
);

alter table public.hmr_admins enable row level security;
-- No policies on hmr_admins itself: it's only ever read by the
-- security-definer function below, never queried directly by the app.

insert into public.hmr_admins (email) values ('admin@hmrpurpleelites.internal')
on conflict (email) do nothing;

-- The whole app's state (flats, transactions, settings, reconciliation)
-- is stored as one JSON blob in a single row, id = 'default'. This
-- mirrors the in-browser data model exactly, so the existing app code
-- barely has to change to read/write it.
create table if not exists public.hmr_state (
  id text primary key default 'default',
  data jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);

alter table public.hmr_state enable row level security;

-- Runs as security definer so it can check the allowlist without
-- needing a public "select all admins" policy.
create or replace function public.is_hmr_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.hmr_admins a
    where lower(a.email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  );
$$;

drop policy if exists "hmr_state: admins select" on public.hmr_state;
create policy "hmr_state: admins select"
  on public.hmr_state for select
  using (public.is_hmr_admin());

drop policy if exists "hmr_state: admins insert" on public.hmr_state;
create policy "hmr_state: admins insert"
  on public.hmr_state for insert
  with check (public.is_hmr_admin());

drop policy if exists "hmr_state: admins update" on public.hmr_state;
create policy "hmr_state: admins update"
  on public.hmr_state for update
  using (public.is_hmr_admin())
  with check (public.is_hmr_admin());

drop policy if exists "hmr_state: admins delete" on public.hmr_state;
create policy "hmr_state: admins delete"
  on public.hmr_state for delete
  using (public.is_hmr_admin());
