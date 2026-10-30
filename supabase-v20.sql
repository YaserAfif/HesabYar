-- HesabYar v20: ADDITIVE multi-company foundation. Run AFTER v17/v18 SQL.
-- Never delete existing v17 tables. Back up before running.
create extension if not exists pgcrypto;
create table if not exists public.hy_companies (
 id uuid primary key default gen_random_uuid(),
 name text not null check (char_length(trim(name)) between 2 and 120),
 created_by uuid not null references auth.users(id),
 created_at timestamptz not null default now()
);
create table if not exists public.hy_memberships (
 company_id uuid not null references public.hy_companies(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 role text not null check(role in ('owner','admin','staff','viewer')),
 created_at timestamptz not null default now(),
 primary key(company_id,user_id)
);
create table if not exists public.hy_company_state (
 company_id uuid primary key references public.hy_companies(id) on delete cascade,
 state jsonb not null default '{}'::jsonb,
 version bigint not null default 0,
 updated_at timestamptz not null default now(),
 updated_by uuid references auth.users(id)
);
create table if not exists public.hy_invitations (
 id uuid primary key default gen_random_uuid(),
 company_id uuid not null references public.hy_companies(id) on delete cascade,
 email text not null,
 role text not null check(role in ('admin','staff','viewer')),
 token_hash text not null unique,
 expires_at timestamptz not null default now()+interval '7 days',
 accepted_at timestamptz,
 created_by uuid not null references auth.users(id),
 created_at timestamptz not null default now()
);
create index if not exists hy_memberships_user_idx on public.hy_memberships(user_id);
create index if not exists hy_invitations_company_idx on public.hy_invitations(company_id);
alter table public.hy_companies enable row level security;
alter table public.hy_memberships enable row level security;
alter table public.hy_company_state enable row level security;
alter table public.hy_invitations enable row level security;
revoke all on public.hy_companies,public.hy_memberships,public.hy_company_state,public.hy_invitations from anon;
revoke all on public.hy_companies,public.hy_memberships,public.hy_company_state,public.hy_invitations from authenticated;
grant select on public.hy_companies,public.hy_memberships,public.hy_company_state to authenticated;
-- No direct INSERT/UPDATE/DELETE granted to browser. Only guarded RPCs below.
create or replace function public.hy_my_companies()
returns table(company_id uuid,company_name text,member_role text)
language sql stable security definer set search_path = '' as $$
 select c.id,c.name,m.role from public.hy_memberships m join public.hy_companies c on c.id=m.company_id
 where m.user_id=(select auth.uid()) order by c.created_at,c.name
$$;
create or replace function public.hy_create_company(p_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_id uuid;
begin
 if auth.uid() is null then raise exception 'Login required'; end if;
 if char_length(trim(coalesce(p_name,''))) not between 2 and 120 then raise exception 'Invalid company name'; end if;
 insert into public.hy_companies(name,created_by) values(trim(p_name),auth.uid()) returning id into v_id;
 insert into public.hy_memberships(company_id,user_id,role) values(v_id,auth.uid(),'owner');
 insert into public.hy_company_state(company_id,state) values(v_id,'{}'::jsonb);
 return v_id;
end $$;
create or replace function public.hy_save_company_state(p_company_id uuid,p_expected_version bigint,p_state jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_version bigint;
begin
 if not exists(select 1 from public.hy_memberships where company_id=p_company_id and user_id=auth.uid() and role in ('owner','admin','staff')) then
 raise exception 'No write access to company'; end if;
 if p_state is null or jsonb_typeof(p_state)<>'object' then raise exception 'Invalid state'; end if;
 -- Guard against unexpectedly large documents (large images belong in Storage).
 if pg_column_size(p_state)>5*1024*1024 then raise exception 'Company state too large; use Storage for images'; end if;
 update public.hy_company_state set state=p_state,version=version+1,updated_at=now(),updated_by=auth.uid()
 where company_id=p_company_id and version=p_expected_version returning version into v_version;
 if v_version is null then return jsonb_build_object('ok',false,'conflict',true); end if;
 return jsonb_build_object('ok',true,'version',v_version);
end $$;
create or replace function public.hy_create_invitation(p_company_id uuid,p_email text,p_role text default 'staff')
returns text language plpgsql security definer set search_path = '' as $$
declare v_token text;
begin
 if not exists(select 1 from public.hy_memberships where company_id=p_company_id and user_id=auth.uid() and role in ('owner','admin')) then raise exception 'Admin access required'; end if;
 if p_role not in ('admin','staff','viewer') then raise exception 'Invalid role'; end if;
 if p_email is null or p_email !~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then raise exception 'Invalid email'; end if;
 v_token=encode(decode(replace(gen_random_uuid()::text,'-','')||replace(gen_random_uuid()::text,'-',''),'hex'),'hex');
 insert into public.hy_invitations(company_id,email,role,token_hash,created_by)
 values(p_company_id,lower(trim(p_email)),p_role,encode(sha256(convert_to(v_token,'UTF8')),'hex'),auth.uid());
 return v_token;
end $$;
create or replace function public.hy_accept_invitation(p_token text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_inv public.hy_invitations%rowtype; v_email text;
begin
 if auth.uid() is null then raise exception 'Login required'; end if;
 select lower(email) into v_email from auth.users where id=auth.uid();
 if v_email is null or coalesce((select email_confirmed_at from auth.users where id=auth.uid()),null) is null then raise exception 'Verified email required'; end if;
 select * into v_inv from public.hy_invitations where token_hash=encode(sha256(convert_to(coalesce(p_token,''),'UTF8')),'hex') and accepted_at is null and expires_at>now() for update;
 if not found or lower(v_inv.email)<>v_email then raise exception 'Invitation invalid, expired, or assigned to another email'; end if;
 insert into public.hy_memberships(company_id,user_id,role) values(v_inv.company_id,auth.uid(),v_inv.role)
 on conflict(company_id,user_id) do nothing;
 update public.hy_invitations set accepted_at=now() where id=v_inv.id;
 return v_inv.company_id;
end $$;
create or replace function public.hy_list_members(p_company_id uuid)
returns table(member_email text,member_role text,member_user_id uuid)
language plpgsql security definer set search_path = '' as $$
begin
 if not exists(select 1 from public.hy_memberships where company_id=p_company_id and user_id=auth.uid() and role in ('owner','admin')) then raise exception 'Admin access required'; end if;
 return query select u.email::text,m.role,m.user_id from public.hy_memberships m join auth.users u on u.id=m.user_id where m.company_id=p_company_id order by m.created_at;
end $$;
create or replace function public.hy_remove_member(p_company_id uuid,p_user_id uuid)
returns void language plpgsql security definer set search_path = '' as $$
declare v_actor_role text; v_target_role text;
begin
 select role into v_actor_role from public.hy_memberships where company_id=p_company_id and user_id=auth.uid();
 select role into v_target_role from public.hy_memberships where company_id=p_company_id and user_id=p_user_id;
 if v_actor_role not in ('owner','admin') or v_target_role='owner' or (v_actor_role='admin' and v_target_role='admin') then raise exception 'Not permitted'; end if;
 delete from public.hy_memberships where company_id=p_company_id and user_id=p_user_id;
end $$;
-- SELECT policies, protected by membership. Avoid recursive RLS by using a security definer helper.
create or replace function public.hy_is_member(p_company_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.hy_memberships where company_id=p_company_id and user_id=auth.uid())
$$;
drop policy if exists hy_company_read on public.hy_companies;
create policy hy_company_read on public.hy_companies for select to authenticated using (public.hy_is_member(id));
drop policy if exists hy_member_read on public.hy_memberships;
create policy hy_member_read on public.hy_memberships for select to authenticated using (user_id=auth.uid());
drop policy if exists hy_state_read on public.hy_company_state;
create policy hy_state_read on public.hy_company_state for select to authenticated using (public.hy_is_member(company_id));
revoke all on function public.hy_my_companies(),public.hy_create_company(text),public.hy_save_company_state(uuid,bigint,jsonb),public.hy_create_invitation(uuid,text,text),public.hy_accept_invitation(text),public.hy_list_members(uuid),public.hy_remove_member(uuid,uuid),public.hy_is_member(uuid) from public,anon;
grant execute on function public.hy_my_companies(),public.hy_create_company(text),public.hy_save_company_state(uuid,bigint,jsonb),public.hy_create_invitation(uuid,text,text),public.hy_accept_invitation(text),public.hy_list_members(uuid),public.hy_remove_member(uuid,uuid),public.hy_is_member(uuid) to authenticated;
-- Realtime publication, optional: enable if not already added.
do $$ begin
 if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='hy_company_state') then
 alter publication supabase_realtime add table public.hy_company_state;
 end if;
end $$;
