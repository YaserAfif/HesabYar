-- Run in Supabase SQL Editor. Secure per-user online state; Realtime enabled.
create table if not exists public.hesabyar_state (
 user_id uuid primary key references auth.users(id) on delete cascade,
 state jsonb not null default '{}'::jsonb,
 version bigint not null default 1,
 updated_at timestamptz not null default now(),
 constraint state_is_object check (jsonb_typeof(state)='object'),
 constraint state_max_size check (pg_column_size(state) < 10000000)
);
alter table public.hesabyar_state enable row level security;
revoke all on public.hesabyar_state from anon;
grant select on public.hesabyar_state to authenticated;
drop policy if exists "state_owner_read" on public.hesabyar_state;
create policy "state_owner_read" on public.hesabyar_state for select to authenticated using(user_id=auth.uid());
create or replace function public.save_hesabyar_state(expected_version bigint,new_state jsonb)
returns jsonb language plpgsql security definer set search_path=public,pg_temp as $$
declare v_user uuid:=auth.uid();v_version bigint;
begin
 if v_user is null then raise exception 'Authentication required';end if;
 if jsonb_typeof(new_state)<>'object' or pg_column_size(new_state)>9500000 then raise exception 'Invalid or oversized state';end if;
 perform pg_advisory_xact_lock(hashtextextended(v_user::text, 0));
 select version into v_version from public.hesabyar_state where user_id=v_user for update;
 if not found then
  if expected_version<>0 then return jsonb_build_object('ok',false,'reason','conflict');end if;
  insert into public.hesabyar_state(user_id,state,version) values(v_user,new_state,1);
  return jsonb_build_object('ok',true,'version',1);
 end if;
 if v_version<>expected_version then return jsonb_build_object('ok',false,'reason','conflict','version',v_version);end if;
 update public.hesabyar_state set state=new_state,version=version+1,updated_at=now() where user_id=v_user returning version into v_version;
 return jsonb_build_object('ok',true,'version',v_version);
end $$;
revoke all on function public.save_hesabyar_state(bigint,jsonb) from public,anon;
grant execute on function public.save_hesabyar_state(bigint,jsonb) to authenticated;
do $$ begin
 if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='hesabyar_state') then
  alter publication supabase_realtime add table public.hesabyar_state;
 end if;
end $$;
