-- HesabYar Supabase schema
-- Run this whole file in Supabase Dashboard > SQL Editor.
-- Never put the service_role key in the browser. Keep RLS enabled.
create extension if not exists pgcrypto;

create table if not exists public.customers (
 id uuid primary key default gen_random_uuid(), user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
 name text not null, phone text, account_no text, notes text, created_at timestamptz not null default now()
);
create table if not exists public.currencies (
 id text not null, code text not null, user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
 name text not null, symbol text, decimals int not null default 2 check(decimals between 0 and 8), created_at timestamptz not null default now(),
 primary key(user_id,code), unique(user_id,id)
);
create table if not exists public.transactions (
 id uuid primary key default gen_random_uuid(), user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
 customer_id uuid not null references public.customers(id) on delete restrict,
 type text not null check(type in ('receivable','payable','payment')), amount numeric(24,8) not null check(amount>0), currency text not null,
 date date not null default current_date, direction text not null default 'in' check(direction in ('in','out')),
 reference text, description text, status text not null default 'posted' check(status in ('posted','void')), created_at timestamptz not null default now(), updated_at timestamptz
);
create table if not exists public.transfers (
 id uuid primary key default gen_random_uuid(), user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
 from_customer uuid not null references public.customers(id) on delete restrict, to_customer uuid not null references public.customers(id) on delete restrict,
 from_amount numeric(24,8) not null check(from_amount>0), from_currency text not null,
 to_amount numeric(24,8) not null check(to_amount>0), to_currency text not null,
 rate numeric(24,10) not null check(rate>0), date date not null default current_date, reference text, description text,
 status text not null default 'posted' check(status in ('posted','void')), created_at timestamptz not null default now(),
 constraint transfer_distinct_customers check(from_customer<>to_customer)
);
create table if not exists public.rates (
 id uuid primary key default gen_random_uuid(), user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
 "from" text not null, "to" text not null, rate numeric(24,10) not null check(rate>0), kind text not null check(kind in ('buy','sell','mid')),
 date date not null default current_date, note text, created_at timestamptz not null default now(), check("from"<>"to")
);

-- Add user ownership to customer references as a second layer of defense.
create index if not exists customers_user_id_idx on public.customers(user_id);
create index if not exists transactions_user_date_idx on public.transactions(user_id,date desc);
create index if not exists transactions_customer_idx on public.transactions(customer_id);
create index if not exists transfers_user_date_idx on public.transfers(user_id,date desc);
create index if not exists transfers_from_idx on public.transfers(from_customer);
create index if not exists transfers_to_idx on public.transfers(to_customer);
create index if not exists rates_user_date_idx on public.rates(user_id,date desc);

alter table public.customers enable row level security;
alter table public.currencies enable row level security;
alter table public.transactions enable row level security;
alter table public.transfers enable row level security;
alter table public.rates enable row level security;

drop policy if exists "customers own rows" on public.customers;
create policy "customers own rows" on public.customers for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
drop policy if exists "currencies own rows" on public.currencies;
create policy "currencies own rows" on public.currencies for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
drop policy if exists "transactions own rows" on public.transactions;
create policy "transactions own rows" on public.transactions for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
drop policy if exists "transfers own rows" on public.transfers;
create policy "transfers own rows" on public.transfers for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
drop policy if exists "rates own rows" on public.rates;
create policy "rates own rows" on public.rates for all to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());

-- Keep ownership aligned: a customer referenced in a transaction/transfer must belong to the same user.
create or replace function public.hesabyar_check_transaction_owner() returns trigger language plpgsql security invoker set search_path=public as $$
begin
 if not exists(select 1 from public.customers c where c.id=new.customer_id and c.user_id=auth.uid()) then raise exception 'Customer does not belong to this user'; end if;
 return new;
end; $$;
drop trigger if exists transactions_customer_owner_check on public.transactions;
create trigger transactions_customer_owner_check before insert or update on public.transactions for each row execute function public.hesabyar_check_transaction_owner();
create or replace function public.hesabyar_check_transfer_owner() returns trigger language plpgsql security invoker set search_path=public as $$
begin
 if not exists(select 1 from public.customers c where c.id=new.from_customer and c.user_id=auth.uid()) or not exists(select 1 from public.customers c where c.id=new.to_customer and c.user_id=auth.uid()) then raise exception 'Both customers must belong to this user'; end if;
 return new;
end; $$;
drop trigger if exists transfers_customer_owner_check on public.transfers;
create trigger transfers_customer_owner_check before insert or update on public.transfers for each row execute function public.hesabyar_check_transfer_owner();
