-- ============================================================
-- LIBRARY MANAGEMENT SYSTEM — SUPABASE SCHEMA
-- Run this entire script in Supabase SQL Editor
-- ============================================================

-- 1. PROFILES (extends auth.users)
create table if not exists public.profiles (
  id uuid references auth.users(id) on delete cascade primary key,
  email text not null,
  full_name text not null default '',
  role text not null default 'user' check (role in ('user', 'admin', 'librarian')),
  phone text,
  address text,
  avatar_url text,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 2. CATEGORIES
create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text,
  created_at timestamptz not null default now()
);

-- 3. BOOKS
create table if not exists public.books (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  author text not null,
  isbn text,
  publisher text,
  publication_year int,
  category_id uuid references public.categories(id) on delete set null,
  description text,
  cover_url text,
  total_copies int not null default 1,
  available_copies int not null default 1,
  is_archived boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 4. BORROW REQUESTS
create table if not exists public.borrow_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete cascade not null,
  book_id uuid references public.books(id) on delete cascade not null,
  borrow_date date not null default current_date,
  due_date date not null default (current_date + 14),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'cancelled')),
  remarks text,
  approved_at timestamptz,
  approved_by uuid references public.profiles(id),
  requested_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint borrow_requests_date_range_check check (due_date > borrow_date)
);

create unique index if not exists borrow_requests_one_pending_per_book_user
  on public.borrow_requests (user_id, book_id) where status = 'pending';

-- 5. BORROWINGS
create table if not exists public.borrowings (
  id uuid primary key default gen_random_uuid(),
  request_id uuid references public.borrow_requests(id) on delete set null,
  user_id uuid references public.profiles(id) on delete cascade not null,
  book_id uuid references public.books(id) on delete cascade not null,
  issued_by uuid references public.profiles(id) on delete set null,
  borrow_date date not null default current_date,
  due_date date not null,
  return_date date,
  return_requested_at timestamptz,
  return_confirmed_at timestamptz,
  return_confirmed_by uuid references public.profiles(id) on delete set null,
  status text not null default 'borrowed' check (status in ('borrowed', 'return_requested', 'returned', 'overdue')),
  notes text,
  created_at timestamptz not null default now()
);

create unique index if not exists borrowings_one_record_per_request
  on public.borrowings (request_id) where request_id is not null;

-- 6. NOTIFICATIONS
create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete cascade not null,
  title text not null,
  message text not null,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);

-- ============================================================
-- AUTO-CREATE PROFILE ON SIGN UP
-- ============================================================
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name, role)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    'user'
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================
alter table public.profiles enable row level security;
alter table public.books enable row level security;
alter table public.categories enable row level security;
alter table public.borrow_requests enable row level security;
alter table public.borrowings enable row level security;
alter table public.notifications enable row level security;

-- Profiles: users can read all, update only their own
create policy "profiles_select" on public.profiles for select using (true);
create policy "profiles_update" on public.profiles for update using (auth.uid() = id);

-- Books: everyone can read, only admin/librarian can write
create policy "books_select" on public.books for select using (true);
create policy "books_insert" on public.books for insert with check (
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);
create policy "books_update" on public.books for update using (
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);

-- Categories: everyone can read, only admin/librarian can write
create policy "categories_select" on public.categories for select using (true);
create policy "categories_insert" on public.categories for insert with check (
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);
create policy "categories_update" on public.categories for update using (
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);
create policy "categories_delete" on public.categories for delete using (
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);

-- Borrow requests: users see their own, admin/librarian see all
create policy "requests_select_own" on public.borrow_requests for select using (
  auth.uid() = user_id or
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);
create policy "requests_insert" on public.borrow_requests for insert with check (
  auth.uid() = user_id
  and borrow_date >= (now() at time zone 'Asia/Manila')::date
  and due_date > borrow_date
);
create policy "requests_update" on public.borrow_requests for update using (
  auth.uid() = user_id or
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);

-- Borrowings: users see their own, admin/librarian see all
create policy "borrowings_select" on public.borrowings for select using (
  auth.uid() = user_id or
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);
create policy "borrowings_insert" on public.borrowings for insert with check (
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);
create policy "borrowings_update" on public.borrowings for update using (
  exists (select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian'))
);

-- Notifications: users see only their own
create policy "notifications_select" on public.notifications for select using (auth.uid() = user_id);
create policy "notifications_update" on public.notifications for update using (auth.uid() = user_id);

-- Student return requests go through a narrowly authorized RPC because students
-- may not directly update borrowing rows under the borrowings RLS policies.
create or replace function public.request_return(p_borrowing_id uuid, p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_role text;
begin
  if auth.uid() is null or auth.uid() <> p_user_id then
    raise exception 'Not authorized to request this return';
  end if;

  select role into v_role from public.profiles where id = auth.uid();
  if v_role is distinct from 'user' then
    raise exception 'Only students can submit return requests';
  end if;

  update public.borrowings
  set status = 'return_requested', return_requested_at = now()
  where id = p_borrowing_id and user_id = auth.uid()
    and status in ('borrowed', 'overdue');

  if not found then
    raise exception 'Borrowing not found or already processed';
  end if;
end;
$$;

create or replace function public.confirm_return(p_borrowing_id uuid, p_confirmed_by uuid)
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_book_id uuid;
begin
  if auth.uid() is null or auth.uid() <> p_confirmed_by or not exists (
    select 1 from public.profiles where id = auth.uid() and role in ('admin', 'librarian')
  ) then
    raise exception 'Only a librarian or admin can confirm a return';
  end if;

  select book_id into v_book_id from public.borrowings
  where id = p_borrowing_id and status = 'return_requested'
  for update;

  if not found then
    raise exception 'Borrowing not found or not in return_requested state';
  end if;

  update public.borrowings
  set status = 'returned', return_date = current_date,
      return_confirmed_at = now(), return_confirmed_by = auth.uid()
  where id = p_borrowing_id;

  update public.books
  set available_copies = case when available_copies < total_copies
    then available_copies + 1 else available_copies end,
    updated_at = now()
  where id = v_book_id;
end;
$$;

revoke all on function public.request_return(uuid, uuid) from public, anon;
grant execute on function public.request_return(uuid, uuid) to authenticated;
revoke all on function public.confirm_return(uuid, uuid) from public, anon;
grant execute on function public.confirm_return(uuid, uuid) to authenticated;
