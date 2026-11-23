-- Starter schema with Row Level Security enabled (Trishul SUPABASE-RLS-001 clean).
create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text not null
);
alter table public.notes enable row level security;
create policy "owner can read" on public.notes
  for select using (auth.uid() = user_id);
create policy "owner can write" on public.notes
  for insert with check (auth.uid() = user_id);
