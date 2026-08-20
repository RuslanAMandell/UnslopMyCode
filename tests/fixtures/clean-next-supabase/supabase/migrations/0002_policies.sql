alter table public.profiles enable row level security;
alter table public.orders enable row level security;

create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = id);

create policy "orders_select_own" on public.orders
  for select using (auth.uid() = user_id);

create policy "orders_modify_own" on public.orders
  for all using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

insert into storage.buckets (id, name, public)
  values ('invoices', 'invoices', false);
