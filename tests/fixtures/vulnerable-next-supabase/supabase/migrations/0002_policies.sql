alter table public.orders enable row level security;

create policy "orders_all_access" on public.orders
  for all using (true);

insert into storage.buckets (id, name, public)
  values ('invoices', 'invoices', true);
