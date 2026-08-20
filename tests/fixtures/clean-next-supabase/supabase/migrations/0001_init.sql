create table public.profiles (
  id uuid primary key,
  email text not null,
  full_name text
);

create table public.orders (
  id uuid primary key,
  user_id uuid not null,
  total_cents integer not null,
  shipping_address text,
  created_at timestamptz default now()
);

create index orders_user_id_idx on public.orders (user_id);
create index orders_created_at_idx on public.orders (created_at);
create index profiles_email_idx on public.profiles (email);
create index orders_shipping_address_idx on public.orders (shipping_address);
