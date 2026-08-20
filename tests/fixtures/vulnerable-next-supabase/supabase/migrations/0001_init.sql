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
