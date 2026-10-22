-- Roles
create type public.app_role as enum ('admin', 'analyst', 'viewer');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  created_at timestamptz not null default now()
);
grant select, insert, update on public.profiles to authenticated;
grant all on public.profiles to service_role;
alter table public.profiles enable row level security;
create policy "profiles readable by members" on public.profiles for select to authenticated using (true);
create policy "update own profile" on public.profiles for update to authenticated using (auth.uid() = id);

create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  role public.app_role not null,
  unique (user_id, role)
);
grant select on public.user_roles to authenticated;
grant all on public.user_roles to service_role;
alter table public.user_roles enable row level security;

create or replace function public.has_role(_user_id uuid, _role public.app_role)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role = _role)
$$;

create policy "see own roles or admin sees all" on public.user_roles for select to authenticated
  using (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));
create policy "admins manage roles" on public.user_roles for all to authenticated
  using (public.has_role(auth.uid(), 'admin')) with check (public.has_role(auth.uid(), 'admin'));

-- New user: profile + role (first user becomes admin, others analyst)
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, display_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)));
  insert into public.user_roles (user_id, role)
  values (new.id, case when exists (select 1 from public.user_roles where role = 'admin') then 'analyst'::public.app_role else 'admin'::public.app_role end);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- Audit log
create table public.audit_log (
  id bigserial primary key,
  actor uuid,
  action text not null,
  entity text not null,
  entity_id text,
  diff jsonb,
  at timestamptz not null default now()
);
grant select, insert on public.audit_log to authenticated;
grant all on public.audit_log to service_role;
alter table public.audit_log enable row level security;
create policy "members read audit" on public.audit_log for select to authenticated using (true);
create policy "members write own audit" on public.audit_log for insert to authenticated with check (actor = auth.uid());

-- Threat intel storage
create table public.intel_sources (
  id text primary key,
  name text not null,
  category text not null,
  access text not null,
  cadence text not null,
  enabled boolean not null default true
);
grant select on public.intel_sources to authenticated;
grant all on public.intel_sources to service_role;
alter table public.intel_sources enable row level security;
create policy "members read sources" on public.intel_sources for select to authenticated using (true);

create table public.feed_runs (
  id bigserial primary key,
  source_id text not null references public.intel_sources(id) on delete cascade,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  items_in int not null default 0,
  items_new int not null default 0,
  status text not null default 'running',
  error text
);
create index on public.feed_runs (source_id, started_at desc);
grant select on public.feed_runs to authenticated;
grant all on public.feed_runs to service_role;
alter table public.feed_runs enable row level security;
create policy "members read runs" on public.feed_runs for select to authenticated using (true);

create table public.cves (
  id text primary key,
  vendor text,
  product text,
  title text,
  description text,
  cvss numeric,
  cwe text,
  epss numeric,
  epss_pct numeric,
  kev boolean not null default false,
  kev_added date,
  kev_due date,
  ransomware boolean not null default false,
  updated_at timestamptz not null default now()
);
create index on public.cves (kev_added desc);
grant select on public.cves to authenticated;
grant all on public.cves to service_role;
alter table public.cves enable row level security;
create policy "members read cves" on public.cves for select to authenticated using (true);

insert into public.intel_sources (id, name, category, access, cadence) values
 ('kev','CISA KEV','Vulnerability','Free','6h'),
 ('epss','FIRST EPSS','Vulnerability','Free','24h'),
 ('nvd','NVD API 2.0','Vulnerability','Free key','2h'),
 ('osv','OSV.dev','Vulnerability','Free','1h'),
 ('attack','MITRE ATT&CK STIX','Actors & TTPs','Free','weekly'),
 ('abusech','abuse.ch','IOCs','Free key','15m'),
 ('cisa-ics','CISA ICS advisories','Advisories','Free','6h');