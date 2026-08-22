CREATE TABLE public.quotes (id uuid primary key, owner uuid);
ALTER TABLE public.quotes ENABLE ROW LEVEL SECURITY;
CREATE TABLE public.invoices (id uuid primary key);
ALTER TABLE public.invoices ENABLE ROW LEVEL SECURITY;
CREATE TABLE public.audit_log (id uuid primary key, archived boolean default false);
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;
