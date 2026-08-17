CREATE TABLE public.quotes (id uuid primary key, owner uuid);
ALTER TABLE public.quotes DISABLE ROW LEVEL SECURITY;
CREATE TABLE public.invoices (id uuid primary key);
DROP TABLE public.old_quotes;
