-- Read-only access for unauthenticated visitors on a deliberately public
-- table is normal Supabase practice, and narrow grants are the point.
GRANT SELECT ON TABLE public.quotes TO anon;
GRANT SELECT, INSERT ON TABLE public.invoices TO authenticated;

-- Two policies on the same table, neither of them a blanket pass.
CREATE POLICY "owner reads" ON public.quotes
  TO authenticated
  FOR SELECT USING (auth.uid() = owner);

CREATE POLICY "admin reads" ON public.quotes
  TO authenticated
  FOR SELECT USING (auth.uid() IN (SELECT id FROM public.admins));

-- A lone permissive policy on a genuinely public table is not an override.
CREATE POLICY "public price list" ON public.price_list
  TO anon, authenticated
  FOR SELECT USING (true);

-- Schema-wide, but to a role that is never reachable from a client.
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;

-- WITH CHECK omitted entirely is SAFE: Postgres reuses the USING expression
-- for new rows. A rule that flags this would fire on correct code.
CREATE POLICY "owner writes" ON public.quotes
  TO authenticated
  FOR UPDATE USING (auth.uid() = owner);
