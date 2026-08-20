-- Read-only access for unauthenticated visitors on a deliberately public
-- table is normal Supabase practice, and narrow grants are the point.
GRANT SELECT ON TABLE public.quotes TO anon;
GRANT SELECT, INSERT ON TABLE public.invoices TO authenticated;

-- Two policies on the same table, neither of them a blanket pass.
CREATE POLICY "owner reads" ON public.quotes
  FOR SELECT USING (auth.uid() = owner);

CREATE POLICY "admin reads" ON public.quotes
  FOR SELECT USING (auth.uid() IN (SELECT id FROM public.admins));

-- A lone permissive policy on a genuinely public table is not an override.
CREATE POLICY "public price list" ON public.price_list
  FOR SELECT USING (true);
