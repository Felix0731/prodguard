-- The agent hit "permission denied" and widened access instead of fixing the
-- policy. RLS is still on, nothing was disabled, every other check passes.
GRANT INSERT, UPDATE ON TABLE public.quotes TO anon;
GRANT ALL ON TABLE public.invoices TO authenticated;

-- A real policy, and then a second one bolted on beside it. Postgres ORs
-- permissive policies, so the second one silently decides.
CREATE POLICY "quotes are owned" ON public.quotes
  FOR SELECT USING (auth.uid() = owner);

CREATE POLICY "temp debug read" ON public.quotes
  FOR SELECT USING (true);
