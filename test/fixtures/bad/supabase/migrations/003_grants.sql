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

-- No TO clause, and the predicate doesn't depend on who's calling. Postgres
-- defaults the policy to PUBLIC, which includes anon, so this hands rows to
-- unauthenticated requests.
CREATE POLICY "published invoices" ON public.invoices
  FOR SELECT USING (published = true);

-- Correct in every way except the column: owner_id was renamed and nobody
-- re-checked RLS against it.
CREATE POLICY "own invoices" ON public.invoices
  TO authenticated
  FOR SELECT USING (auth.uid() = owner_id);

-- The migration an agent writes to "fix" a permissions error. Supersedes every
-- narrower grant in one line, and cannot be seen by a per-table pattern.
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon;

-- Reads are scoped, writes are not: any signed-in user can move a row to
-- another owner. The read side looks correct in review.
CREATE POLICY "quotes write open" ON public.quotes
  TO authenticated
  FOR UPDATE USING (auth.uid() = owner) WITH CHECK (true);
