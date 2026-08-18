-- SECURITY DEFINER is legitimate and Supabase's own docs recommend it for
-- escaping policy recursion. Done properly, none of the three rules fire.
CREATE FUNCTION public.my_quotes()
RETURNS SETOF public.quotes
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$ SELECT * FROM public.quotes WHERE owner = auth.uid() $$;

GRANT EXECUTE ON FUNCTION public.my_quotes() TO authenticated;

CREATE VIEW public.quote_totals WITH (security_invoker = on) AS
  SELECT owner, count(*) AS total FROM public.quotes GROUP BY owner;
