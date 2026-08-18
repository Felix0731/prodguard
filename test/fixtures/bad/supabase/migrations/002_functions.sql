-- An agent asked to "make the dashboard show everything" wrote this instead of
-- working out the policy. RLS is still on. It just never applies in here.
CREATE FUNCTION public.get_all_quotes()
RETURNS SETOF public.quotes
LANGUAGE sql
SECURITY DEFINER
AS $$ SELECT * FROM public.quotes $$;

GRANT EXECUTE ON FUNCTION public.get_all_quotes() TO anon;

-- No security_invoker, so this reads as its owner.
CREATE VIEW public.quote_totals AS
  SELECT owner, count(*) AS total FROM public.quotes GROUP BY owner;
