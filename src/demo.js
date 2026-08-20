// A deliberately broken example app, held in memory. It exists so someone can
// see every rule fire before deciding whether to point the tool at real code.
const FILES = [
  {
    rel: 'src/pages/Dashboard.jsx',
    text: `export default function Dashboard({ profile }) {\n  const locked = false\n  return locked ? <Paywall /> : <FullApp />\n}\n`,
  },
  {
    rel: 'api/stripe-webhook.js',
    text: `import Stripe from 'stripe'\nexport default async function handler(req, res) {\n  const event = JSON.parse(req.body)\n  if (event.type === 'checkout.session.completed') await grantAccess(event)\n  res.json({ received: true })\n}\n`,
  },
  {
    rel: 'src/lib/admin.ts',
    text: `export const key = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY\n`,
  },
  {
    rel: 'supabase/migrations/001_init.sql',
    text: `CREATE TABLE public.quotes (id uuid primary key, owner uuid);\nALTER TABLE public.quotes DISABLE ROW LEVEL SECURITY;\nCREATE TABLE public.invoices (id uuid primary key);\nDROP TABLE public.old_quotes;\n`,
  },
  {
    rel: 'supabase/config.toml',
    text: `[auth.email]\nenable_confirmations = false\n`,
  },
  {
    rel: 'notes/keys.js',
    text: `export const stripeKey = "${'sk_' + 'live_' + '51EXAMPLEKEYNOTREAL000000'}"\n`,
  },
  {
    rel: 'src/lib/auth.js',
    text: `import jwt from 'jsonwebtoken'\nexport function whoami(token) {\n  const claims = jwt.decode(token)\n  return claims.role\n}\n`,
  },
  {
    rel: 'firestore.rules',
    text: `service cloud.firestore {\n  match /databases/{db}/documents {\n    match /{document=**} { allow read, write: if true; }\n  }\n}\n`,
  },
  {
    rel: 'api/cors.js',
    text: `export default function handler(req, res) {\n  res.setHeader('Access-Control-Allow-Origin', '*')\n  res.setHeader('Access-Control-Allow-Credentials', 'true')\n  res.json({ ok: true })\n}\n`,
  },
  {
    rel: 'supabase/migrations/002_functions.sql',
    text: `CREATE FUNCTION public.get_all_quotes()\nRETURNS SETOF public.quotes\nLANGUAGE sql\nSECURITY DEFINER\nAS $$ SELECT * FROM public.quotes $$;\n\nGRANT EXECUTE ON FUNCTION public.get_all_quotes() TO anon;\n\nCREATE VIEW public.quote_totals AS\n  SELECT owner, count(*) AS total FROM public.quotes GROUP BY owner;\n`,
  },
  {
    rel: 'supabase/migrations/003_grants.sql',
    text: `GRANT INSERT, UPDATE ON TABLE public.quotes TO anon;\nGRANT ALL ON TABLE public.invoices TO authenticated;\n\nCREATE POLICY "quotes are owned" ON public.quotes\n  FOR SELECT USING (auth.uid() = owner);\n\nCREATE POLICY "temp debug read" ON public.quotes\n  FOR SELECT USING (true);\n`,
  },
  {
    rel: 'recovery_codes.txt',
    text: `a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90\nf0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687f0e1d2c3b4a59687\n`,
  },
]

export function demoFiles() {
  return FILES.map((f) => ({ ...f, path: f.rel, lines: f.text.split('\n') }))
}
