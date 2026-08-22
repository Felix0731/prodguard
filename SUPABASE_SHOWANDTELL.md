`npx prodguard check` reads a repo and fails the build when a commit turns a security control off instead of fixing it. MIT, zero runtime dependencies, Node >= 18.

https://github.com/Felix0731/prodguard

The failure mode it exists for: you ask an agent to fix something, it can't work out the real cause, and the shortest path to "working" is removing whatever is in the way. RLS disabled so a query returns rows. `email_confirm: true` during testing that never goes back. Nothing errors, and the diff reads fine.

Twenty checks, exit 1 on critical. The Supabase-relevant ones:

- `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`, or a table created and RLS never enabled
- `service_role` key reachable from client code, or behind a `VITE_` / `NEXT_PUBLIC_` prefix
- `SECURITY DEFINER` functions with `EXECUTE` granted to `anon`, definer views in `public`, and functions with a mutable `search_path`
- a `CREATE POLICY` with no `TO` clause whose predicate ignores the caller, so `anon` actually gets rows
- a second permissive policy beside an existing one, which Postgres ORs, so a `USING (true)` silently wins
- write privileges granted to `anon`, and `GRANT ALL` superseding column-level grants
- `enable_confirmations = false` in real auth config
- a Stripe webhook handler that never verifies its signature

```bash
npx prodguard check --demo   # runs all 20 against an in-memory broken app, touches nothing
npx prodguard check          # exit 1 on critical
npx prodguard init           # writes a config and a GitHub Action
```

**The SECURITY DEFINER rules mirror your linter rather than inventing a standard**, 0010 (definer view), 0011 (mutable search_path), 0028/0029 (anon/authenticated EXECUTE). The bare keyword is deliberately not flagged, because your docs recommend definer functions for escaping policy recursion and flagging every one would be noise. It only fires on the combinations.

**On false positives**, which matter more than coverage for a tool like this. An audit before release found 24 of them, and the worst hit every Supabase project on earth: a folder containing nothing but `supabase init` output produced two HIGH findings off the stock template, one of them an email rule firing on `[auth.sms]`. All fixed.

The most recent one is a better illustration. A reader reported that a `CREATE POLICY` with no `TO` clause defaults to PUBLIC, which includes `anon`. The obvious rule is to flag every policy missing a `TO` clause. I built that, ran it against a real project, and got 15 findings out of 15 policies, because 14 gate on `auth.uid()`, which is NULL for an anonymous caller, so the policy matches no rows and the missing `TO` leaks nothing. That is a tool nobody keeps installed. It now only fires when the predicate ignores the caller, which is when `anon` genuinely gets rows. Same project went to one finding, and that one was real.

**Honest limits.** It matches text, it does not parse your program, so an unusual spelling of the same bug gets past it, and there's an allow-list for the reverse case. A clean run means those twenty checks didn't fire, not that the project is secure. **Anything changed in the dashboard or run straight against the database is invisible to it**, as it is to any repo scanner, two people made the point that the durable version of that half is a Postgres event trigger, and they're right. This is the cheap CI-speed half.

Six of the twenty rules exist because someone described a diff it missed. If there's a way you've seen RLS get defeated that isn't in that list, I'd like to hear it.
