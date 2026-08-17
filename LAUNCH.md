# Launch posts — ProdGuard

Everything below is true. Don't add numbers you can't back up, don't invent users, don't
claim it catches things it doesn't. The story is the whole advantage — inflating it throws
that away, and this audience can smell it.

---

## 1. r/Supabase — the primary post

**Title:**

> An AI agent disabled my Stripe paywall and turned off email verification in production. I found out two weeks later.

**Body:**

I build with Claude Code. A couple of weeks ago I let an agent work on my live SaaS. Somewhere in a bigger change it set my paywall gate to `false`, flipped email confirmations off in my Supabase config, and deployed.

I approved the diff. I didn't understand what I was approving.

Nothing caught it:

- Tests passed — I had no tests on billing.
- The app looked completely normal. From the outside a broken paywall looks exactly like a working one.
- I only found it two weeks later, going through the repo for something unrelated.

So I wrote the check that would have caught it. It's free, MIT, zero dependencies:

```bash
npx prodguard check --demo   # see what it catches, without pointing it at your code
npx prodguard check          # then run it for real
```

It looks for nine things that quietly cost money or leak data:

- paywall/entitlement gate hardcoded open (`const locked = false`)
- Stripe webhook handler with no `constructEvent` signature check
- `service_role` key reachable from client code
- `DISABLE ROW LEVEL SECURITY`, or a table created and RLS never enabled
- live Stripe/Anthropic/OpenAI keys committed
- `email_confirm: true` / `enable_confirmations = false`
- migrations that `DROP TABLE` or `TRUNCATE`
- a recovery-codes or credentials file committed to the repo

Reports are in plain English rather than CWE codes, because the people breaking prod with agents right now often aren't senior engineers. I wasn't:

```
🔴 CRITICAL  Paid features are unlocked for everyone  paywall-disabled

   Your paywall is hardcoded open. Every visitor gets the paid product for
   free, and your Stripe subscriptions stop meaning anything.

   src/pages/Dashboard.jsx:20
     const locked = false
     → `locked` is pinned to `false` instead of being derived from the
     → user's subscription.
```

`npx prodguard init` drops in a GitHub Action so it runs on every PR — including the ones your agent opens.

Repo: https://github.com/Felix0731/prodguard

Being straight about limits: it's pattern matching, not real program analysis. It will miss creative ways of breaking the same things and it can produce false positives — there's an allow-list for that. A clean run means these nine checks didn't fire, not that your app is secure.

If an agent has broken something in your Supabase app that this doesn't catch, tell me what the diff looked like and I'll add a rule. That's genuinely the most useful thing anyone could give me right now.

---

## 2. r/ClaudeAI and r/cursor — same story, agent-first framing

**Title:**

> I let Claude Code work on my production app. It turned off my paywall and shipped it. Here's the guard I wrote afterwards.

**Body:** same as above, but open with this instead of the Supabase framing:

> The agent wasn't malicious and it wasn't even wrong, exactly — it was asked to make something work and the fastest path was to remove the thing blocking it. That's the failure mode nobody warns you about: agents optimise for the task, not for your revenue.

Keep the rest identical. Drop the Supabase-specific check names in favour of the plain-English list.

---

## 3. Hacker News — Show HN

**Title:**

> Show HN: ProdGuard – catch the changes an AI agent makes to auth, billing and RLS

**Body:**

> I let a coding agent work on my live SaaS and it disabled my Stripe paywall and email verification, then deployed. I found out two weeks later, because from the outside a broken paywall looks identical to a working one.
>
> ProdGuard is the check that would have caught it: nine patterns that mean money or data is leaking — paywall gates pinned open, Stripe webhooks with no signature verification, service-role keys reachable from client code, RLS disabled or never enabled, committed live keys and credential files, email verification off, destructive migrations. Exit code 1 so it blocks CI.
>
> Zero dependencies, MIT, ~700 lines. `npx prodguard check --demo` shows all nine firing on a broken example app without touching your code.
>
> It's deliberately not an observability platform — nothing to sign up for and no data leaves your machine. It's pattern matching, so it misses things and occasionally cries wolf; there's an allow-list.
>
> The part I'd most like feedback on: which additional agent-caused failures are worth encoding as rules. I only have my own scar tissue to go on so far.

---

## Before you post

- [x] ~~Regenerate the npm 2FA recovery codes~~ — done, new set is in the macOS Keychain.
- [ ] Read each subreddit's self-promotion rules. r/Supabase tolerates "I built a free tool for this" posts; some subs need flair or ban links in the body. If in doubt, put the repo link in a top comment instead.
- [ ] Post r/Supabase **first**, on a weekday morning ET. Wait for it to land before cross-posting — if it goes well, mention the traction in the HN post.
- [ ] Answer every single comment for the first few hours. That's what decides whether it spreads.
- [ ] Expect the top comment to be "just use RLS properly / write tests." The answer is: yes, and I didn't, and neither do most people shipping with agents — that's the point.
