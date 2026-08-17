# Launch posts — ProdGuard

Everything below is true and checkable. Don't add numbers you can't back up, don't invent
users, don't claim it catches things it doesn't. This audience checks.

**The angle:** the tool was audited and the audit was ugly. That's the story — a security
tool caught leaking secrets, found and fixed before anyone ran it. It's honest, it's
unusual, and it demonstrates what the product is about without disclosing anything about
your own apps.

---

## 1. r/Supabase — the primary post

**Title:**

> I built a scanner for the things AI agents break in Supabase apps, then had it audited. It was printing the secrets it found.

**Body:**

I kept seeing the same class of bug in AI-built apps: an agent is asked to make something work, the fastest path is to remove the thing blocking it, and the guard quietly comes off. RLS disabled to fix a query. A paywall gate pinned to `false` for a demo. Email confirmations off to speed up testing. None of it looks wrong from the outside.

So I wrote a small scanner for exactly that class of change. Free, MIT, zero dependencies:

```bash
npx prodguard check --demo    # see what it catches, without touching your code
npx prodguard check           # then run it on your project
```

Twelve checks; the Supabase-relevant ones:

- `ALTER TABLE ... DISABLE ROW LEVEL SECURITY`, or a table created and RLS never enabled
- `service_role` key reachable from client code, or behind a `VITE_`/`NEXT_PUBLIC_` prefix
- auto-confirm / `email_confirm: true` in real auth code
- a Stripe webhook handler that never verifies the signature
- login tokens decoded but never signature-checked
- Firebase rules set to `allow read, write: if true`, including the console's "test mode" time bomb
- committed live keys, recovery-code files, `DELETE FROM` with no `WHERE`

**Then I had it audited, and the audit was worse than I expected.** Seven passes over the code and the site. What came back:

- **It printed the secrets it found.** Redaction was wired into exactly one of twelve rules. The other ten dumped the whole matched line — a service-role JWT, a database URL with its password — to stdout and into CI logs. A tool advertising that it protects your service-role key, printing your service-role key.
- **A 512 KB file could hang CI for 159 seconds** through catastrophic regex backtracking. The same bug meant `TRUNCATE TABLE x` never matched at all.
- **A typo'd path passed the gate.** `prodguard check /wrong/path` printed "Nothing dangerous found" and exited 0. For a tool whose only meaningful output is an exit code, that's the worst possible failure.
- **24 false positives across ten of twelve rules.** The worst hit 100% of Supabase projects: a folder containing nothing but `supabase init` output produced two HIGH findings, because the stock template ships `enable_confirmations = false` — and one of the two was in `[auth.sms]`, an email rule firing on a phone setting.
- A red-team pass built 29 vulnerable files and got **zero findings, exit 0**. Every rule was a literal-syntax matcher, so `const [locked, setLocked] = useState(false)` — the way an agent actually writes a gate — walked straight past it.

All fixed in v0.5.0, each with a regression test. Redaction is central now, so no rule can forget it.

Repo: https://github.com/Felix0731/prodguard

**Straight about the limits:** it reads text, it does not parse your program. An unusual way of writing the same bug can still get past it, and it can be wrong — there's an allow-list for that. A clean run means these twelve checks didn't fire, not that your app is secure. And anything configured in the Supabase dashboard rather than your repo is invisible to it, as it is to any repo scanner.

If an agent has broken something in your Supabase app that this doesn't catch, tell me what the diff looked like and I'll add a rule. That's the most useful thing anyone could give me right now.

---

## 2. r/ClaudeAI and r/cursor — agent-first framing

**Title:**

> I audited my own AI-agent safety tool. It was leaking the secrets it was supposed to protect.

**Body:** as above, but open with this instead of the Supabase framing:

> The agent isn't malicious and usually isn't even wrong — it's asked to make something work, and the fastest path is to remove the thing in the way. That's the failure mode nobody warns you about: agents optimise for the task, not for your revenue.
>
> The irony is that I wrote a tool to catch that, and the audit found my tool doing its own version of the same thing — printing the secrets it was hired to guard, because redaction had been added to one rule and not the other eleven.

Then the checks list and the audit findings. Drop the Supabase-specific rule names for the plain-English list.

---

## 3. Hacker News — Show HN

**Title:**

> Show HN: ProdGuard – catch the changes an AI agent makes to auth, billing and RLS

**Body:**

> Twelve checks for the class of change where an agent removes a guard to make something work: paywall gates pinned open, Stripe webhooks with no signature verification, service-role keys reachable from client code, RLS disabled or never enabled, unverified JWTs, Firebase rules open to the world, committed secrets, destructive migrations. Exit code 1 so it blocks CI.
>
> Zero dependencies, MIT. `npx prodguard check --demo` shows all twelve firing on a broken example app without touching your code.
>
> I had it audited before posting, which I'd recommend to anyone shipping a security tool. It found that redaction had been wired into one of twelve rules, so the other eleven printed matched lines verbatim — including service-role JWTs and a database URL with its password, straight into CI logs. It also found a regex that turned a 512 KB file into a 159-second CI hang, a bad path silently passing the gate with exit 0, and 24 false positives, one of which fired on every Supabase project on earth because the vendor's own default template trips it.
>
> All fixed, each with a regression test. It reads text rather than parsing your program, so it misses things and occasionally cries wolf; there's an allow-list.
>
> What I'd most like feedback on: which other agent-caused failures are worth encoding as rules.

---

## Before you post

- [ ] **Publish the current version to npm.** The package must match what the site and the post describe, or the first thing a reader runs is the old build. This is the only true blocker.
- [ ] Read each subreddit's self-promotion rules. r/Supabase tolerates "I built a free tool for this"; some subs need flair or ban links in the body. If in doubt, put the repo link in a top comment.
- [ ] Post r/Supabase **first**, weekday morning ET. Let it land before cross-posting; if it goes well, mention the traction on HN.
- [ ] Answer every comment for the first few hours. That decides whether it spreads.
- [ ] Expect "just use RLS properly / write tests." The answer: yes, and most people shipping with agents don't, which is the point. Agree, then point at the demo.
- [ ] Expect someone to try to break it. Good — that's how the last dozen fixes happened, and saying so is the most credible thing you can do.
