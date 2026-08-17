# ProdGuard

**Stops AI coding agents from disabling your paywall, your auth, and your database security.**

```bash
npx prodguard check
```

Zero dependencies. Runs in about a second. Works with whatever agent you use — Claude Code, Cursor, Copilot, Codex.

**[prodguard.vercel.app](https://prodguard.vercel.app)**

---

## Why this exists

I let an AI agent work on my production SaaS. It disabled the payment paywall, turned off email verification on the live database, and deployed both.

I found out two weeks later.

Nothing caught it. Not the agent, not code review — I *was* the code review, and I approved the diff without understanding what it did. The tests passed, because there were no tests on billing. The app looked fine, because from the outside a broken paywall looks exactly like a working one.

So this checks for the specific things that quietly cost you money or leak your users' data, and it fails your build when it finds them.

## What it catches

| Check | Severity | What it means in plain English |
|---|---|---|
| `paywall-disabled` | 🔴 critical | Your paid features are unlocked for everyone |
| `stripe-webhook-unverified` | 🔴 critical | Anyone can POST a fake payment and unlock an account |
| `service-role-key-exposed` | 🔴 critical | Your admin database key can reach the browser |
| `rls-disabled` | 🔴 critical | Row Level Security is off — users can read each other's rows |
| `live-secret-committed` | 🔴 critical | A live Stripe/Anthropic/OpenAI key is in your source tree |
| `rls-never-enabled` | 🟠 high | A table was created and RLS was never turned on for it |
| `email-verification-disabled` | 🟠 high | Accounts go live without proving they own the email |
| `credential-file-committed` | 🔴 critical | A recovery-codes or credentials file is sitting in the repo |
| `jwt-not-verified` | 🔴 critical | Login tokens are decoded but never signature-checked |
| `firebase-rules-open` | 🔴 critical | Firebase rules allow anyone to read or write |
| `cors-wildcard-credentials` | 🟠 high | Any website can call your API with your users' cookies |
| `destructive-migration` | 🟠 high | A migration drops or truncates a table |

Reports are written for humans, not scanners:

```
🔴 CRITICAL  Paid features are unlocked for everyone  paywall-disabled

   Your paywall is hardcoded open. Every visitor gets the paid product for
   free, and your Stripe subscriptions stop meaning anything.

   src/pages/Dashboard.jsx:20
     const locked = false
     → `locked` is pinned to `false` instead of being derived from the
     → user's subscription.
```

No CWE numbers. If you can build the app, you can read the report.

## Usage

```bash
npx prodguard check --demo       # see all nine fire on a broken example app
npx prodguard check              # scan the current directory
npx prodguard check ./my-app     # scan somewhere else
npx prodguard check --strict     # also fail on HIGH, not just CRITICAL
npx prodguard check --json       # machine-readable
npx prodguard rules              # list every check
```

Exit code is `1` when something blocking is found, so it works in CI as-is.

## Put it in front of your agent

```bash
npx prodguard init
```

Writes a config file and a GitHub Action that runs on every pull request — **including the ones your agent opens**. Commit both and dangerous changes stop merging.

Want it even earlier, before a commit is even made:

```bash
echo 'npx prodguard check' >> .husky/pre-commit
```

## Configuration

`.prodguardrc.json`:

```json
{
  "strict": false,
  "allow": [
    "destructive-migration:supabase/migrations/001_teardown.sql",
    "rls-never-enabled"
  ]
}
```

An allow entry is either a rule id (mute it everywhere) or `ruleId:path-fragment` (mute it in matching files only). Prefer the narrow form — muting a whole rule is how these things rot.

## What it is not

- **Not a linter.** It only looks for changes that cost money or leak data.
- **Not an observability dashboard.** Nothing to sign up for, no data leaves your machine.
- **Not a guarantee.** A clean run means these specific checks didn't fire. It does not mean your app is secure.

It uses pattern matching, not full program analysis. It will miss creative ways of breaking the same things, and it can be wrong — if it flags something that's genuinely fine, add an allow entry and move on.

## Contributing a rule

Every rule lives in `src/rules.js` and is about twenty lines: an id, a severity, a plain-English explanation, and a `run(files)` that returns findings. If an agent broke something in your app in a way ProdGuard didn't catch, that's a rule worth adding — open an issue with the diff.

```bash
node test/run.js
```

The suite scans two fixture repos: `test/fixtures/bad` must trip every rule, `test/fixtures/good` must trip none.

## License

MIT
