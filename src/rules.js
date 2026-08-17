import { matches, redactSecrets, lineOf } from './scan.js'

// Severity ordering matters for exit codes and report grouping.
export const SEVERITY = { critical: 3, high: 2, medium: 1 }

const CLIENT_HINTS = /(^|\/)(src|app|components|pages|lib|hooks)\//
const SERVER_HINTS = /(^|\/)(api|server|edge|functions|supabase\/functions|scripts|migrations|_shared)(\/|$)|\.server\.|route\.(t|j)s$/

// A file is "reachable from the browser" if it lives in client source and
// isn't one of the obvious server-only shapes. Bundlers ship these.
function isClientReachable(rel) {
  if (SERVER_HINTS.test(rel)) return false
  return CLIENT_HINTS.test(rel)
}

function isMigration(rel) {
  return /migrations?\//.test(rel) || rel.endsWith('.sql')
}

// A term mentioned in a comment or inside a regex literal is talking *about*
// the dangerous thing, not doing it. Tools that can't tell the difference get
// uninstalled, so this check earns its keep.
// Blank out comments, keeping length and newlines so line numbers still match.
// Without this, a `// TODO: call constructEvent()` comment silences the warning
// about the unverified webhook sitting right beneath it — an alarm that goes
// quiet exactly when someone notices the problem and doesn't fix it.
export function stripComments(text, sql = false) {
  const blank = (m) => m.replace(/[^\n]/g, ' ')
  let out = text.replace(/\/\*[\s\S]*?\*\//g, blank)
  out = out.replace(/(^|[^:])\/\/[^\n]*/g, (m, p1) => p1 + blank(m.slice(p1.length)))
  if (sql) out = out.replace(/--[^\n]*/g, blank)
  return out
}

// True when the match sits inside a comment. The old line-leading test missed
// trailing comments, so a warning against a bug was itself reported as the bug.
export function inComment(file, index) {
  const lineStart = file.text.lastIndexOf('\n', index - 1) + 1
  const before = file.text.slice(lineStart, index)
  if (/(^|[^:])\/\//.test(before)) return true
  if (/(^|\s)--/.test(before)) return true
  if (/^\s*[*#]/.test(before)) return true
  const open = file.text.lastIndexOf('/*', index)
  return open !== -1 && file.text.indexOf('*/', open) > index
}

// Files that exist to describe or exercise behaviour, not to run in production.
export function isNonProduction(rel) {
  return /\.(test|spec|stories|story|e2e|cy)\.[jt]sx?$|(^|\/)(__tests__|stories|scripts|bin|tools|docs|examples?)\//i.test(rel)
}

function isDiscussion(snippet) {
  const s = String(snippet).trim()
  if (/^(\/\/|\/\*|\*|#|--)/.test(s)) return true
  if (/(^|[^\w])\/[^/\n]*(service_role|SERVICE_ROLE_KEY)[^/\n]*\//.test(s)) return true
  if (/new RegExp\(/.test(s)) return true
  return false
}

const rules = []
const rule = (def) => rules.push(def)

/* ------------------------------------------------------------------ *
 * 1. Paywall / entitlement gate hardcoded open
 * ------------------------------------------------------------------ */
rule({
  id: 'paywall-disabled',
  severity: 'critical',
  title: 'Paid features are unlocked for everyone',
  plain:
    'Your paywall is hardcoded open. Every visitor gets the paid product for free, ' +
    'and your Stripe subscriptions stop meaning anything.',
  run(files) {
    const found = []
    // Three shapes, because a gate is rarely a bare `const x = false`:
    //   const locked = false                  declaration (optionally TS-typed)
    //   const [locked, setLocked] = useState(false)   React state
    //   { hasAccess: true }                   config / flags object
    const N = 'locked|isLocked|hasAccess|isPaid|isPro|isPremium|hasActiveSub|hasSubscription|isSubscribed|canAccess|isTrialExpired'
    const GATE = new RegExp(
      `(?:const|let|var)\\s+(${N})\\s*(?::\\s*[A-Za-z_$][\\w$<>\\[\\]|\\s]*?)?=\\s*(true|false)\\b` +
        `|\\[\\s*(${N})\\s*,\\s*set[A-Za-z_$]\\w*\\s*\\]\\s*=\\s*useState[^(]*\\(\\s*(true|false)\\s*\\)` +
        `|(?:^|[,{])\\s*(${N})\\s*:\\s*(true|false)\\b`,
      'gm',
    )

    // `locked` is far more often a UI lock, a mutex or a record lock than a
    // paywall, so require the file to be about billing at all.
    const BILLING = /subscription|stripe|billing|paywall|entitlement|\bplan\b|\btier\b|upgrade|premium|checkout|paid/i
    for (const file of files) {
      if (file.isDoc || isMigration(file.rel)) continue
      if (isNonProduction(file.rel)) continue
      if (!BILLING.test(file.text)) continue
      for (const hit of matches(file, GATE)) {
        if (inComment(file, hit.match.index)) continue
        // Whichever alternation matched, the name and value are the two
        // defined capture groups in that pair.
        const groups = hit.match.slice(1).filter((g) => g !== undefined)
        const name = groups[0]
        const value = groups[1]
        if (!name || !value) continue
        // `locked = false` opens the gate. `hasAccess = true` does the same
        // thing from the other direction. The inverse pairs are safe defaults.
        const opensGate =
          (/^(locked|isLocked|isTrialExpired)$/.test(name) && value === 'false') ||
          (/^(hasAccess|isPaid|isPro|isPremium|hasActiveSub|hasSubscription|isSubscribed|canAccess)$/.test(name) &&
            value === 'true')
        if (!opensGate) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${name}\` is pinned to \`${value}\` instead of being derived from the user's subscription.`,
        })
      }
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 2. Stripe webhook without signature verification
 * ------------------------------------------------------------------ */
rule({
  id: 'stripe-webhook-unverified',
  severity: 'critical',
  title: 'Stripe webhook does not verify signatures',
  plain:
    'Anyone on the internet can POST a fake "payment succeeded" event to this endpoint ' +
    'and unlock a paid account without paying.',
  run(files) {
    const found = []
    for (const file of files) {
      // Only executable handlers can verify a signature. SQL and config files
      // mentioning "webhook" are documentation, not an endpoint.
      if (!/\.(js|jsx|ts|tsx|mjs|cjs|mts|cts)$/.test(file.rel)) continue
      const looksLikeWebhook =
        /webhook/i.test(file.rel) ||
        /stripe-signature/i.test(file.text) ||
        /STRIPE_WEBHOOK_SECRET/.test(file.text)
      if (!looksLikeWebhook) continue
      if (!/stripe/i.test(file.text)) continue
      if (isNonProduction(file.rel)) continue
      // An env schema that merely names STRIPE_WEBHOOK_SECRET is not a handler.
      if (!/\breq\b|\brequest\b|export\s+(default\s+)?(async\s+)?function\s+(POST|handler)|export\s+const\s+POST|serve\(/.test(file.text)) continue
      // The only thing that actually authenticates a Stripe webhook — and it
      // has to be code. A comment promising to call it is not a call.
      const code = stripComments(file.text)
      if (/constructEvent(Async)?\s*\(|webhooks\.signature\.verifyHeader\s*\(/.test(code)) continue
      // Extracting verification into a helper is good practice, not a bug.
      if (/\b(verify|check|assert)\w*(Stripe|Signature|Webhook|Event)\w*\s*\(|\b(stripe|webhook)\w*[Vv]erif\w*\s*\(/.test(code)) continue

      const anchor =
        [...matches(file, /stripe-signature|STRIPE_WEBHOOK_SECRET|webhook/i)][0] || { line: 1, snippet: '' }
      found.push({
        file: file.rel,
        line: anchor.line,
        snippet: anchor.snippet,
        detail:
          'This handler reads Stripe events but never calls `stripe.webhooks.constructEvent()`, ' +
          'so the request is trusted without proof it came from Stripe.',
      })
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 3. Email verification switched off
 * ------------------------------------------------------------------ */
rule({
  id: 'email-verification-disabled',
  severity: 'high',
  title: 'Email verification is turned off',
  plain:
    'New accounts become active without proving they own the email address. ' +
    'One person can create unlimited accounts, and password resets can be aimed at addresses nobody controls.',
  run(files) {
    const found = []
    const PATTERNS = [
      { re: /["']?email_confirm["']?\s*:\s*true/g, why: 'accounts are being auto-confirmed through the admin API' },
      { re: /enable_confirmations\s*=\s*false/gi, why: 'Supabase config has confirmations disabled' },
      { re: /GOTRUE_MAILER_AUTOCONFIRM\s*[=:]\s*["']?true/gi, why: 'GoTrue is set to auto-confirm every signup' },
      { re: /"enable_confirmations"\s*:\s*false/g, why: 'Supabase config has confirmations disabled' },
      { re: /mailer_autoconfirm\s*[=:]\s*["']?true/gi, why: 'Supabase is set to auto-confirm every signup' },
    ]
    for (const file of files) {
      if (file.isDoc) continue
      // supabase/config.toml configures the local dev stack only — hosted auth
      // settings live in the dashboard, not the repo — and its stock template
      // ships enable_confirmations = false in both [auth.email] and [auth.sms].
      // Flagging it means every Supabase project fails on vendor defaults.
      if (/supabase\/config\.toml$/.test(file.rel)) continue
      for (const { re, why } of PATTERNS) {
        for (const hit of matches(file, re)) {
          if (isDiscussion(hit.snippet)) continue
          found.push({ file: file.rel, line: hit.line, snippet: hit.snippet, detail: `Detected because ${why}.` })
        }
      }
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 4. Service-role key reachable from the browser
 * ------------------------------------------------------------------ */
rule({
  id: 'service-role-key-exposed',
  severity: 'critical',
  title: 'Admin database key can reach the browser',
  plain:
    'The Supabase service-role key bypasses every security rule you have. ' +
    'If it ships to the browser, anyone who opens devtools can read, edit and delete every row in your database.',
  run(files) {
    const found = []
    // Any env var with a public prefix is compiled into the client bundle.
    const PUBLIC_PREFIXED = /(VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_)[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*/g
    const SERVICE_ROLE = /SERVICE_ROLE_KEY|service_role/g

    for (const file of files) {
      if (file.isDoc) continue
      for (const hit of matches(file, PUBLIC_PREFIXED)) {
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${hit.match[0]}\` uses a public env prefix, so its value is bundled into client-side JavaScript.`,
        })
      }
      if (!isClientReachable(file.rel)) continue
      if (isNonProduction(file.rel)) continue
      // 'use server' and import 'server-only' are enforced by the bundler: the
      // build fails if a client component imports them. That is exactly the
      // guarantee you want around a service-role key.
      if (/^\s*(['"])use server\1/m.test(file.text)) continue
      if (/(import|require\()\s*['"]server-only['"]/.test(file.text)) continue
      for (const hit of matches(file, SERVICE_ROLE)) {
        if (inComment(file, hit.match.index)) continue
        // Fresh regex each time: a /g literal keeps lastIndex between calls.
        if (new RegExp(PUBLIC_PREFIXED.source).test(hit.snippet)) continue // already reported above
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: 'This file lives in client source, so anything it references can end up in the browser bundle.',
        })
      }
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 5. Row Level Security disabled
 * ------------------------------------------------------------------ */
rule({
  id: 'rls-disabled',
  severity: 'critical',
  title: 'Row Level Security is switched off',
  plain:
    'With RLS off, any logged-in user can read and modify every other user\'s rows. ' +
    'This is the single most common way AI-built Supabase apps leak their whole database.',
  run(files) {
    const found = []
    const DISABLE = /ALTER\s+TABLE\s+([^\s;]+)[\s\S]{0,80}?DISABLE\s+ROW\s+LEVEL\s+SECURITY/gi
    for (const file of files) {
      if (!/\.sql$/.test(file.rel) && !/\.toml$/.test(file.rel)) continue
      for (const hit of matches(file, DISABLE)) {
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `Row Level Security is explicitly disabled on \`${hit.match[1]}\`.`,
        })
      }
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 6. Table created without RLS ever being enabled
 * ------------------------------------------------------------------ */
rule({
  id: 'rls-never-enabled',
  severity: 'high',
  title: 'Table created without Row Level Security',
  plain:
    'This table was created but nothing in your migrations ever turns on Row Level Security for it. ' +
    'Unless you enabled it by hand in the dashboard, the table is readable by any authenticated user.',
  run(files) {
    const sql = files.filter((f) => /\.sql$/.test(f.rel))
    if (!sql.length) return []
    const allSql = sql.map((f) => stripComments(f.text, true)).join('\n')

    const enabled = new Set()
    for (const m of allSql.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?([^\s;]+)[\s\S]{0,80}?ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi)) {
      enabled.add(normalizeTable(m[1]))
    }

    // A table that was explicitly DISABLEd is already reported as critical by
    // `rls-disabled`. Reporting it here too would just be the same bug twice.
    const explicitlyDisabled = new Set()
    for (const m of allSql.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?([^\s;]+)[\s\S]{0,80}?DISABLE\s+ROW\s+LEVEL\s+SECURITY/gi)) {
      explicitlyDisabled.add(normalizeTable(m[1]))
    }

    const found = []
    for (const file of sql) {
      const CREATE = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)/gi
      for (const hit of matches(file, CREATE)) {
        const table = normalizeTable(hit.match[1])
        if (!table || enabled.has(table) || explicitlyDisabled.has(table)) continue
        if (inComment(file, hit.match.index)) continue
        // PostgREST only exposes `public`; a table in a private schema is not
        // reachable over the API, so RLS on it would change nothing.
        if (table.includes('.')) continue
        // Supabase's own bookkeeping tables are not the developer's problem.
        if (/^(auth|storage|realtime|extensions|graphql|vault|net|cron)\./.test(table)) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `No \`ENABLE ROW LEVEL SECURITY\` found anywhere in your migrations for \`${table}\`.`,
        })
      }
    }
    return found
  },
})

function normalizeTable(raw) {
  return String(raw).replace(/["`]/g, '').replace(/^public\./, '').toLowerCase()
}

/* ------------------------------------------------------------------ *
 * 7. Live secrets committed to the repo
 * ------------------------------------------------------------------ */
rule({
  id: 'live-secret-committed',
  severity: 'critical',
  title: 'A live secret is sitting in the repository',
  plain:
    'This key is in your source tree. If the repo is ever public — or an agent pushes it somewhere ' +
    'you did not intend — it is immediately usable by whoever finds it.',
  run(files) {
    const found = []
    const PATTERNS = [
      { re: /sk_live_[A-Za-z0-9]{16,}/g, what: 'Stripe live secret key' },
      { re: /rk_live_[A-Za-z0-9]{16,}/g, what: 'Stripe live restricted key' },
      { re: /sk-ant-api[A-Za-z0-9_-]{20,}/g, what: 'Anthropic API key' },
      { re: /sk-proj-[A-Za-z0-9_-]{20,}/g, what: 'OpenAI API key' },
    ]
    for (const file of files) {
      if (/\.(example|sample|template)\.|\.(example|sample|template)$/.test(file.rel)) continue
      if (isNonProduction(file.rel)) continue
      for (const { re, what } of PATTERNS) {
        for (const hit of matches(file, re)) {
          if (inComment(file, hit.match.index) && file.isDoc) continue
          if (/(.)\1{7,}/.test(hit.match[0])) continue
          if (/REPLACE|YOUR[_-]|EXAMPLE|PLACEHOLDER|XXXX|CHANGEME|\.\.\./i.test(hit.match[0])) continue
          found.push({
            file: file.rel,
            line: hit.line,
            snippet: redact(hit.snippet),
            detail: `${what} found on disk in this directory. ProdGuard does not read git, so check whether this file is actually committed.`,
          })
        }
      }
    }
    return found
  },
})

function redact(line) {
  return line.replace(/([A-Za-z0-9_-]{6})[A-Za-z0-9_-]{10,}/g, '$1…redacted…')
}

/* ------------------------------------------------------------------ *
 * 9. A credential file sitting in the repo
 * ------------------------------------------------------------------ */
rule({
  id: 'credential-file-committed',
  severity: 'critical',
  title: 'A credentials file is in your repository',
  plain:
    'Recovery codes, backup codes and key exports are account master keys — most of them bypass ' +
    'two-factor authentication entirely. In a repo they get pushed, forked, cloned and backed up. ' +
    'Keep them in a password manager or your OS keychain, never in a project folder.',
  run(files) {
    const found = []
    // Named like a credential dump...
    // Dropped the very generic `secrets`/`credentials` — a secrets runbook is
    // not a secrets dump — in favour of names that mean an actual export.
    const NAME = /(^|\/)[^/]*(recovery[-_. ]?codes?|backup[-_. ]?codes?|2fa[-_. ]?codes?|private[-_. ]?key)[^/]*\.(txt|csv|json|md|text)$/i
    // ...and actually containing secret-shaped lines, so we don't flag a doc
    // that merely discusses credentials.
    // GitHub, Google and npm recovery codes are short dashed alphanumerics —
    // the previous 16+ hex / 32+ base64 test missed all of them.
    const SECRETY =
      /^[0-9a-f]{16,}$|^[A-Za-z0-9+/]{32,}={0,2}$|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY/m
    const DASHED = /^[A-Za-z0-9]{4,8}-[A-Za-z0-9]{4,8}(-[A-Za-z0-9]{4,8})?$/gm

    for (const file of files) {
      if (!NAME.test(file.rel)) continue
      if (/\.(example|sample|template)\.|\.(example|sample|template)$/.test(file.rel)) continue
      if (isNonProduction(file.rel)) continue
      // Two or more code-shaped lines: one is a coincidence, a block is a dump.
      const dashed = (file.text.match(DASHED) || []).length
      if (!SECRETY.test(file.text) && dashed < 2) continue
      found.push({
        file: file.rel,
        line: 1,
        snippet: '',
        detail:
          'This file is named like a credential export and contains secret-shaped values. ' +
          'Move it out of the repository, then rotate whatever it holds — assume it is already exposed.',
      })
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 10. A token that is decoded but never verified
 * ------------------------------------------------------------------ */
rule({
  id: 'jwt-not-verified',
  severity: 'critical',
  title: 'Login tokens are read without checking the signature',
  plain:
    'Decoding a JWT reads what it claims to say; verifying it proves the claim came from you. ' +
    'Code that only decodes will believe any token a visitor hands it — including one they wrote ' +
    'themselves saying they are an administrator.',
  run(files) {
    const found = []
    // The receiver has to be a JWT library. Matching a bare `.decode(` also
    // catches TextDecoder, base64 helpers and stream decoders — none of which
    // are auth, and all of which appear in ordinary code.
    const DECODE =
      /\b(?:jwt|jsonWebToken|jsonwebtoken|jose)\s*\.\s*decode\s*\(|\bdecodeJwt\s*\(|\bjwt_?[Dd]ecode\s*\(/g
    for (const file of files) {
      if (file.isDoc) continue
      if (!/\.(js|jsx|ts|tsx|mjs|cjs|mts|cts)$/.test(file.rel)) continue
      if (!/jwt|jsonwebtoken|jose/i.test(file.text)) continue
      // `.verify()` anywhere used to suppress the whole file, so an unrelated
      // hmac.verify() next to a jwt.decode() hid the bug. Require the verify
      // to belong to a JWT library.
      if (isNonProduction(file.rel)) continue
      const code = stripComments(file.text)
      if (/\b(?:jwt|jsonWebToken|jsonwebtoken|jose)\s*\.\s*verify\s*\(|\bjwtVerify\s*\(|\bverifyIdToken\s*\(/.test(code)) continue
      // Decoding purely to read `exp` and schedule a refresh trusts nothing.
      if (!/\brole\b|\badmin\b|isAdmin|permission|scope|authoriz|\bres\.|\bnext\s*\(/i.test(code)) continue
      // A file that verifies somewhere is doing the right thing.
      for (const hit of matches(file, DECODE)) {
        if (isDiscussion(hit.snippet)) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: 'This decodes a token but nothing in the file verifies its signature.',
        })
      }
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 11. Firebase security rules left wide open
 * ------------------------------------------------------------------ */
rule({
  id: 'firebase-rules-open',
  severity: 'critical',
  title: 'Firebase rules allow anyone to read or write',
  plain:
    'A rule that always evaluates true means any person on the internet can read, overwrite ' +
    'and delete this data without logging in. It is the Firebase equivalent of leaving Row Level ' +
    'Security off.',
  run(files) {
    const found = []
    // `if true` is the obvious form. Firebase's own console "test mode" writes
    // a time bomb instead, and Realtime Database uses a different syntax
    // entirely — both are wide open, and both were invisible before.
    const OPEN =
      /allow\s+(read|write|create|update|delete)[^;:]*:\s*if\s+(?:true\b|request\.time\s*[<≤]|1\s*==\s*1)|"\.(read|write)"\s*:\s*true/gi
    for (const file of files) {
      if (!/\.rules$|firestore\.rules|storage\.rules|database\.rules\.json/i.test(file.rel)) continue
      for (const hit of matches(file, OPEN)) {
        if (inComment(file, hit.match.index)) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: /request\.time/.test(hit.snippet)
            ? 'This is Firebase\'s "test mode" rule: open to the whole internet until the date passes, then closed to everyone.'
            : `This grants ${hit.match[1] || hit.match[2] || 'access'} to every visitor, signed in or not.`,
        })
      }
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 12. CORS opened to everyone while sending credentials
 * ------------------------------------------------------------------ */
rule({
  id: 'cors-wildcard-credentials',
  severity: 'high',
  title: 'Any website can call this API with your users\' cookies',
  plain:
    'Allowing every origin while also allowing credentials lets a page the attacker controls make ' +
    'requests to your API as your logged-in user, and read the answer. Browsers block this pairing ' +
    'for good reason; forcing it back on re-opens the hole.',
  run(files) {
    const found = []
    for (const file of files) {
      if (file.isDoc) continue
      if (!/\.(js|jsx|ts|tsx|mjs|cjs|mts|cts|json|yml|yaml|toml)$/.test(file.rel)) continue
      const wildcard =
        /(Access-Control-Allow-Origin["'\s:=,]+\*)|(origin\s*:\s*["']\*["'])|(origin\s*:\s*true\b)|(Access-Control-Allow-Origin["'\s:=,]+.{0,40}headers\.origin)/i
      // \b so axios's `withCredentials: true` does not masquerade as CORS creds.
      const creds = /(Access-Control-Allow-Credentials["'\s:=,]+true)|(^|[^A-Za-z])credentials\s*:\s*true/i
      const code = stripComments(file.text)
      if (!wildcard.test(code) || !creds.test(code)) continue
      // Two correctly-configured routes in one file are not one hole: the
      // wildcard and the credentials have to belong to the same config.
      const wIdx = code.search(wildcard)
      const cIdx = code.search(creds)
      if (wIdx === -1 || cIdx === -1 || Math.abs(wIdx - cIdx) > 400) continue
      const anchor = { line: lineOf(file, wIdx), snippet: (file.lines[lineOf(file, wIdx) - 1] || '').trim().slice(0, 160) }
      found.push({
        file: file.rel,
        line: anchor.line,
        snippet: anchor.snippet,
        detail: 'This file allows every origin and also allows credentials on the same endpoint.',
      })
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 8. Destructive migration
 * ------------------------------------------------------------------ */
rule({
  id: 'destructive-migration',
  severity: 'high',
  title: 'Migration destroys data',
  plain:
    'This migration drops or empties a table. If an agent wrote it and it runs against production, ' +
    'the data is gone and no amount of redeploying brings it back.',
  run(files) {
    const found = []
    const DESTRUCTIVE =
      /\b(DROP\s+TABLE|TRUNCATE(?:\s+TABLE)?|DROP\s+SCHEMA|DROP\s+DATABASE)\s+(?:IF\s+EXISTS\s+)?([^\s;]+)|\b(ALTER\s+TABLE)\s+([^\s;]+)[\s\S]{0,40}?DROP\s+COLUMN|\b(DELETE\s+FROM)\s+([^\s;]+)\s*;/gi
    for (const file of files) {
      if (!isMigration(file.rel)) continue
      // A down migration undoing its up migration is the entire point of one.
      if (/\.down\.sql$|_down\.sql$|(^|\/)down\//i.test(file.rel)) continue
      for (const hit of matches(file, DESTRUCTIVE)) {
        if (inComment(file, hit.match.index)) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: (() => {
          const g = hit.match.slice(1).filter((x) => x !== undefined)
          const what = (g[0] || '').trim().toUpperCase()
          const target = g[1] || ''
          if (what.startsWith('DELETE')) return `\`DELETE FROM ${target}\` with no WHERE clause empties the table.`
          if (what.startsWith('ALTER')) return `\`DROP COLUMN\` on \`${target}\` destroys that column's data.`
          return `\`${what}\` on \`${target}\`.`
        })(),
        })
      }
    }
    return found
  },
})

export function runRules(files) {
  const results = []
  // One line can match a pattern several times (alternations, repeated terms).
  // The developer only needs to be told about that line once.
  const seen = new Set()
  for (const def of rules) {
    let hits = []
    try {
      hits = def.run(files) || []
    } catch (err) {
      console.error(`prodguard: rule ${def.id} failed — ${err.message}`)
      continue
    }
    for (const hit of hits) {
      const key = `${def.id}|${hit.file}|${hit.line}`
      if (seen.has(key)) continue
      seen.add(key)
      // Central, unconditional. No rule can forget.
      if (hit.snippet) hit.snippet = redactSecrets(hit.snippet)
      if (hit.detail) hit.detail = redactSecrets(hit.detail)
      results.push({
        rule: def.id,
        severity: def.severity,
        title: def.title,
        plain: def.plain,
        ...hit,
      })
    }
  }
  return results.sort(
    (a, b) => SEVERITY[b.severity] - SEVERITY[a.severity] || a.file.localeCompare(b.file) || a.line - b.line,
  )
}

export const allRules = rules
