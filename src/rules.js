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

/* ------------------------------------------------------------------ *
 * 13-15. SECURITY DEFINER — the other way RLS gets bypassed
 *
 * Raised by a reader on r/Supabase minutes after release: an agent that
 * cannot work out a policy often does not disable RLS at all. It writes a
 * SECURITY DEFINER function that runs as the owner and steps around it.
 *
 * These mirror Supabase's own linter (0010, 0011, 0028/0029) rather than
 * inventing a standard. SECURITY DEFINER on its own is legitimate and their
 * docs recommend it for escaping policy recursion, so flagging the keyword
 * would be noise. Only the dangerous combinations fire.
 * ------------------------------------------------------------------ */

const NEXT_STATEMENT = /\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?(?:FUNCTION|VIEW|TABLE|POLICY|TRIGGER|INDEX)\b/i

// One CREATE block: from `start` to the next CREATE, capped at 4000 chars.
// Sliced by index rather than matched with a regex that spans dollar-quoted
// bodies — that shape is what produced the 159-second CI hang.
function blockAt(text, start) {
  const from = start + 6
  const rel = text.slice(from).search(NEXT_STATEMENT)
  const end = rel === -1 ? text.length : from + rel
  return text.slice(start, Math.min(end, start + 4000))
}

// A CREATE POLICY is a single statement, but blockAt runs to the next CREATE and
// so swallows whatever follows it. An ordinary `GRANT ... TO authenticated` sitting
// after a policy was enough on its own to satisfy the TO test in
// policy-missing-to-clause and silence a real finding — a pass that should have
// been a report, which is the failure this scanner treats as worse than a miss.
// Semicolons inside quoted strings are not terminators.
function firstStatement(block) {
  let quoted = false
  for (let i = 0; i < block.length; i++) {
    const ch = block[i]
    if (ch === "'") quoted = !quoted
    else if (ch === ';' && !quoted) return block.slice(0, i + 1)
  }
  return block
}

function normalizeFn(raw) {
  return String(raw).replace(/["`]/g, '').replace(/^public\./, '').toLowerCase()
}

const FUNCTION_HEAD = /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([A-Za-z0-9_."]+)/gi
const VIEW_HEAD = /CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+([A-Za-z0-9_."]+)/gi
const IS_DEFINER = /\bSECURITY\s+DEFINER\b/i

// Comments are blanked, not removed, so indexes still line up with the raw
// file. A commented-out `SET search_path` must not silence the finding, and a
// commented-out `SECURITY DEFINER` must not create one.
function sqlFiles(files) {
  return files
    .filter((f) => /\.sql$/.test(f.rel))
    .map((f) => ({ file: f, sql: stripComments(f.text, true) }))
}

// Roles explicitly granted EXECUTE, gathered across every migration — the
// GRANT is routinely in a different file from the CREATE.
function executeGrants(pairs) {
  const map = new Map()
  const GRANT = /GRANT\s+(?:ALL|EXECUTE)[^;]{0,80}?\bON\s+FUNCTION\s+([A-Za-z0-9_."]+)[^;]{0,200}?\bTO\s+([^;]{1,120})/gi
  for (const { sql } of pairs) {
    for (const m of sql.matchAll(GRANT)) {
      const fn = normalizeFn(m[1])
      if (!map.has(fn)) map.set(fn, new Set())
      for (const role of m[2].toLowerCase().split(/[\s,]+/)) {
        const clean = role.replace(/["`;()]/g, '')
        if (clean) map.get(fn).add(clean)
      }
    }
  }
  return map
}

rule({
  id: 'security-definer-anon-executable',
  severity: 'critical',
  title: 'SECURITY DEFINER function is callable by anonymous users',
  plain:
    'This function runs with its owner\'s privileges, so Row Level Security does not apply to anything it touches. ' +
    'EXECUTE is granted to a role reachable without logging in, which makes it a public door into those tables.',
  run(files) {
    const pairs = sqlFiles(files)
    if (!pairs.length) return []
    const grants = executeGrants(pairs)
    const found = []
    for (const { file, sql } of pairs) {
      for (const hit of matches(file, FUNCTION_HEAD)) {
        if (inComment(file, hit.match.index)) continue
        if (!IS_DEFINER.test(blockAt(sql, hit.match.index))) continue
        const roles = grants.get(normalizeFn(hit.match[1]))
        if (!roles) continue
        const open = [...roles].filter((r) => r === 'anon' || r === 'public')
        if (!open.length) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${hit.match[1]}\` is SECURITY DEFINER and EXECUTE is granted to \`${open.join('`, `')}\`.`,
        })
      }
    }
    return found
  },
})

rule({
  id: 'security-definer-search-path',
  severity: 'medium',
  title: 'SECURITY DEFINER function has no fixed search_path',
  plain:
    'Without `SET search_path`, this function resolves table and function names using the caller\'s search path. ' +
    'Anyone able to create objects in a schema on that path can have their version run with the owner\'s privileges. ' +
    'Supabase reports this as function_search_path_mutable.',
  run(files) {
    const found = []
    for (const { file, sql } of sqlFiles(files)) {
      for (const hit of matches(file, FUNCTION_HEAD)) {
        if (inComment(file, hit.match.index)) continue
        const body = blockAt(sql, hit.match.index)
        if (!IS_DEFINER.test(body)) continue
        if (/\bSET\s+search_path\b/i.test(body)) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${hit.match[1]}\` is SECURITY DEFINER with no \`SET search_path\`.`,
        })
      }
    }
    return found
  },
})

rule({
  id: 'security-definer-view',
  severity: 'high',
  title: 'View in public ignores Row Level Security',
  plain:
    'A view reads its underlying tables as whoever created it unless `security_invoker` is set, so RLS on those ' +
    'tables does not apply to whoever selects from the view. Supabase reports this as security_definer_view. ' +
    'The fix is `WITH (security_invoker = on)`.',
  run(files) {
    const found = []
    for (const { file, sql } of sqlFiles(files)) {
      for (const hit of matches(file, VIEW_HEAD)) {
        if (inComment(file, hit.match.index)) continue
        const name = String(hit.match[1]).replace(/["`]/g, '')
        // PostgREST only exposes `public`; a view in a private schema is not
        // reachable over the API.
        if (name.includes('.') && !/^public\./i.test(name)) continue
        if (/security_invoker\s*=\s*(true|on|1)/i.test(blockAt(sql, hit.match.index))) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${name}\` has no \`security_invoker\`, so it queries as its owner and bypasses RLS.`,
        })
      }
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 16-18. Grants and duplicate policies — RLS defeated without touching RLS
 *
 * Both reported by readers on r/Supabase. An agent that hits "permission
 * denied" often does not disable RLS at all: it widens a GRANT, or bolts a
 * second permissive policy alongside the existing one. Postgres ORs
 * permissive policies, so a `USING (true)` wins silently and both policies
 * read perfectly fine on their own.
 * ------------------------------------------------------------------ */

// Reads a balanced parenthesised expression starting at `open`, so a nested
// predicate like `USING ((select auth.uid()) = owner)` is read whole. Counting
// characters beats a regex here: the pattern that would match nested parens is
// the same shape that hung CI for 159 seconds.
function readParen(text, open) {
  if (text[open] !== '(') return ''
  let depth = 0
  for (let i = open; i < text.length && i < open + 4000; i++) {
    if (text[i] === '(') depth++
    else if (text[i] === ')') {
      depth--
      if (depth === 0) return text.slice(open + 1, i)
    }
  }
  return ''
}

// `(true)`, `( TRUE )`, `((true))` — all the same unconditional pass.
function isAlwaysTrue(expr) {
  let e = String(expr).trim()
  while (e.startsWith('(') && e.endsWith(')')) e = e.slice(1, -1).trim()
  return /^true$/i.test(e)
}

const OPEN_ROLES = new Set(['anon', 'public'])
const WRITE_PRIVS = /\b(ALL|INSERT|UPDATE|DELETE|TRUNCATE)\b/i

// GRANT <privs> ON [TABLE] <name> TO <roles>. Bounded so it cannot run away.
const GRANT_RE = /GRANT\s+([A-Za-z, ]{2,80}?)\s+ON\s+(?:TABLE\s+)?([A-Za-z0-9_."]+)\s+TO\s+([^;]{1,120})/gi

// `GRANT ... ON ALL TABLES IN SCHEMA public TO anon` is the same act at schema
// scope, and the per-table pattern above cannot see it: there is no table name
// between ON and TO. Reported by a reader who audits Supabase projects, as the
// migration an agent writes to "fix" a permissions error, silently undoing every
// earlier hardening migration in one line.
const GRANT_SCHEMA_RE = /GRANT\s+([A-Za-z, ]{2,80}?)\s+ON\s+ALL\s+(TABLES|SEQUENCES|FUNCTIONS|ROUTINES)\s+IN\s+SCHEMA\s+([A-Za-z0-9_.", ]{1,80}?)\s+TO\s+([^;]{1,120})/gi

function grantRoles(raw) {
  return String(raw)
    .toLowerCase()
    .split(/[\s,]+/)
    .map((r) => r.replace(/["`;]/g, ''))
    .filter(Boolean)
}

// Postgres checks the table privilege before it ever evaluates a policy, so a
// policy is only reachable if the role actually holds the grant. A missing TO on
// a table where `anon` was never granted SELECT leaks nothing, whatever the
// predicate says. Reported by the reader whose missing-TO report became the rule
// below, as the third condition it was missing.
//
// The naive reading of that — fire only when a GRANT to anon is visible — would
// be an inversion rather than a refinement. In Supabase the grant is a platform
// default that never appears in the repository at all, so requiring positive
// evidence of it would silence nearly every true finding, which is the failure
// mode this scanner treats as worse than a miss. The default assumption stays
// "anon can reach it"; only an explicit REVOKE in the repo, never re-granted,
// takes a table back out of scope.
const REVOKE_RE = /REVOKE\s+([A-Za-z, ]{2,80}?)\s+ON\s+(?:TABLE\s+)?([A-Za-z0-9_."]+)\s+FROM\s+([^;]{1,120})/gi

function coversSelect(raw) {
  return /\b(ALL|SELECT)\b/i.test(String(raw))
}

function opensToAnon(raw) {
  return grantRoles(raw).some((r) => OPEN_ROLES.has(r))
}

// Tables this repo explicitly puts out of anon's reach.
function anonUnreachableTables(pairs) {
  const revoked = new Set()
  const regranted = new Set()
  for (const { sql } of pairs) {
    for (const m of sql.matchAll(REVOKE_RE)) {
      if (coversSelect(m[1]) && opensToAnon(m[3])) revoked.add(normalizeTable(m[2]))
    }
    for (const m of sql.matchAll(GRANT_RE)) {
      if (coversSelect(m[1]) && opensToAnon(m[3])) regranted.add(normalizeTable(m[2]))
    }
  }
  // Migration order across files is not something this can resolve, so when a
  // table is both revoked and granted the finding stands rather than being
  // dropped on a guess.
  for (const t of regranted) revoked.delete(t)
  return revoked
}

rule({
  id: 'anon-write-grant',
  severity: 'critical',
  title: 'Write access granted to unauthenticated users',
  plain:
    'This grants insert, update or delete on a table to a role anyone can reach without logging in. ' +
    'Row Level Security still applies, but any gap in a policy is now writable by the public internet, ' +
    'and a grant is the quiet way an agent answers "permission denied" without touching RLS at all.',
  run(files) {
    const found = []
    for (const { file, sql } of sqlFiles(files)) {
      for (const hit of matches(file, GRANT_RE)) {
        if (inComment(file, hit.match.index)) continue
        if (!WRITE_PRIVS.test(hit.match[1])) continue
        const open = grantRoles(hit.match[3]).filter((r) => OPEN_ROLES.has(r))
        if (!open.length) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${hit.match[1].trim().toUpperCase()}\` on \`${hit.match[2]}\` granted to \`${open.join('`, `')}\`.`,
        })
      }
      void sql
    }
    return found
  },
})

rule({
  id: 'grant-all-on-table',
  severity: 'high',
  title: 'GRANT ALL replaces whatever column-level access you had',
  plain:
    'GRANT ALL hands over every privilege on the table, including TRUNCATE, and supersedes any ' +
    'column-level grants that were limiting access before. Nothing is disabled and no policy changes, ' +
    'so every other check here still passes — the access just got wider in one line.',
  run(files) {
    const found = []
    for (const { file, sql } of sqlFiles(files)) {
      for (const hit of matches(file, GRANT_RE)) {
        if (inComment(file, hit.match.index)) continue
        if (!/^\s*ALL\b/i.test(hit.match[1])) continue
        const roles = grantRoles(hit.match[3])
        // anon/public is the critical rule's job; don't report it twice.
        if (roles.some((r) => OPEN_ROLES.has(r))) continue
        if (!roles.includes('authenticated')) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`GRANT ALL\` on \`${hit.match[2]}\` to \`authenticated\`. Grant only the privileges the app uses.`,
        })
      }
      void sql
    }
    return found
  },
})

const POLICY_HEAD = /CREATE\s+POLICY\s+(?:"([^"]{1,80})"|([A-Za-z0-9_]{1,80}))\s+ON\s+([A-Za-z0-9_."]+)/gi

rule({
  id: 'duplicate-permissive-policy',
  severity: 'critical',
  title: 'A second permissive policy overrides the one next to it',
  plain:
    'Postgres combines permissive policies with OR, so when several cover the same command the most ' +
    'open one decides. A `USING (true)` sitting beside a real policy silently grants everything, and ' +
    'both policies read perfectly fine on their own.',
  run(files) {
    const pairs = sqlFiles(files)
    if (!pairs.length) return []

    // Collect every policy across all migrations first — the permissive one is
    // routinely added in a later file than the policy it overrides.
    const policies = []
    for (const { file, sql } of pairs) {
      for (const hit of matches(file, POLICY_HEAD)) {
        if (inComment(file, hit.match.index)) continue
        const body = blockAt(sql, hit.match.index)
        if (/\bAS\s+RESTRICTIVE\b/i.test(body)) continue // restrictive policies AND, they cannot widen
        const cmd = (body.match(/\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b/i) || [, 'ALL'])[1].toUpperCase()
        const usingAt = body.search(/\bUSING\s*\(/i)
        const checkAt = body.search(/\bWITH\s+CHECK\s*\(/i)
        const usingExpr = usingAt === -1 ? '' : readParen(body, body.indexOf('(', usingAt))
        const checkExpr = checkAt === -1 ? '' : readParen(body, body.indexOf('(', checkAt))
        policies.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          name: hit.match[1] || hit.match[2],
          table: normalizeTable(hit.match[3]),
          cmd,
          open: isAlwaysTrue(usingExpr) || isAlwaysTrue(checkExpr),
        })
      }
    }

    const overlaps = (a, b) => a === b || a === 'ALL' || b === 'ALL'
    const found = []
    for (const p of policies) {
      if (!p.open) continue
      // A lone `USING (true)` policy may well be a deliberately public table.
      // It is only a silent override when something else already covers the
      // same command and is being widened by this one.
      const others = policies.filter((q) => q !== p && q.table === p.table && overlaps(q.cmd, p.cmd))
      if (!others.length) continue
      found.push({
        file: p.file,
        line: p.line,
        snippet: p.snippet,
        detail:
          `\`${p.name}\` on \`${p.table}\` is permissive and always true, alongside ` +
          `${others.length} other polic${others.length === 1 ? 'y' : 'ies'} for ${p.cmd}. ` +
          `Permissive policies are OR'd, so this one decides.`,
      })
    }
    return found
  },
})

/* ------------------------------------------------------------------ *
 * 19-20. Two more from the same r/Supabase thread
 * ------------------------------------------------------------------ */

rule({
  id: 'grant-schema-wide',
  severity: 'critical',
  title: 'Every table in the schema granted at once',
  plain:
    'This grants on ALL objects in a schema in a single statement, so it covers tables the author ' +
    'never looked at and silently supersedes any narrower grants earlier migrations set up. ' +
    'When the target role is reachable without logging in, every table in the schema is exposed ' +
    'and only Row Level Security is left standing between the public internet and the data.',
  run(files) {
    const found = []
    for (const { file } of sqlFiles(files)) {
      for (const hit of matches(file, GRANT_SCHEMA_RE)) {
        if (inComment(file, hit.match.index)) continue
        const privs = hit.match[1].trim().toUpperCase()
        if (!WRITE_PRIVS.test(privs) && !/\bSELECT\b/i.test(privs)) continue
        const roles = grantRoles(hit.match[4])
        const open = roles.filter((r) => OPEN_ROLES.has(r) || r === 'authenticated')
        if (!open.length) continue
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail:
            `\`${privs}\` on ALL ${hit.match[2].toUpperCase()} in schema \`${hit.match[3].trim()}\` ` +
            `granted to \`${open.join('`, `')}\`. Grant per table, per privilege.`,
        })
      }
    }
    return found
  },
})

rule({
  id: 'policy-write-check-open',
  severity: 'critical',
  title: 'Policy reads carefully but lets anything be written',
  plain:
    'The USING expression scopes which rows the caller can see, but WITH CHECK is unconditional, ' +
    'so the caller can write a row that does not satisfy it — moving a record to another owner, ' +
    'or inserting one under someone else\'s id. The read side looks correct in review, which is ' +
    'exactly why this survives one. Omitting WITH CHECK entirely is safe (Postgres falls back to ' +
    'USING); writing it as `true` is not.',
  run(files) {
    const found = []
    for (const { file, sql } of sqlFiles(files)) {
      for (const hit of matches(file, POLICY_HEAD)) {
        if (inComment(file, hit.match.index)) continue
        const body = blockAt(sql, hit.match.index)
        if (/\bAS\s+RESTRICTIVE\b/i.test(body)) continue
        const checkAt = body.search(/\bWITH\s+CHECK\s*\(/i)
        if (checkAt === -1) continue // omitted is safe: USING is reused
        if (!isAlwaysTrue(readParen(body, body.indexOf('(', checkAt)))) continue
        // A policy that is open on BOTH sides is a deliberately public table, and
        // duplicate-permissive-policy already speaks to the read side. The bug
        // here is specifically a careful read paired with an open write.
        const usingAt = body.search(/\bUSING\s*\(/i)
        if (usingAt === -1) continue
        if (isAlwaysTrue(readParen(body, body.indexOf('(', usingAt)))) continue
        const name = hit.match[1] || hit.match[2]
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${name}\` on \`${normalizeTable(hit.match[3])}\` scopes reads but its \`WITH CHECK\` is \`true\`, so writes are unrestricted.`,
        })
      }
    }
    return found
  },
})

rule({
  id: 'policy-missing-to-clause',
  severity: 'high',
  title: 'Policy has no TO clause, so it also answers anonymous requests',
  plain:
    'A CREATE POLICY with no TO clause defaults to PUBLIC, which includes anon, this ' +
    'predicate does not depend on who is calling, and nothing in this repo revokes anon\'s access ' +
    'to the table — so it matches rows for an unauthenticated request too. Nothing is disabled and ' +
    'the policy reads correctly; the role it covers is just wider than whoever wrote it assumed. ' +
    'Add `TO authenticated`.',
  run(files) {
    const pairs = sqlFiles(files)
    const unreachable = anonUnreachableTables(pairs)
    const found = []
    for (const { file, sql } of pairs) {
      for (const hit of matches(file, POLICY_HEAD)) {
        if (inComment(file, hit.match.index)) continue
        // Third condition: anon has to actually hold the table privilege for any
        // of this to be reachable. See anonUnreachableTables above for why this
        // suppresses on evidence rather than requiring it.
        if (unreachable.has(normalizeTable(hit.match[3]))) continue
        // The policy's own statement, not everything up to the next CREATE — see
        // firstStatement for the GRANT that used to silence this.
        const body = firstStatement(blockAt(sql, hit.match.index))
        if (/\bTO\s+[A-Za-z0-9_"]/i.test(body)) continue
        // A restrictive policy only ever narrows access, so a missing TO on one
        // cannot widen anything.
        if (/\bAS\s+RESTRICTIVE\b/i.test(body)) continue
        // The predicate decides whether this actually matters. `auth.uid() = owner`
        // evaluates to NULL for an anonymous caller, so the policy matches no rows
        // and the missing TO leaks nothing — flagging those would fire on almost
        // every Supabase project and get the tool uninstalled. Only an
        // identity-independent predicate (`is_public`, `true`, a plain column
        // comparison) actually hands rows to anon.
        if (/\b(auth\s*\.\s*(uid|jwt|role)|current_setting|current_user|session_user)\b/i.test(body)) continue
        const name = hit.match[1] || hit.match[2]
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${name}\` on \`${normalizeTable(hit.match[3])}\` has no \`TO\` clause, so it defaults to PUBLIC (which includes \`anon\`).`,
        })
      }
    }
    return found
  },
})

// Columns introduced by CREATE TABLE and ALTER TABLE ... ADD COLUMN, per table.
// Deliberately additive: a column this misses only costs a finding we don't
// raise, whereas one we invent costs a false positive.
function declaredColumns(pairs) {
  const byTable = new Map()
  const add = (table, col) => {
    const t = normalizeTable(table)
    if (!byTable.has(t)) byTable.set(t, new Set())
    byTable.get(t).add(String(col).replace(/["`]/g, '').toLowerCase())
  }
  for (const { sql } of pairs) {
    for (const m of sql.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_."]+)\s*\(/gi)) {
      const inner = readParen(sql, sql.indexOf('(', m.index + m[0].length - 1))
      // Split on top-level commas only, so `numeric(10, 2)` stays one column.
      let depth = 0, cur = ''
      const parts = []
      for (const ch of inner) {
        if (ch === '(') depth++
        else if (ch === ')') depth--
        if (ch === ',' && depth === 0) { parts.push(cur); cur = '' } else cur += ch
      }
      parts.push(cur)
      for (const part of parts) {
        const name = part.trim().split(/\s+/)[0]
        if (!name) continue
        // Skip table-level constraints, which are not columns.
        if (/^(primary|foreign|unique|check|constraint|exclude|like)$/i.test(name)) continue
        add(m[1], name)
      }
    }
    for (const m of sql.matchAll(/ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?([A-Za-z0-9_."]+)[\s\S]{0,60}?ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_"]+)/gi)) {
      add(m[1], m[2])
    }
  }
  return byTable
}

// Identifiers a policy predicate references. Function names, keywords and
// qualified references are excluded — only bare identifiers that could plausibly
// be a column of the policy's own table.
const SQL_WORDS = new Set([
  'and','or','not','in','is','null','true','false','select','from','where','exists','case','when',
  'then','else','end','like','ilike','any','all','between','as','on','using','with','check','cast',
  'current_setting','auth','uid','jwt','role','coalesce','array','text','uuid','int','boolean','left',
  'join','inner','outer','distinct','count','sum','min','max','now','current_user','session_user',
])
function referencedIdentifiers(expr) {
  const out = new Set()
  const cleaned = String(expr).replace(/'[^']*'/g, ' ')
  for (const m of cleaned.matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*(\(|\.)?/g)) {
    const word = m[1].toLowerCase()
    if (m[2]) continue           // a function call or a qualified prefix, not a bare column
    if (SQL_WORDS.has(word)) continue
    out.add(word)
  }
  return out
}

rule({
  id: 'policy-references-missing-column',
  severity: 'medium',
  title: 'Policy references a column that does not exist',
  plain:
    'This policy predicate names a column that no migration ever creates on that table. ' +
    'Usually the wake of a rename that nobody re-checked RLS against, which means the policy is ' +
    'not filtering on what its author thought. It cannot catch a rename to another valid column — ' +
    'only two authenticated sessions reading the same table settles that.',
  run(files) {
    const pairs = sqlFiles(files)
    if (!pairs.length) return []
    const columns = declaredColumns(pairs)
    if (!columns.size) return []

    const found = []
    for (const { file, sql } of pairs) {
      for (const hit of matches(file, POLICY_HEAD)) {
        if (inComment(file, hit.match.index)) continue
        const table = normalizeTable(hit.match[3])
        const known = columns.get(table)
        // Only judge tables this repo actually defines. A policy on a table
        // created elsewhere would otherwise report every column as missing.
        if (!known || !known.size) continue
        const body = blockAt(sql, hit.match.index)
        const preds = []
        const u = body.search(/\bUSING\s*\(/i)
        const c = body.search(/\bWITH\s+CHECK\s*\(/i)
        if (u !== -1) preds.push(readParen(body, body.indexOf('(', u)))
        if (c !== -1) preds.push(readParen(body, body.indexOf('(', c)))
        // A subquery pulls in other tables' columns, which this cannot resolve.
        if (preds.some((e) => /\bSELECT\b/i.test(e))) continue

        const missing = []
        for (const ident of referencedIdentifiers(preds.join(' '))) {
          if (!known.has(ident)) missing.push(ident)
        }
        if (!missing.length) continue
        const name = hit.match[1] || hit.match[2]
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${name}\` references \`${missing.join('`, `')}\` on \`${table}\`, which no migration creates. Verify the policy still filters on what you intend.`,
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
