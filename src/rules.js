import { matches } from './scan.js'

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
    const GATE =
      /(?:const|let|var)\s+(locked|isLocked|hasAccess|isPaid|isPro|isPremium|hasActiveSub|hasSubscription|isSubscribed|canAccess|isTrialExpired)\s*=\s*(true|false)\b/g

    for (const file of files) {
      if (isMigration(file.rel)) continue
      for (const hit of matches(file, GATE)) {
        const name = hit.match[1]
        const value = hit.match[2]
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
      if (!/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(file.rel)) continue
      const looksLikeWebhook =
        /webhook/i.test(file.rel) ||
        /stripe-signature/i.test(file.text) ||
        /STRIPE_WEBHOOK_SECRET/.test(file.text)
      if (!looksLikeWebhook) continue
      if (!/stripe/i.test(file.text)) continue
      // The only thing that actually authenticates a Stripe webhook.
      if (/constructEvent(Async)?\s*\(/.test(file.text)) continue

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
      { re: /email_confirm\s*:\s*true/g, why: 'accounts are being auto-confirmed through the admin API' },
      { re: /enable_confirmations\s*=\s*false/g, why: 'Supabase config has confirmations disabled' },
      { re: /"enable_confirmations"\s*:\s*false/g, why: 'Supabase config has confirmations disabled' },
      { re: /mailer_autoconfirm\s*[=:]\s*true/g, why: 'Supabase is set to auto-confirm every signup' },
    ]
    for (const file of files) {
      for (const { re, why } of PATTERNS) {
        for (const hit of matches(file, re)) {
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
      for (const hit of matches(file, PUBLIC_PREFIXED)) {
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${hit.match[0]}\` uses a public env prefix, so its value is bundled into client-side JavaScript.`,
        })
      }
      if (!isClientReachable(file.rel)) continue
      for (const hit of matches(file, SERVICE_ROLE)) {
        if (isDiscussion(hit.snippet)) continue
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
    const allSql = sql.map((f) => f.text).join('\n')

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
      if (/\.example$|\.sample$|\.template$/.test(file.rel)) continue
      for (const { re, what } of PATTERNS) {
        for (const hit of matches(file, re)) {
          found.push({
            file: file.rel,
            line: hit.line,
            snippet: redact(hit.snippet),
            detail: `${what} found in tracked source.`,
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
    const DESTRUCTIVE = /\b(DROP\s+TABLE|TRUNCATE\s+(?:TABLE\s+)?|DROP\s+SCHEMA)\s+(?:IF\s+EXISTS\s+)?([^\s;]+)/gi
    for (const file of files) {
      if (!isMigration(file.rel)) continue
      for (const hit of matches(file, DESTRUCTIVE)) {
        found.push({
          file: file.rel,
          line: hit.line,
          snippet: hit.snippet,
          detail: `\`${hit.match[1].trim().toUpperCase()}\` on \`${hit.match[2]}\`.`,
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
      console.error(`shipguard: rule ${def.id} failed — ${err.message}`)
      continue
    }
    for (const hit of hits) {
      const key = `${def.id}|${hit.file}|${hit.line}`
      if (seen.has(key)) continue
      seen.add(key)
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
