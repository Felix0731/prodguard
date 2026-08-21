#!/usr/bin/env node
// Zero-dependency test runner. Scans two fixture repos: `bad/` must trip every
// rule, `good/` must trip none. Exits non-zero if either expectation breaks.
import { dirname, join } from 'node:path'
import { writeFileSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { collectFiles } from '../src/scan.js'
import { runRules, allRules } from '../src/rules.js'

const here = dirname(fileURLToPath(import.meta.url))

// The secret fixture is generated at run time, never committed. A literal
// `sk_live_...` string in the repo trips GitHub's secret scanning, which
// blocks the push — so the pieces only ever meet in memory.
const secretFixture = join(here, 'fixtures', 'bad', 'src', 'pages', 'keys.js')
mkdirSync(dirname(secretFixture), { recursive: true })
writeFileSync(
  secretFixture,
  `export const stripeKey = "${'sk_' + 'live_' + '51FAKEKEYFORTESTSONLY0000'}"\n`,
)
const scan = (name) => runRules(collectFiles(join(here, 'fixtures', name)))

const bad = scan('bad')
const good = scan('good')
const badRules = new Set(bad.map((f) => f.rule))

let failures = 0
const pass = (msg) => console.log(`  \u001b[32m✓\u001b[0m ${msg}`)
const fail = (msg) => {
  failures++
  console.log(`  \u001b[31m✗\u001b[0m ${msg}`)
}

console.log('\n  bad/ fixture — every rule should fire\n')
for (const rule of allRules) {
  if (badRules.has(rule.id)) pass(rule.id)
  else fail(`${rule.id} did not fire on the bad fixture`)
}

console.log('\n  good/ fixture — nothing should fire\n')
if (good.length === 0) {
  pass('clean repo produced zero findings')
} else {
  for (const f of good) fail(`false positive: ${f.rule} at ${f.file}:${f.line} — ${f.snippet}`)
}

console.log('\n  specifics\n')
const expect = (label, cond) => (cond ? pass(label) : fail(label))

expect(
  'paywall rule points at the exact line',
  bad.some((f) => f.rule === 'paywall-disabled' && f.file.endsWith('Dashboard.jsx') && f.line === 2),
)
expect(
  'secret is redacted in output',
  bad.some((f) => f.rule === 'live-secret-committed' && !f.snippet.includes('51QxAbCdEfGhIjKlMnOpQrStUvWx')),
)
expect(
  'rls-never-enabled flags invoices but not quotes',
  bad.some((f) => f.rule === 'rls-never-enabled' && /invoices/.test(f.detail)) &&
    !bad.some((f) => f.rule === 'rls-never-enabled' && /quotes/.test(f.detail)),
)
expect('critical findings exist in bad fixture', bad.some((f) => f.severity === 'critical'))
expect(
  'docs quoting broken code do not fire (README.md in good/)',
  !good.some((f) => /README\.md/.test(f.file)),
)
expect(
  'TextDecoder is not mistaken for an unverified JWT',
  !good.some((f) => f.rule === 'jwt-not-verified'),
)

// Evasions found by red-teaming. Each of these was silent before.
expect(
  'a UI lock with no billing context is not a paywall',
  !good.some((f) => f.rule === 'paywall-disabled'),
)
expect(
  'useState(false) counts as a paywall gate',
  bad.some((f) => f.rule === 'paywall-disabled' && /useGate\.tsx/.test(f.file)),
)
expect(
  'Realtime Database rules are checked, not just firestore.rules',
  bad.some((f) => f.rule === 'firebase-rules-open' && /database\.rules\.json/.test(f.file)),
)
expect(
  'short dashed recovery codes are recognised',
  bad.some((f) => f.rule === 'credential-file-committed' && /recovery-codes\.txt/.test(f.file)),
)
expect(
  'a comment promising constructEvent does not silence the warning',
  bad.some((f) => f.rule === 'stripe-webhook-unverified' && /late-webhook\.mts/.test(f.file)),
)

// SECURITY DEFINER (r/Supabase, 2026-08-18). The keyword alone is legitimate,
// so the good/ fixture writes one properly and must stay silent.
expect(
  'a definer function granted to anon is critical',
  bad.some((f) => f.rule === 'security-definer-anon-executable' && f.severity === 'critical' && /get_all_quotes/.test(f.detail)),
)
expect(
  'a definer function with SET search_path does not fire',
  !good.some((f) => f.rule === 'security-definer-search-path'),
)
expect(
  'a definer function granted only to authenticated is not called anon-executable',
  !good.some((f) => f.rule === 'security-definer-anon-executable'),
)
expect(
  'a view with security_invoker does not fire',
  !good.some((f) => f.rule === 'security-definer-view'),
)
expect(
  'a view without security_invoker does fire',
  bad.some((f) => f.rule === 'security-definer-view' && /quote_totals/.test(f.detail)),
)

// Grants and duplicate policies (r/Supabase, 2026-08-20). RLS is never touched
// in any of these — that is the whole point of them.
expect(
  'a write grant to anon is critical',
  bad.some((f) => f.rule === 'anon-write-grant' && f.severity === 'critical' && /quotes/.test(f.detail)),
)
expect(
  'GRANT SELECT to anon is not treated as a write grant',
  !good.some((f) => f.rule === 'anon-write-grant'),
)
expect(
  'GRANT ALL to authenticated fires',
  bad.some((f) => f.rule === 'grant-all-on-table' && /invoices/.test(f.detail)),
)
expect(
  'a narrow grant to authenticated does not fire',
  !good.some((f) => f.rule === 'grant-all-on-table'),
)
expect(
  'the anon write grant is not reported twice by the GRANT ALL rule',
  !bad.some((f) => f.rule === 'grant-all-on-table' && /quotes/.test(f.detail)),
)
expect(
  'a USING (true) policy beside a real one is flagged',
  bad.some((f) => f.rule === 'duplicate-permissive-policy' && /temp debug read/.test(f.detail)),
)
expect(
  'two real policies on one table do not fire',
  !good.some((f) => f.rule === 'duplicate-permissive-policy'),
)

// Guidondor's third report and jaimittal91's cheap tripwire (r/Supabase, 2026-08-21).
expect(
  'a policy with no TO clause is flagged',
  bad.some((f) => f.rule === 'policy-missing-to-clause' && /published invoices/.test(f.detail)),
)
expect(
  'TO authenticated silences it',
  !good.some((f) => f.rule === 'policy-missing-to-clause'),
)
expect(
  'a missing TO on an auth.uid() predicate does NOT fire (anon matches no rows)',
  !bad.some((f) => f.rule === 'policy-missing-to-clause' && /own invoices/.test(f.detail)),
)
expect(
  'a policy referencing a column no migration creates is flagged',
  bad.some((f) => f.rule === 'policy-references-missing-column' && /owner_id/.test(f.detail)),
)
expect(
  'a policy referencing a real column does not fire',
  !good.some((f) => f.rule === 'policy-references-missing-column'),
)
expect(
  'a policy on a table this repo never defines is skipped, not reported as all-missing',
  !bad.concat(good).some((f) => f.rule === 'policy-references-missing-column' && /price_list/.test(f.detail)),
)

console.log('')
if (failures) {
  console.log(`  \u001b[31m${failures} failing\u001b[0m\n`)
  process.exit(1)
}
console.log(`  \u001b[32mall good\u001b[0m — ${bad.length} findings in bad/, 0 in good/\n`)
