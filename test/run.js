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

console.log('')
if (failures) {
  console.log(`  \u001b[31m${failures} failing\u001b[0m\n`)
  process.exit(1)
}
console.log(`  \u001b[32mall good\u001b[0m — ${bad.length} findings in bad/, 0 in good/\n`)
