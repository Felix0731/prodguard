#!/usr/bin/env node
import { resolve, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import { collectFiles, loadConfig, isAllowed } from '../src/scan.js'
import { runRules, allRules } from '../src/rules.js'
import { printReport, printJson } from '../src/report.js'
import { init } from '../src/init.js'
import { demoFiles } from '../src/demo.js'

const here = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'))

const argv = process.argv.slice(2)
const flags = new Set(argv.filter((a) => a.startsWith('-')))
const positional = argv.filter((a) => !a.startsWith('-'))
const command = positional[0] || 'check'

if (flags.has('--version') || flags.has('-v')) {
  console.log(pkg.version)
  process.exit(0)
}

if (flags.has('--help') || flags.has('-h') || command === 'help') {
  usage()
  process.exit(0)
}

const root = resolve(positional[1] || process.cwd())

if (command === 'init') {
  init(root)
  process.exit(0)
}

if (command === 'rules') {
  console.log('')
  for (const r of allRules) {
    console.log(`  ${r.severity.padEnd(8)} ${r.id}`)
    console.log(`           ${r.title}`)
  }
  console.log('')
  process.exit(0)
}

if (command !== 'check') {
  console.error(`prodguard: unknown command "${command}"`)
  usage()
  process.exit(2)
}

// Silently ignoring a flag is how a stale install ends up printing a cheerful
// "nothing found" for a command the user thinks they ran.
const KNOWN_FLAGS = new Set(['--demo', '--strict', '--json', '--help', '-h', '--version', '-v'])
const unknown = [...flags].filter((f) => !KNOWN_FLAGS.has(f))
if (unknown.length) {
  console.error(`\n  prodguard: unrecognised option ${unknown.join(', ')}`)
  console.error(`  This version is v${pkg.version}. If you expected it to work, try: npx prodguard@latest\n`)
  process.exit(2)
}

const config = loadConfig(root)
const strict = flags.has('--strict') || config.strict === true

// `--demo` runs every rule against a small in-memory app so a stranger can see
// exactly what the tool does without pointing it at their own codebase.
if (flags.has('--demo')) {
  const findings = runRules(demoFiles())
  if (flags.has('--json')) printJson(findings, { root: 'demo', fileCount: demoFiles().length, strict })
  else {
    console.log('')
    console.log('  Running against a deliberately broken example app — your files are untouched.')
    printReport(findings, { root: 'demo app', fileCount: demoFiles().length, strict })
    console.log('  Point it at something real with:  npx prodguard check .')
    console.log('')
  }
  process.exit(0)
}

const files = collectFiles(root)
const findings = runRules(files).filter((f) => !isAllowed(f, config.allow))

if (flags.has('--json')) {
  printJson(findings, { root, fileCount: files.length, strict })
} else {
  printReport(findings, { root, fileCount: files.length, strict })
}

const critical = findings.filter((f) => f.severity === 'critical').length
const high = findings.filter((f) => f.severity === 'high').length
process.exit(critical > 0 || (strict && high > 0) ? 1 : 0)

function usage() {
  console.log(`
  prodguard v${pkg.version}
  Stops AI coding agents from disabling your paywall, your auth, and your database security.

  Usage
    npx prodguard check [path]     Scan a repo (default: current directory)
    npx prodguard init [path]      Add config + a GitHub Action that blocks bad merges
    npx prodguard check --demo     See every check fire on a broken example app
    npx prodguard rules            List every check

  Options
    --strict     Also fail on HIGH findings, not just CRITICAL
    --json       Machine-readable output
    --version    Print version

  Exit codes
    0  nothing blocking
    1  at least one CRITICAL (or HIGH with --strict)
`)
}
