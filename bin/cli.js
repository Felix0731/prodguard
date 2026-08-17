#!/usr/bin/env node
import { resolve, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import { collectFiles, loadConfig, isAllowed } from '../src/scan.js'
import { runRules, allRules } from '../src/rules.js'
import { printReport, printJson } from '../src/report.js'
import { init } from '../src/init.js'

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
  console.error(`shipguard: unknown command "${command}"`)
  usage()
  process.exit(2)
}

const config = loadConfig(root)
const strict = flags.has('--strict') || config.strict === true

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
  shipguard v${pkg.version}
  Stops AI coding agents from disabling your paywall, your auth, and your database security.

  Usage
    npx shipguard check [path]     Scan a repo (default: current directory)
    npx shipguard init [path]      Add config + a GitHub Action that blocks bad merges
    npx shipguard rules            List every check

  Options
    --strict     Also fail on HIGH findings, not just CRITICAL
    --json       Machine-readable output
    --version    Print version

  Exit codes
    0  nothing blocking
    1  at least one CRITICAL (or HIGH with --strict)
`)
}
