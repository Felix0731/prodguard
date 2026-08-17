import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '.nuxt', 'out',
  'coverage', '.vercel', '.turbo', '.cache', 'vendor', '.venv', '__pycache__',
  // Fixture and mock trees exist to hold deliberately broken code. Scanning
  // them produces findings nobody can act on — including in this repo.
  'fixtures', '__fixtures__', '__mocks__', '__snapshots__',
])

const TEXT_EXT = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts',
  '.sql', '.pgsql', '.psql', '.json', '.toml', '.yml', '.yaml', '.svelte', '.vue', '.astro',
  // Plain-text formats: people paste credential exports into these.
  '.txt', '.text', '.csv', '.md',
  // Firebase security rules
  '.rules',
])

// A file is worth reading if it has a known code extension, or it's a dotenv
// file — those carry the secrets we most care about leaking.
function isInteresting(name) {
  if (name.startsWith('.env')) return true
  const dot = name.lastIndexOf('.')
  return dot !== -1 && TEXT_EXT.has(name.slice(dot))
}

const MAX_BYTES = 512 * 1024

/**
 * Walk a repository and return every readable source file as
 * { path, rel, text, lines }. Binary and generated trees are skipped.
 */
export function collectFiles(root) {
  const out = []

  function walk(dir) {
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue
        walk(full)
        continue
      }
      if (!entry.isFile()) continue
      if (!isInteresting(entry.name)) continue
      let stat
      try {
        stat = statSync(full)
      } catch {
        continue
      }
      if (stat.size > MAX_BYTES) continue
      let text
      try {
        text = readFileSync(full, 'utf8')
      } catch {
        continue
      }
      if (text.includes('\u0000')) continue // binary file wearing a text extension
      const rel = relative(root, full).split(sep).join('/')
      out.push({
        path: full,
        rel,
        text,
        get lines() {
          // Built on demand; eagerly duplicating every file doubled memory.
          if (!this._lines) this._lines = this.text.split('\n')
          return this._lines
        },
        // Prose files quote broken code on purpose — a README showing
        // `const locked = false` as an example is documentation, not a bug.
        // Only the rules that hunt for literal secrets should read them.
        isDoc: /\.(md|txt|text|csv)$/i.test(rel),
      })
    }
  }

  walk(root)
  return out
}

/**
 * Line number (1-indexed) of a character offset. Counting newlines from zero on
 * every match is O(size x matches) — 14 seconds on one large file — so the
 * offsets are indexed once and binary-searched thereafter.
 */
export function lineOf(file, index) {
  if (!file._nl) {
    const nl = []
    for (let i = 0; i < file.text.length; i++) if (file.text.charCodeAt(i) === 10) nl.push(i)
    file._nl = nl
  }
  const nl = file._nl
  let lo = 0
  let hi = nl.length
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (nl[mid] < index) lo = mid + 1
    else hi = mid
  }
  return lo + 1
}

/**
 * Anything that looks like a credential is masked before it can reach a
 * terminal or a CI log. This runs on EVERY snippet from EVERY rule — relying on
 * individual rules to remember is how a scanner ends up printing the key it was
 * hired to protect.
 */
const SECRET_SHAPES = [
  /\b(sk_live_|rk_live_|sk_test_|whsec_|sk-ant-api|sk-proj-|xox[abpsr]-)[A-Za-z0-9_-]{8,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  /:\/\/[^:@/\s]+:[^@/\s]{3,}@/g,
  /\b([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD))\s*[=:]\s*["']?([^\s"';,]{12,})/g,
]

export function redactSecrets(line) {
  let out = String(line)
  out = out.replace(SECRET_SHAPES[5], (m, k) => `${k}=…redacted…`)
  for (const re of SECRET_SHAPES.slice(0, 5)) {
    out = out.replace(re, (m) => m.slice(0, 8) + '…redacted…')
  }
  return out
}

/**
 * Run every regex match in a file, yielding { line, snippet } for each hit.
 * Regexes are cloned so a shared /g lastIndex never leaks between files.
 */
export function* matches(file, regex) {
  const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g')
  let m
  while ((m = re.exec(file.text)) !== null) {
    const line = lineOf(file, m.index)
    yield {
      line,
      snippet: (file.lines[line - 1] || '').trim().slice(0, 160),
      match: m,
    }
    if (m.index === re.lastIndex) re.lastIndex++
  }
}

export function loadConfig(root) {
  const defaults = { allow: [], strict: false }
  const path = join(root, '.prodguardrc.json')
  if (!existsSync(path)) return defaults
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'))
    const merged = { ...defaults, ...parsed }
    if (!Array.isArray(merged.allow)) {
      if (merged.allow != null) {
        console.error('prodguard: "allow" in .prodguardrc.json must be an array — ignoring it')
      }
      merged.allow = []
    }
    return merged
  } catch (err) {
    console.error(`prodguard: could not parse .prodguardrc.json — ${err.message}`)
    return defaults
  }
}

/**
 * An allow entry is "ruleId" (mute everywhere) or "ruleId:path/fragment"
 * (mute only in matching files). Findings are matched against both forms.
 */
export function isAllowed(finding, allow) {
  return allow.some((entry) => {
    const [rule, pathPart] = String(entry).split(':')
    if (rule !== finding.rule) return false
    if (!pathPart) return true
    return finding.file.includes(pathPart)
  })
}
