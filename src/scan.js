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
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.sql', '.json', '.toml', '.yml', '.yaml', '.svelte', '.vue', '.astro',
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
      out.push({
        path: full,
        rel: relative(root, full).split(sep).join('/'),
        text,
        lines: text.split('\n'),
      })
    }
  }

  walk(root)
  return out
}

/** Line number (1-indexed) of a character offset within a file. */
export function lineOf(file, index) {
  let line = 1
  for (let i = 0; i < index && i < file.text.length; i++) {
    if (file.text.charCodeAt(i) === 10) line++
  }
  return line
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
  const path = join(root, '.shipguardrc.json')
  if (!existsSync(path)) return defaults
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'))
    return { ...defaults, ...parsed }
  } catch (err) {
    console.error(`shipguard: could not parse .shipguardrc.json — ${err.message}`)
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
