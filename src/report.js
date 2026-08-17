const useColor = process.stdout.isTTY && !process.env.NO_COLOR

const c = (code) => (s) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s)
const bold = c('1')
const dim = c('2')
const red = c('31')
const yellow = c('33')
const green = c('32')
const cyan = c('36')

const BADGE = {
  critical: { icon: '🔴', label: 'CRITICAL', paint: red },
  high: { icon: '🟠', label: 'HIGH', paint: yellow },
  medium: { icon: '🟡', label: 'MEDIUM', paint: yellow },
}

export function printReport(findings, { root, fileCount, strict }) {
  const counts = { critical: 0, high: 0, medium: 0 }
  for (const f of findings) counts[f.severity]++

  console.log('')
  console.log(bold('  ProdGuard') + dim(`  ·  ${fileCount} files scanned  ·  ${root}`))
  console.log('')

  if (!findings.length) {
    console.log(`  ${green('✓')} Nothing dangerous found.`)
    console.log('')
    console.log(dim('  That means none of ProdGuard\'s checks fired — not that the app is perfect.'))
    console.log('')
    return
  }

  // Group by rule so the plain-English explanation is stated once, not per hit.
  const byRule = new Map()
  for (const f of findings) {
    if (!byRule.has(f.rule)) byRule.set(f.rule, [])
    byRule.get(f.rule).push(f)
  }

  for (const [ruleId, hits] of byRule) {
    const { icon, label, paint } = BADGE[hits[0].severity]
    console.log(`  ${icon} ${paint(bold(label))}  ${bold(hits[0].title)}  ${dim(ruleId)}`)
    console.log('')
    for (const line of wrap(hits[0].plain, 76)) console.log(`     ${line}`)
    console.log('')
    for (const hit of hits) {
      console.log(`     ${cyan(`${hit.file}:${hit.line}`)}`)
      if (hit.snippet) console.log(`       ${dim(hit.snippet)}`)
      if (hit.detail) {
        for (const line of wrap(hit.detail, 72)) console.log(`       ${dim('→ ' + line)}`)
      }
    }
    console.log('')
  }

  const parts = []
  if (counts.critical) parts.push(red(`${counts.critical} critical`))
  if (counts.high) parts.push(yellow(`${counts.high} high`))
  if (counts.medium) parts.push(yellow(`${counts.medium} medium`))
  console.log(`  ${bold('Result:')} ${parts.join(dim(' · '))}`)

  const failing = counts.critical > 0 || (strict && counts.high > 0)
  if (failing) {
    console.log('')
    console.log(`  ${red('✗')} Blocking. Fix these before shipping, or add an allow entry to ${bold('.prodguardrc.json')}.`)
  }
  console.log('')
}

export function printJson(findings, meta) {
  const counts = { critical: 0, high: 0, medium: 0 }
  for (const f of findings) counts[f.severity]++
  console.log(JSON.stringify({ ...meta, counts, findings }, null, 2))
}

function wrap(text, width) {
  const words = String(text).split(/\s+/)
  const lines = []
  let line = ''
  for (const word of words) {
    if ((line + ' ' + word).trim().length > width) {
      if (line) lines.push(line.trim())
      line = word
    } else {
      line += ' ' + word
    }
  }
  if (line.trim()) lines.push(line.trim())
  return lines
}
