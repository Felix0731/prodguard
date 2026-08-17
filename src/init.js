import { writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const CONFIG = `{
  "strict": false,
  "allow": []
}
`

const WORKFLOW = `name: ShipGuard

# Runs on every pull request, including the ones your AI agent opens.
on:
  pull_request:
  push:
    branches: [main, master]

jobs:
  shipguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Check for dangerous changes
        run: npx --yes shipguard check
`

export function init(root) {
  const configPath = join(root, '.shipguardrc.json')
  const workflowDir = join(root, '.github', 'workflows')
  const workflowPath = join(workflowDir, 'shipguard.yml')

  let wrote = 0

  if (existsSync(configPath)) {
    console.log(`  · .shipguardrc.json already exists, leaving it alone`)
  } else {
    writeFileSync(configPath, CONFIG)
    console.log(`  ✓ wrote .shipguardrc.json`)
    wrote++
  }

  if (existsSync(workflowPath)) {
    console.log(`  · .github/workflows/shipguard.yml already exists, leaving it alone`)
  } else {
    mkdirSync(workflowDir, { recursive: true })
    writeFileSync(workflowPath, WORKFLOW)
    console.log(`  ✓ wrote .github/workflows/shipguard.yml`)
    wrote++
  }

  console.log('')
  if (wrote) {
    console.log(`  Commit those two files and every future pull request gets checked.`)
  }
  console.log(`  Run a scan right now with:  npx shipguard check`)
  console.log('')
}
