/**
 * Regenerate fixture/expected/ golden baselines from the current pipeline.
 *
 * Run deliberately when an output change is intended:
 *   npm run gen:fixture -w data_scripts/nodejs
 * The test suite (nodejs/test/fixture.test.ts) compares against these
 * files byte-for-byte, so a diff here should always be reviewed.
 */

import { writeFileSync, mkdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { GraphChartData } from '../nodejs/src/cwe_catalog.js'

const fixtureDir = dirname(fileURLToPath(import.meta.url))
const outDir = join(fixtureDir, 'expected')
mkdirSync(outDir, { recursive: true })

const fixtureXml = readFileSync(join(fixtureDir, 'mini_cwe.xml'), 'utf-8')
const catalog = new GraphChartData(fixtureXml)
const graphs = catalog.generateGraphData()

writeFileSync(join(outDir, 'cwe_metadata.json'), JSON.stringify(catalog.cweInfo))
writeFileSync(join(outDir, 'graph_data.json'), JSON.stringify(graphs))
console.log(`Fixture baseline written to ${outDir}`)
