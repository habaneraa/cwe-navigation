/** Regenerate the expected fixture output after an intentional data format change. */

import { writeFileSync, mkdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { CweGraphData } from '../src/catalog.js'

const fixtureDir = dirname(fileURLToPath(import.meta.url))
const outDir = join(fixtureDir, 'expected')
mkdirSync(outDir, { recursive: true })

const fixtureXml = readFileSync(join(fixtureDir, 'mini_cwe.xml'), 'utf-8')
const catalog = new CweGraphData(fixtureXml)
const graphs = catalog.generateGraphData()

writeFileSync(join(outDir, 'cwe_metadata.json'), JSON.stringify(catalog.cweInfo))
writeFileSync(join(outDir, 'graph_data.json'), JSON.stringify(graphs))
console.log(`Fixture baseline written to ${outDir}`)
