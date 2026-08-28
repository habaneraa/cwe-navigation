/**
 * CWE data pipeline: downloads cwec_latest.xml.zip into data_scripts/cache/
 * (auto-downloads when the cache is missing, --download forces a refresh),
 * then writes:
 *   - <repo>/public/cwe_metadata.json
 *   - <repo>/public/graph_data.json
 * which is what the frontend fetches, so `npm run build` always ships
 * fresh data. `--out <dir>` writes to that directory instead and adds a
 * node_manifest.json with input provenance (e.g. for debugging diffs).
 *
 * Output is compact JSON (JSON.stringify) with insertion key order, so
 * regenerations diff cleanly: only real data changes show up. During the
 * python->nodejs migration (CWE 4.20) the pipeline was verified
 * byte-identical against the python implementation; python has since been
 * retired and the JSON is written in plain JS formatting.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'
import { unzipSync } from 'fflate'
import { createHash } from 'node:crypto'

import { GraphChartData } from './cwe_catalog.js'
import type { XmlDict } from './xmltodict.js'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = dirname(scriptDir) // data_scripts/nodejs/
const dataScriptsDir = join(packageDir, '..')
const repoRoot = dirname(dataScriptsDir)
const cacheDir = join(dataScriptsDir, 'cache')
const cacheXmlPath = join(cacheDir, 'cwec_latest.xml')
const defaultOutputDir = join(repoRoot, 'public')

const CWE_DATA_URL = 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip'

async function downloadCwe(): Promise<void> {
  mkdirSync(cacheDir, { recursive: true })
  console.log(`Downloading and extracting from: ${CWE_DATA_URL}`)
  const response = await fetch(CWE_DATA_URL)
  if (!response.ok) {
    throw new Error(`download failed: ${response.status} ${response.statusText}`)
  }
  const zipBytes = new Uint8Array(await response.arrayBuffer())
  const entries = unzipSync(zipBytes)
  const firstEntryName = Object.keys(entries)[0]
  const xmlText = Buffer.from(entries[firstEntryName]).toString('utf-8')
  writeFileSync(cacheXmlPath, xmlText)
  console.log(`CWE catalog XML has been saved to ${cacheXmlPath}`)
}

function loadCweXml(): string {
  if (!existsSync(cacheXmlPath)) {
    throw new Error(`cached xml missing at ${cacheXmlPath}; download failed?`)
  }
  console.log(`Loaded CWE catalog data from ${cacheXmlPath}`)
  return readFileSync(cacheXmlPath, 'utf-8')
}

async function main(): Promise<void> {
  // comparison mode: `--out <dir>` redirects output and adds a provenance manifest
  const outFlag = process.argv.indexOf('--out')
  const outputDir = outFlag >= 0 ? resolve(process.argv[outFlag + 1]) : defaultOutputDir
  const comparisonMode = outFlag >= 0

  // download when missing so a fresh checkout can build right away;
  // --download forces a refresh even when the cache exists
  if (process.argv.includes('--download') || !existsSync(cacheXmlPath)) {
    await downloadCwe()
  }
  const xmlText = loadCweXml()

  mkdirSync(outputDir, { recursive: true })
  const catalog = new GraphChartData(xmlText)
  catalog.showCweBasicInfo()

  // order mirrors the original python main(): metadata first, then graph data
  writeFileSync(join(outputDir, 'cwe_metadata.json'), JSON.stringify(catalog.cweInfo))
  writeFileSync(
    join(outputDir, 'catalog_info.json'),
    JSON.stringify({
      cwe_version: catalog.rootDict['@Version'],
      updated_at: catalog.rootDict['@Date'],
      view_id: '1000',
    }),
  )

  const graphData = catalog.generateGraphData()
  writeFileSync(join(outputDir, 'graph_data.json'), JSON.stringify(graphData))

  if (comparisonMode) {
    const version = catalog.rootDict['@Version']
    const date = catalog.rootDict['@Date']
    const manifest = {
      generator: 'nodejs data pipeline (data_scripts/nodejs)',
      entry: 'src/generate.ts',
      cwe_version: version,
      cwe_date: date,
      source_xml_sha256: createHash('sha256').update(xmlText).digest('hex'),
    }
    writeFileSync(join(outputDir, 'node_manifest.json'), JSON.stringify(manifest, null, 2))
  }
  console.log(`Nodejs output written to ${outputDir}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
