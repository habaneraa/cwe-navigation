/** Download the current CWE catalog and generate the frontend data files. */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { unzipSync } from 'fflate'

import { CweGraphData } from './catalog.js'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const dataDir = dirname(scriptDir)
const repoRoot = dirname(dataDir)
const cacheDir = join(dataDir, 'cache')
const cacheXmlPath = join(cacheDir, 'cwec_latest.xml')
const outputDir = join(repoRoot, 'public')

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
  if (process.argv.includes('--download') || !existsSync(cacheXmlPath)) {
    await downloadCwe()
  }
  const xmlText = loadCweXml()

  mkdirSync(outputDir, { recursive: true })
  const catalog = new CweGraphData(xmlText)
  catalog.printSummary()

  writeFileSync(join(outputDir, 'cwe_metadata.json'), JSON.stringify(catalog.cweInfo))
  writeFileSync(
    join(outputDir, 'catalog_info.json'),
    JSON.stringify({
      cwe_version: catalog.rootDict['@Version'],
      updated_at: catalog.rootDict['@Date'],
      view_id: '1000'
    })
  )

  const graphData = catalog.generateGraphData()
  writeFileSync(join(outputDir, 'graph_data.json'), JSON.stringify(graphData))
  console.log(`Generated frontend data in ${outputDir}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
