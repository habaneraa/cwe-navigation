import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { GraphChartData } from '../src/cwe_catalog.js'

/**
 * Golden regression tests on the small fixture catalog.
 *
 * fixture/expected/ is a frozen baseline (regenerate deliberately with
 * `npm run gen:fixture -w data_scripts/nodejs` when an output change is
 * intended). The suite pins the pipeline's behavior against that baseline
 * so refactors cannot silently change the exported data.
 */

const fixtureXmlPath = fileURLToPath(new URL('../../fixture/mini_cwe.xml', import.meta.url))
const expectedDir = fileURLToPath(new URL('../../fixture/expected/', import.meta.url))

const fixtureXml = readFileSync(fixtureXmlPath, 'utf-8')
const expectedMetadata = readFileSync(expectedDir + 'cwe_metadata.json', 'utf-8')
const expectedGraph = readFileSync(expectedDir + 'graph_data.json', 'utf-8')

const catalog = new GraphChartData(fixtureXml)
const graphs = catalog.generateGraphData()

/**
 * "Popular Weaknesses" node order is one deterministic choice among the
 * orders the original implementation could emit (python set() iteration
 * was nondeterministic there). Compare that one array canonically;
 * everything else must match exactly.
 */
function canonicalize(json: unknown): Record<string, { nodes: { name: string }[] }> {
  const copy = JSON.parse(JSON.stringify(json)) as Record<string, { nodes: { name: string }[] }>
  for (const [key, value] of Object.entries(copy)) {
    if (key === 'Popular Weaknesses') {
      value.nodes.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    }
  }
  return copy
}

describe('fixture golden baseline', () => {
  it('metadata json is byte-identical to the frozen baseline', () => {
    expect(JSON.stringify(catalog.cweInfo)).toBe(expectedMetadata)
  })

  it('metadata parses to the same structure', () => {
    expect(JSON.parse(JSON.stringify(catalog.cweInfo))).toEqual(JSON.parse(expectedMetadata))
  })

  it('graph data matches the baseline (popular nodes compared canonically)', () => {
    expect(canonicalize(graphs)).toEqual(canonicalize(JSON.parse(expectedGraph)))
    // byte-identical after canonicalization also pins key order
    expect(JSON.stringify(canonicalize(graphs))).toBe(
      JSON.stringify(canonicalize(JSON.parse(expectedGraph))),
    )
  })

  it('mixed-content description reproduces the xmltodict shape', () => {
    const cwe801 = catalog.cweInfo['CWE-801']
    expect(cwe801.description).toEqual({
      'xhtml:p': [
        'First paragraph.',
        { 'xhtml:b': 'bold', '#text': 'Second paragraph with  inline.' },
      ],
    })
  })

  it('entity decoding matches the baseline', () => {
    expect(catalog.cweInfo['CWE-700'].description).toBe(
      'Pillar description with & entity and é accent.',
    )
  })

  it('exports detail badges and mapping guidance metadata', () => {
    const cwe787 = catalog.cweInfo['CWE-787']
    expect(cwe787.status).toBe('Usen')
    expect(cwe787.structure).toBe('Simple')
    expect(cwe787.mapping_rationale).toBe(
      'Use this entry when the buffer write exceeds its intended bounds.',
    )
    expect(cwe787.mapping_comments).toBe(
      'Prefer a more specific child weakness when the root cause is known.',
    )
    expect(cwe787.mapping_reasons).toEqual(['Acceptable-Use'])
    expect(catalog.cweInfo['CWE-1001'].status).toBe('Usen')
  })

  it('filters relationships per the view id / ordinal / nature rules', () => {
    // CWE-807: ChildOf without View_ID -> kept in metadata, excluded from tree+graph
    expect(catalog.cweInfo['CWE-807'].related_weaknesses).toEqual([
      { ID: '807', Nature: 'ChildOf', CWE_ID: '804' },
    ])
    const allNodes = graphs['All Weaknesses (could be very laggy)'].nodes.map((n) => n.name)
    expect(allNodes).not.toContain('CWE-807')
    expect(allNodes).not.toContain('CWE-805') // missing Ordinal
    expect(allNodes).toContain('CWE-806') // CanPrecede target, in tree
  })

  it('tree depth drives symbolSize and the pillar root gets 30', () => {
    const tree = graphs['Tree of CWE-700: Pillar P']
    const byName = Object.fromEntries(tree.nodes.map((n) => [n.name, n]))
    expect(byName['CWE-700'].symbolSize).toBe(30) // root
    expect(byName['CWE-787'].symbolSize).toBe(13) // depth 1 under the pillar
    expect(byName['CWE-802'].symbolSize).toBe(11) // depth 2
  })

  it('top CWE id gets the purple border style', () => {
    const tree = graphs['Tree of CWE-700: Pillar P']
    const byName = Object.fromEntries(tree.nodes.map((n) => [n.name, n]))
    expect(byName['CWE-787'].itemStyle).toEqual({
      borderWidth: 2,
      borderColor: '#9B30FF',
      opacity: 1,
    })
    expect(byName['CWE-802'].itemStyle).toEqual({ borderWidth: 0, opacity: 1 })
  })

  it('non-ParentOf edges become dashed and force-layout-ignored', () => {
    const all = graphs['All Weaknesses (could be very laggy)']
    const canPrecede = all.links.find((l) => l.value === 'CanPrecede')
    expect(canPrecede).toEqual({
      source: 'CWE-801',
      target: 'CWE-806',
      value: 'CanPrecede',
      ignoreForceLayout: true,
      lineStyle: { type: 'dashed' },
      symbol: ['none', 'arrow'],
      symbolSize: 5,
    })

    const tree = graphs['Tree of CWE-700: Pillar P']
    expect(tree.links.some((link) => link.value === 'CanPrecede')).toBe(true)
  })

  it('metadata keeps xml document order across weaknesses/categories/views', () => {
    expect(Object.keys(catalog.cweInfo)).toEqual([
      'CWE-700',
      'CWE-787',
      'CWE-801',
      'CWE-802',
      'CWE-803',
      'CWE-804',
      'CWE-805',
      'CWE-807',
      'CWE-806',
      'CWE-1001',
      'CWE-1002',
      'CWE-1000',
      'CWE-1400',
    ])
  })
})
