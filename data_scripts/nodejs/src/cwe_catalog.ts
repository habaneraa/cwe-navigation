/**
 * CWE catalog data model, originally ported 1:1 from the python
 * implementation (cwe_catalog.py, retired after the migration was
 * verified). Iteration order and JSON key order are significant: the
 * exported JSON has a byte-stable format inherited from that port.
 * Comments still mark the original python constructs where they explain
 * quirky behavior.
 */

import { DiGraph, type EdgeTuple } from './digraph.js'
import { xmltodictParse, type XmlDict, type XmlValue } from './xmltodict.js'

type Dict = Record<string, unknown>

interface CweEntry extends Dict {
  cwe_entry_type: 'weakness' | 'category' | 'view'
  name: string
  description: XmlValue
  vulnerability_mapping: string
  abstraction?: string
  related_weaknesses?: RelatedWeakness[]
  members?: RelatedWeakness[]
}

interface RelatedWeakness {
  [key: string]: string // ID / Nature / CWE_ID / View_ID / Ordinal (attribute order preserved)
}

interface RelatedWeaknessRaw {
  [key: string]: string
}

function asList<T>(v: T | T[] | undefined | null): T[] {
  // python idiom: `x if isinstance(x, list) else [x,]`
  if (v === undefined || v === null) return []
  return Array.isArray(v) ? v : [v]
}

/**
 * Extract the inner element list from a wrapper element, mirroring python:
 *   rw = weakness['Related_Weaknesses']['Related_Weakness']
 *   rw = rw if isinstance(rw, list) else [rw,]
 * (missing wrapper -> [], like python's `weakness.get(...)` + falsy check)
 */
function wrappedList(container: unknown, innerKey: string): RelatedWeakness[] {
  if (container === undefined || container === null) return []
  const inner = (container as XmlDict)[innerKey]
  if (inner === undefined || inner === null) return []
  const list = asList(inner as RelatedWeaknessRaw | RelatedWeaknessRaw[])
  return list.map((r) => {
    const stripped: RelatedWeakness = {}
    for (const [k, v] of Object.entries(r)) {
      stripped[k.slice(1)] = String(v) // python: {k[1:]: v for k, v in r.items()}
    }
    return stripped
  })
}

/** Extract the inner element list from a wrapper element (`<Weaknesses><Weakness/>...`). */
function wrappedDictList(container: unknown, innerKey: string): XmlDict[] {
  if (container === undefined || container === null || typeof container !== 'object') return []
  const inner = (container as XmlDict)[innerKey]
  if (inner === undefined || inner === null) return []
  return (Array.isArray(inner) ? inner : [inner]) as XmlDict[]
}

export class CweCatalog {
  static readonly viewIdUsedForNavigation = '1000'

  // python: self._root_dict / self._cwe_info (private by convention only)
  readonly rootDict: XmlDict
  readonly cweInfo: Record<string, CweEntry>

  // tree structure, based on CWE-1000 Research Concepts
  readonly tree: DiGraph
  // Each node has exactly one parent node, so we use a map for this relationship.
  readonly parentMap: Map<string, string>
  readonly graph: DiGraph

  constructor(cweXmlText: string) {
    const parsed = xmltodictParse(cweXmlText)
    this.rootDict = parsed['Weakness_Catalog'] as XmlDict
    this.cweInfo = this.getSimplifiedCweEntryInfo()

    this.tree = this.buildTreeOf(CweCatalog.viewIdUsedForNavigation)
    if (!this.tree.isArborescence()) {
      // python: assert nx.is_arborescence(digraph), '? unexpected tree view ?!'
      throw new Error('? unexpected tree view ?!')
    }
    this.parentMap = new Map()
    for (const [u, v] of this.tree.edges()) {
      this.parentMap.set(v, u)
    }
    this.graph = this.buildGraph(CweCatalog.viewIdUsedForNavigation)
  }

  get(index: string | number): CweEntry {
    let cweId: string
    if (typeof index === 'string') {
      if (index.startsWith('CWE-')) {
        cweId = index
      } else if (/^\d+$/.test(index)) {
        cweId = `CWE-${index}`
      } else {
        cweId = ''
      }
    } else {
      cweId = 'CWE-' + index
    }
    const entry = this.cweInfo[cweId]
    if (entry === undefined) {
      throw new Error(`CWE ID not found: ${index}`)
    }
    return entry
  }

  get weaknesses(): XmlDict[] {
    return wrappedDictList(this.rootDict['Weaknesses'], 'Weakness')
  }

  get categories(): XmlDict[] {
    return wrappedDictList(this.rootDict['Categories'], 'Category')
  }

  get views(): XmlDict[] {
    return wrappedDictList(this.rootDict['Views'], 'View')
  }

  get allCweIds(): string[] {
    return Object.keys(this.cweInfo)
  }

  showCweBasicInfo(): void {
    const catalog = this.rootDict as Record<string, unknown>
    const cweVersion = catalog['@Version'] as string
    const cweDate = catalog['@Date'] as string
    // (typo "Commmon" kept intentionally, inherited from the original pipeline output)
    console.log(`Commmon Weakness Enumeration Catalog (${cweVersion} ${cweDate})`)
    console.log(`Number of weaknesses: ${this.weaknesses.length}`)
    console.log(`Number of categories: ${this.categories.length}`)
    console.log(`Number of views: ${this.views.length}`)
    console.log(`Total entries: ${this.allCweIds.length}`)
  }

  /** python: get_simplified_cwe_entry_info */
  protected getSimplifiedCweEntryInfo(): Record<string, CweEntry> {
    const cweMetadata: Record<string, CweEntry> = {}

    for (const weakness of this.weaknesses) {
      const weaknessId = 'CWE-' + (weakness['@ID'] as string)
      const weaknessName = weakness['@Name'] as string
      const abstraction = weakness['@Abstraction'] as string
      const description = weakness['Description'] as XmlValue
      const vulnerabilityMapping = (weakness['Mapping_Notes'] as XmlDict)['Usage'] as string
      const relatedWeaknesses = wrappedList(weakness['Related_Weaknesses'], 'Related_Weakness')

      cweMetadata[weaknessId] = {
        cwe_entry_type: 'weakness',
        name: weaknessName,
        abstraction,
        description,
        vulnerability_mapping: vulnerabilityMapping,
        related_weaknesses: relatedWeaknesses,
      }
    }

    for (const category of this.categories) {
      const categoryId = 'CWE-' + (category['@ID'] as string)
      const categoryName = category['@Name'] as string
      const categorySummary = category['Summary'] as XmlValue
      const members = wrappedList(category['Relationships'], 'Has_Member')

      cweMetadata[categoryId] = {
        cwe_entry_type: 'category',
        name: categoryName,
        description: categorySummary,
        vulnerability_mapping: 'Prohibited',
        members,
      }
    }

    for (const view of this.views) {
      const viewId = 'CWE-' + (view['@ID'] as string)
      const viewName = view['@Name'] as string
      const viewDescription = view['Objective'] as XmlValue
      const members = wrappedList(view['Members'], 'Has_Member')

      cweMetadata[viewId] = {
        cwe_entry_type: 'view',
        name: viewName,
        description: viewDescription,
        vulnerability_mapping: 'Prohibited',
        members,
      }
    }

    return cweMetadata
  }

  /** python: _build_tree_of */
  protected buildTreeOf(viewId: string = '1000'): DiGraph {
    const digraph = new DiGraph()
    for (const cweId of this.allCweIds) {
      const rws = this.get(cweId).related_weaknesses
      if (rws) {
        for (const rwDict of rws) {
          if (
            rwDict['Nature'] === 'ChildOf' &&
            rwDict['View_ID'] === viewId &&
            rwDict['Ordinal'] === 'Primary'
          ) {
            digraph.addEdge('CWE-' + rwDict['CWE_ID'], cweId)
          }
        }
      }
    }
    for (const member of this.get(viewId).members ?? []) {
      digraph.addEdge('CWE-' + viewId, 'CWE-' + member['CWE_ID'])
    }
    return digraph
  }

  /** python: _build_graph — heterogeneous graph of CWE entries */
  protected buildGraph(viewId: string = '1000'): DiGraph {
    const digraph = new DiGraph()

    // we want parent ---> child, so that: (parent) ---ParentOf--> (child)
    const relationshipToEdge = (w: string, rw: RelatedWeakness): void => {
      if (rw['Nature'] === 'ChildOf') {
        digraph.addEdge('CWE-' + rw['CWE_ID'], w, {
          nature: 'ParentOf',
          ordinal: rw['Ordinal'] ?? '',
        })
      } else {
        digraph.addEdge(w, 'CWE-' + rw['CWE_ID'], {
          nature: rw['Nature'],
          ordinal: rw['Ordinal'] ?? '',
        })
      }
    }

    for (const cweId of this.allCweIds) {
      const rws = this.get(cweId).related_weaknesses
      if (rws) {
        for (const rwDict of rws) {
          if (
            rwDict['View_ID'] === viewId &&
            (rwDict['Nature'] !== 'ChildOf' || rwDict['Ordinal'] === 'Primary')
          ) {
            relationshipToEdge(cweId, rwDict)
          }
        }
      }
    }

    for (const member of this.get(viewId).members ?? []) {
      digraph.addEdge('CWE-' + viewId, 'CWE-' + member['CWE_ID'], { nature: 'HasMember' })
    }
    return digraph
  }

  /** python: find_path_on_tree — returns null when descendant is not under ancestor */
  findPathOnTree(ancestor: string, descendant: string): string[] | null {
    const path = [descendant]
    let currentNode = descendant
    while (currentNode !== ancestor) {
      if (currentNode === 'CWE-1000') {
        // reaches root node, fail
        return null
      }
      currentNode = this.parentMap.get(currentNode) as string // python: KeyError possible
      path.push(currentNode)
    }
    path.reverse()
    return path
  }

  getPillarWeaknessAncestor(node: string): string | null {
    const pathFromRoot = this.findPathOnTree('CWE-1000', node)
    if (pathFromRoot && pathFromRoot.length > 1) {
      if (this.get(pathFromRoot[1]).abstraction !== 'Pillar') {
        // python: assert self[path[1]]['abstraction'] == 'Pillar'
        throw new Error(`AssertionError: ${pathFromRoot[1]} is not a Pillar`)
      }
      return pathFromRoot[1]
    }
    return null
  }
}

export class GraphChartData extends CweCatalog {
  static readonly abstractions = ['Compound', 'Pillar', 'Class', 'Base', 'Variant']

  // hard-coded for now (kept in sync with cwe_catalog.py)
  static readonly topCweIds = new Set([
    'CWE-125', 'CWE-119', 'CWE-787', 'CWE-476', 'CWE-Other', 'CWE-416', 'CWE-20', 'CWE-190',
    'CWE-200', 'CWE-399', 'CWE-120', 'CWE-401', 'CWE-264', 'CWE-362', 'CWE-189', 'CWE-772',
    'CWE-835', 'CWE-617', 'CWE-369', 'CWE-415', 'CWE-400', 'CWE-122', 'CWE-770', 'CWE-22',
    'CWE-908', 'CWE-284', 'CWE-674', 'CWE-254', 'CWE-295', 'CWE-59', 'CWE-193', 'CWE-287',
    'CWE-269', 'CWE-834', 'CWE-667', 'CWE-310', 'CWE-17', 'CWE-754', 'CWE-843', 'CWE-755',
    'CWE-909', 'CWE-404', 'CWE-665', 'CWE-191', 'CWE-79', 'CWE-252', 'CWE-78', 'CWE-681',
    'CWE-89', 'CWE-704',
  ])

  private get topCweIds(): Set<string> {
    return GraphChartData.topCweIds
  }

  /** python: export_data */
  exportData(nodes: string[], edges: EdgeTuple[], rootNode: string): GraphExport {
    const exportNodes: GraphNode[] = []
    const exportLinks: GraphLink[] = []
    const validNodeSet = new Set(nodes)
    for (const cweNode of nodes) {
      const path = this.findPathOnTree(rootNode, cweNode)
      const depth = path ? path.length - 1 : 1
      const category = this.get(cweNode).abstraction ?? 'Pillar'
      const style: Record<string, number | string> = {
        borderWidth: 0,
      }
      if (this.topCweIds.has(cweNode)) {
        style['borderColor'] = '#9B30FF'
        style['borderWidth'] = 2
        style['opacity'] = 1
      } else {
        style['opacity'] = 1
      }
      exportNodes.push({
        name: cweNode,
        value: this.get(cweNode).vulnerability_mapping,
        symbolSize: cweNode !== rootNode ? 15 - depth * 2 : 30,
        category,
        itemStyle: style,
      })
    }
    for (const [src, tgt, data] of edges) {
      const attr = data['nature'] ?? 'ParentOf' // python: edges.data('nature', default='ParentOf')
      if (validNodeSet.has(src) && validNodeSet.has(tgt)) {
        const isStructural = attr === 'ParentOf' || attr === 'HasMember'
        exportLinks.push({
          source: src,
          target: tgt,
          value: attr,
          ignoreForceLayout: !isStructural,
          lineStyle: {
            type: isStructural ? 'solid' : 'dashed',
          },
          symbol: ['none', 'arrow'],
          symbolSize: 5,
        })
      }
    }

    console.log(`root ${rootNode}: ${exportNodes.length} nodes, ${exportLinks.length}`)
    return {
      nodes: exportNodes,
      links: exportLinks,
      categories: GraphChartData.abstractions.map((c) => ({ name: c })),
      legends: [...GraphChartData.abstractions],
    }
  }

  /** python: generate_graph_data */
  generateGraphData(): Record<string, GraphExport> {
    const allGraphs: Record<string, GraphExport> = {}

    // trees of pillar weaknesses
    for (const [, rootNode] of this.tree.outEdges('CWE-1000')) {
      const visibleNodes: string[] = []
      for (const cweId of this.tree.nodes()) {
        if (this.getPillarWeaknessAncestor(cweId) === rootNode) {
          visibleNodes.push(cweId)
        }
      }
      const exportedGraph = this.exportData(visibleNodes, this.tree.edges(), rootNode)
      const graphName = `Tree of ${rootNode}: ${this.get(rootNode).name}`
      allGraphs[graphName] = exportedGraph
    }

    // graph
    const targetCwes = this.topCweIds
    const visibleNodesOnGraph = new Set<string>()
    for (const target of targetCwes) {
      if (!this.graph.hasNode(target)) {
        continue
      }
      const path = this.findPathOnTree('CWE-1000', target)
      if (path) {
        for (const p of path) visibleNodesOnGraph.add(p)
      }
    }
    const popularGraph = this.exportData(
      [...visibleNodesOnGraph],
      this.graph.edges(),
      'CWE-1000',
    )
    allGraphs['Popular Weaknesses'] = popularGraph

    const allGraph = this.exportData(this.graph.nodes(), this.graph.edges(), 'CWE-1000')
    allGraphs['All Weaknesses (could be very laggy)'] = allGraph

    return allGraphs
  }
}

export interface GraphNode {
  name: string
  value: string
  symbolSize: number
  category: string
  itemStyle: Record<string, number | string>
}

export interface GraphLink {
  source: string
  target: string
  value: string
  ignoreForceLayout: boolean
  lineStyle: { type: string }
  symbol: string[]
  symbolSize: number
}

export interface GraphExport {
  nodes: GraphNode[]
  links: GraphLink[]
  categories: { name: string }[]
  legends: string[]
}

export type { Dict }
