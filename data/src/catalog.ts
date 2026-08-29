import { DiGraph, type EdgeTuple } from './digraph.js'
import { parseXml, type XmlDict, type XmlValue } from './xml.js'

interface CweEntry {
  cwe_entry_type: 'weakness' | 'category' | 'view'
  name: string
  description: XmlValue
  vulnerability_mapping: string
  status?: string
  structure?: string
  abstraction?: string
  mapping_rationale?: XmlValue
  mapping_comments?: XmlValue
  mapping_reasons?: string[]
  related_weaknesses?: RelatedWeakness[]
  members?: RelatedWeakness[]
}

interface RelatedWeakness {
  [key: string]: string // ID / Nature / CWE_ID / View_ID / Ordinal (attribute order preserved)
}

function asList<T>(v: T | T[] | undefined | null): T[] {
  if (v === undefined || v === null) return []
  return Array.isArray(v) ? v : [v]
}

function wrappedList(container: unknown, innerKey: string): RelatedWeakness[] {
  if (container === undefined || container === null) return []
  const inner = (container as XmlDict)[innerKey]
  if (inner === undefined || inner === null) return []
  const list = asList(inner as RelatedWeakness | RelatedWeakness[])
  return list.map((r) => {
    const stripped: RelatedWeakness = {}
    for (const [k, v] of Object.entries(r)) {
      stripped[k.slice(1)] = String(v)
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
  static readonly navigationViewId = '1000'

  readonly rootDict: XmlDict
  readonly cweInfo: Record<string, CweEntry>

  // tree structure, based on CWE-1000 Research Concepts
  readonly tree: DiGraph
  // Each node has exactly one parent node, so we use a map for this relationship.
  readonly parentMap: Map<string, string>
  readonly graph: DiGraph

  constructor(cweXmlText: string) {
    const parsed = parseXml(cweXmlText)
    this.rootDict = parsed['Weakness_Catalog'] as XmlDict
    this.cweInfo = this.buildMetadata()

    this.tree = this.buildTree(CweCatalog.navigationViewId)
    if (!this.tree.isArborescence()) {
      throw new Error('CWE Research Concepts view is not a tree')
    }
    this.parentMap = new Map()
    for (const [u, v] of this.tree.edges()) {
      this.parentMap.set(v, u)
    }
    this.graph = this.buildGraph(CweCatalog.navigationViewId)
  }

  get(cweId: string): CweEntry {
    const entry = this.cweInfo[cweId]
    if (entry === undefined) {
      throw new Error(`CWE ID not found: ${cweId}`)
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

  printSummary(): void {
    const catalog = this.rootDict as Record<string, unknown>
    const cweVersion = catalog['@Version'] as string
    const cweDate = catalog['@Date'] as string
    console.log(`Common Weakness Enumeration Catalog (${cweVersion} ${cweDate})`)
    console.log(`Number of weaknesses: ${this.weaknesses.length}`)
    console.log(`Number of categories: ${this.categories.length}`)
    console.log(`Number of views: ${this.views.length}`)
    console.log(`Total entries: ${this.allCweIds.length}`)
  }

  protected buildMetadata(): Record<string, CweEntry> {
    const cweMetadata: Record<string, CweEntry> = {}

    for (const weakness of this.weaknesses) {
      const weaknessId = 'CWE-' + (weakness['@ID'] as string)
      const weaknessName = weakness['@Name'] as string
      const abstraction = weakness['@Abstraction'] as string
      const status = weakness['@Status'] as string
      const structure = weakness['@Structure'] as string
      const description = weakness['Description'] as XmlValue
      const mappingNotes = weakness['Mapping_Notes'] as XmlDict
      const vulnerabilityMapping = mappingNotes['Usage'] as string
      const mappingReasons = wrappedList(mappingNotes['Reasons'], 'Reason')
        .map((reason) => reason['Type'])
        .filter((reason): reason is string => Boolean(reason))
      const relatedWeaknesses = wrappedList(weakness['Related_Weaknesses'], 'Related_Weakness')

      cweMetadata[weaknessId] = {
        cwe_entry_type: 'weakness',
        name: weaknessName,
        abstraction,
        status,
        structure,
        description,
        vulnerability_mapping: vulnerabilityMapping,
        ...(mappingNotes['Rationale'] !== undefined
          ? { mapping_rationale: mappingNotes['Rationale'] as XmlValue }
          : {}),
        ...(mappingNotes['Comments'] !== undefined
          ? { mapping_comments: mappingNotes['Comments'] as XmlValue }
          : {}),
        ...(mappingReasons.length ? { mapping_reasons: mappingReasons } : {}),
        related_weaknesses: relatedWeaknesses
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
        status: category['@Status'] as string,
        description: categorySummary,
        vulnerability_mapping: 'Prohibited',
        members
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
        status: view['@Status'] as string,
        description: viewDescription,
        vulnerability_mapping: 'Prohibited',
        members
      }
    }

    return cweMetadata
  }

  protected buildTree(viewId: string): DiGraph {
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
    for (const member of this.get(`CWE-${viewId}`).members ?? []) {
      digraph.addEdge('CWE-' + viewId, 'CWE-' + member['CWE_ID'])
    }
    return digraph
  }

  protected buildGraph(viewId: string): DiGraph {
    const digraph = new DiGraph()

    // we want parent ---> child, so that: (parent) ---ParentOf--> (child)
    const relationshipToEdge = (w: string, rw: RelatedWeakness): void => {
      if (rw['Nature'] === 'ChildOf') {
        digraph.addEdge('CWE-' + rw['CWE_ID'], w, {
          nature: 'ParentOf',
          ordinal: rw['Ordinal'] ?? ''
        })
      } else {
        digraph.addEdge(w, 'CWE-' + rw['CWE_ID'], {
          nature: rw['Nature'],
          ordinal: rw['Ordinal'] ?? ''
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

    for (const member of this.get(`CWE-${viewId}`).members ?? []) {
      digraph.addEdge('CWE-' + viewId, 'CWE-' + member['CWE_ID'], { nature: 'HasMember' })
    }
    return digraph
  }

  findPathOnTree(ancestor: string, descendant: string): string[] | null {
    const path = [descendant]
    let currentNode = descendant
    while (currentNode !== ancestor) {
      const parent = this.parentMap.get(currentNode)
      if (!parent) return null
      currentNode = parent
      path.push(currentNode)
    }
    path.reverse()
    return path
  }

  getPillarWeaknessAncestor(node: string): string | null {
    const pathFromRoot = this.findPathOnTree('CWE-1000', node)
    if (pathFromRoot && pathFromRoot.length > 1) {
      if (this.get(pathFromRoot[1]).abstraction !== 'Pillar') {
        throw new Error(`${pathFromRoot[1]} is not a Pillar`)
      }
      return pathFromRoot[1]
    }
    return null
  }
}

export class CweGraphData extends CweCatalog {
  static readonly abstractions = ['Compound', 'Pillar', 'Class', 'Base', 'Variant']

  static readonly topCweIds = new Set([
    'CWE-125',
    'CWE-119',
    'CWE-787',
    'CWE-476',
    'CWE-416',
    'CWE-20',
    'CWE-190',
    'CWE-200',
    'CWE-399',
    'CWE-120',
    'CWE-401',
    'CWE-264',
    'CWE-362',
    'CWE-189',
    'CWE-772',
    'CWE-835',
    'CWE-617',
    'CWE-369',
    'CWE-415',
    'CWE-400',
    'CWE-122',
    'CWE-770',
    'CWE-22',
    'CWE-908',
    'CWE-284',
    'CWE-674',
    'CWE-254',
    'CWE-295',
    'CWE-59',
    'CWE-193',
    'CWE-287',
    'CWE-269',
    'CWE-834',
    'CWE-667',
    'CWE-310',
    'CWE-17',
    'CWE-754',
    'CWE-843',
    'CWE-755',
    'CWE-909',
    'CWE-404',
    'CWE-665',
    'CWE-191',
    'CWE-79',
    'CWE-252',
    'CWE-78',
    'CWE-681',
    'CWE-89',
    'CWE-704'
  ])

  exportData(nodes: string[], edges: EdgeTuple[], rootNode: string): GraphExport {
    const exportNodes: GraphNode[] = []
    const exportLinks: GraphLink[] = []
    const validNodeSet = new Set(nodes)
    for (const cweNode of nodes) {
      const path = this.findPathOnTree(rootNode, cweNode)
      const depth = path ? path.length - 1 : 1
      const category = this.get(cweNode).abstraction ?? 'Pillar'
      const style: Record<string, number | string> = { borderWidth: 0, opacity: 1 }
      if (CweGraphData.topCweIds.has(cweNode)) {
        style['borderColor'] = '#9B30FF'
        style['borderWidth'] = 2
      }
      exportNodes.push({
        name: cweNode,
        value: this.get(cweNode).vulnerability_mapping,
        symbolSize: cweNode !== rootNode ? 15 - depth * 2 : 30,
        category,
        itemStyle: style
      })
    }
    for (const [src, tgt, data] of edges) {
      const attr = data['nature'] ?? 'ParentOf'
      if (validNodeSet.has(src) && validNodeSet.has(tgt)) {
        const isStructural = attr === 'ParentOf' || attr === 'HasMember'
        exportLinks.push({
          source: src,
          target: tgt,
          value: attr,
          ignoreForceLayout: !isStructural,
          lineStyle: {
            type: isStructural ? 'solid' : 'dashed'
          },
          symbol: ['none', 'arrow'],
          symbolSize: 5
        })
      }
    }

    console.log(`root ${rootNode}: ${exportNodes.length} nodes, ${exportLinks.length}`)
    return {
      nodes: exportNodes,
      links: exportLinks,
      categories: CweGraphData.abstractions.map((c) => ({ name: c })),
      legends: [...CweGraphData.abstractions]
    }
  }

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
      const exportedGraph = this.exportData(visibleNodes, this.graph.edges(), rootNode)
      const graphName = `Tree of ${rootNode}: ${this.get(rootNode).name}`
      allGraphs[graphName] = exportedGraph
    }

    const visibleNodesOnGraph = new Set<string>()
    for (const target of CweGraphData.topCweIds) {
      if (!this.graph.hasNode(target)) {
        continue
      }
      const path = this.findPathOnTree('CWE-1000', target)
      if (path) {
        for (const p of path) visibleNodesOnGraph.add(p)
      }
    }
    const popularGraph = this.exportData([...visibleNodesOnGraph], this.graph.edges(), 'CWE-1000')
    allGraphs['Popular Weaknesses'] = popularGraph

    const allGraph = this.exportData(this.graph.nodes(), this.graph.edges(), 'CWE-1000')
    allGraphs['All Weaknesses'] = allGraph

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
