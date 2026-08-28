/**
 * Minimal re-implementation of the networkx.DiGraph semantics the data
 * model was built on: insertion-ordered nodes/edges and networkx's
 * iteration order for .nodes / .edges / .out_edges, which the JSON export
 * depends on (array order in the output files must stay stable).
 */

export interface EdgeData {
  [key: string]: string
}

export type EdgeTuple = [string, string, EdgeData]

export class DiGraph {
  private _nodeOrder: string[] = []
  private _nodeSet = new Set<string>()
  private _succ = new Map<string, string[]>()
  private _edgeData = new Map<string, EdgeData>()

  hasNode(u: string): boolean {
    return this._nodeSet.has(u)
  }

  /** networkx add_node: no-op if present. */
  addNode(u: string): void {
    if (!this._nodeSet.has(u)) {
      this._nodeSet.add(u)
      this._nodeOrder.push(u)
      this._succ.set(u, [])
    }
  }

  /**
   * networkx add_edge: adds missing endpoints in (u, v) order; if the edge
   * exists its data dict is updated but position/order is kept.
   */
  addEdge(u: string, v: string, data: EdgeData = {}): void {
    this.addNode(u)
    this.addNode(v)
    const succ = this._succ.get(u) as string[]
    if (!succ.includes(v)) {
      succ.push(v)
      this._edgeData.set(edgeKey(u, v), { ...data })
    } else {
      Object.assign(this._edgeData.get(edgeKey(u, v)) as EdgeData, data)
    }
  }

  hasEdge(u: string, v: string): boolean {
    return this._edgeData.has(edgeKey(u, v))
  }

  /** Iteration order matches `for n in G` on a networkx DiGraph. */
  nodes(): string[] {
    return this._nodeOrder
  }

  /** Iteration order matches `for e in G.edges` (u in node order, then v in add order). */
  edges(): EdgeTuple[] {
    const out: EdgeTuple[] = []
    for (const u of this._nodeOrder) {
      for (const v of this._succ.get(u) as string[]) {
        out.push([u, v, this._edgeData.get(edgeKey(u, v)) as EdgeData])
      }
    }
    return out
  }

  /** Iteration order matches `G.out_edges([u])`. */
  outEdges(u: string): EdgeTuple[] {
    const out: EdgeTuple[] = []
    for (const v of this._succ.get(u) ?? []) {
      out.push([u, v, this._edgeData.get(edgeKey(u, v)) as EdgeData])
    }
    return out
  }

  inDegree(u: string): number {
    let n = 0
    for (const succ of this._succ.values()) {
      for (const v of succ) {
        if (v === u) n++
      }
    }
    return n
  }

  /**
   * networkx.is_arborescence: every node has in-degree <= 1, exactly one
   * node has in-degree 0, and that root reaches every node.
   */
  isArborescence(): boolean {
    if (this._nodeOrder.length === 0) return false
    let root: string | null = null
    for (const u of this._nodeOrder) {
      const deg = this.inDegree(u)
      if (deg > 1) return false
      if (deg === 0) {
        if (root !== null) return false
        root = u
      }
    }
    if (root === null) return false
    // reachability (in-degree <= 1 + single root + full reachability => tree)
    const seen = new Set<string>([root])
    const stack = [root]
    while (stack.length > 0) {
      const u = stack.pop() as string
      for (const v of this._succ.get(u) as string[]) {
        if (!seen.has(v)) {
          seen.add(v)
          stack.push(v)
        }
      }
    }
    return seen.size === this._nodeOrder.length
  }
}

function edgeKey(u: string, v: string): string {
  return `${u}\u0000${v}`
}
