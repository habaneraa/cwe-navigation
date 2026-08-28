<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import * as echarts from 'echarts'
import {
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Clipboard,
  ExternalLink,
  Filter,
  Focus,
  Github,
  Info,
  Maximize2,
  Minus,
  Network,
  Plus,
  RotateCcw,
  Search,
  SlidersHorizontal,
  TriangleAlert,
  X,
} from 'lucide-vue-next'

const abstractionOrder = ['Pillar', 'Class', 'Base', 'Variant', 'Compound']
const abstractionColors = {
  Pillar: '#6d5bd0',
  Class: '#2f7f86',
  Base: '#dc7a3f',
  Variant: '#3f73c8',
  Compound: '#b55271',
}
const abstractionSymbols = {
  Pillar: 'diamond',
  Class: 'roundRect',
  Base: 'circle',
  Variant: 'circle',
  Compound: 'rect',
}

const chartEl = ref(null)
const searchInput = ref(null)
const loading = ref(true)
const loadError = ref('')
const graphs = ref({})
const metadata = ref({})
const dataInfo = ref({})
const selectedView = ref('')
const selectedNodeId = ref('')
const trail = ref([])
const enabledAbstractions = ref(new Set(abstractionOrder))
const enabledRelations = ref(new Set())
const searchScope = ref('all')
const searchQuery = ref('')
const searchOpen = ref(false)
const activeResult = ref(0)
const leftCollapsed = ref(false)
const mobileFiltersOpen = ref(false)
const mobileDetailExpanded = ref(false)
const modal = ref('')
const pendingView = ref('')
const toast = ref('')
const showGuide = ref(false)
const zoomLevel = ref(1)
let chart
let toastTimer

const viewEntries = computed(() => Object.entries(graphs.value))
const currentGraph = computed(() => graphs.value[selectedView.value] || { nodes: [], links: [] })
const selectedNode = computed(() => metadata.value[selectedNodeId.value])

const nodesInCurrentView = computed(() => new Set(currentGraph.value.nodes.map((node) => node.name)))
const abstractionCounts = computed(() => {
  const counts = Object.fromEntries(abstractionOrder.map((name) => [name, 0]))
  currentGraph.value.nodes.forEach((node) => {
    counts[node.category] = (counts[node.category] || 0) + 1
  })
  return counts
})
const relationTypes = computed(() => {
  const counts = {}
  currentGraph.value.links.forEach((link) => {
    counts[link.value] = (counts[link.value] || 0) + 1
  })
  return Object.entries(counts).sort((a, b) => b[1] - a[1])
})
const filteredNodes = computed(() =>
  currentGraph.value.nodes.filter(
    (node) => node.category === 'Pillar' || enabledAbstractions.value.has(node.category),
  ),
)
const filteredNodeIds = computed(() => new Set(filteredNodes.value.map((node) => node.name)))
const filteredLinks = computed(() =>
  currentGraph.value.links.filter(
    (link) =>
      filteredNodeIds.value.has(link.source) &&
      filteredNodeIds.value.has(link.target) &&
      enabledRelations.value.has(link.value),
  ),
)
const filtersActive = computed(
  () =>
    enabledAbstractions.value.size !== abstractionOrder.length ||
    enabledRelations.value.size !== relationTypes.value.length,
)

const relatedWeaknesses = computed(() => {
  if (!selectedNodeId.value) return []
  const related = new Map()
  ;(selectedNode.value?.related_weaknesses || [])
    .filter((relation) => relation.View_ID === '1000')
    .forEach((relation) => {
      const id = `CWE-${relation.CWE_ID}`
      if (metadata.value[id]) {
        related.set(id, { id, nature: relation.Nature, node: metadata.value[id] })
      }
    })
  currentGraph.value.links.forEach((link) => {
    let id = ''
    let nature = link.value
    if (link.source === selectedNodeId.value) id = link.target
    if (link.target === selectedNodeId.value) {
      id = link.source
      if (link.value === 'ParentOf') nature = 'ChildOf'
    }
    if (id && metadata.value[id] && !related.has(id)) {
      related.set(id, { id, nature, node: metadata.value[id] })
    }
  })
  return [...related.values()]
})

const searchableEntries = computed(() =>
  Object.entries(metadata.value)
    .filter(([, entry]) => entry.cwe_entry_type === 'weakness')
    .map(([id, entry]) => ({ id, ...entry })),
)
const searchResults = computed(() => {
  const raw = searchQuery.value.trim()
  if (!raw) return []
  const query = raw.toLowerCase()
  const normalizedId = query.replace(/^cwe[-\s]?/, '')
  const tokens = query.split(/\s+/).filter(Boolean)
  return searchableEntries.value
    .map((entry) => {
      const id = entry.id.toLowerCase()
      const name = entry.name.toLowerCase()
      const description = String(entry.description || '').toLowerCase()
      let score = 0
      let matches = false
      if (searchScope.value === 'all' || searchScope.value === 'id') {
        const idNumber = id.slice(4)
        if (idNumber === normalizedId) score += 1000
        else if (idNumber.startsWith(normalizedId)) score += 180
        else if (id.includes(query)) score += 100
        matches ||= idNumber.includes(normalizedId)
      }
      if (searchScope.value === 'all' || searchScope.value === 'name') {
        const nameMatches = tokens.every((token) => name.includes(token))
        if (nameMatches) score += name.startsWith(query) ? 130 : 90
        matches ||= nameMatches
      }
      if (searchScope.value === 'all' || searchScope.value === 'description') {
        const descriptionMatches = tokens.every((token) => description.includes(token))
        if (descriptionMatches) score += 40
        matches ||= descriptionMatches
      }
      return matches ? { ...entry, score, view: findViewForNode(entry.id) } : null
    })
    .filter(Boolean)
    .sort((a, b) => b.score - a.score || Number(a.id.slice(4)) - Number(b.id.slice(4)))
    .slice(0, 60)
})

function findViewForNode(nodeId) {
  if (nodesInCurrentView.value.has(nodeId)) return selectedView.value
  const tree = viewEntries.value.find(
    ([name, graph]) => name.startsWith('Tree of') && graph.nodes.some((node) => node.name === nodeId),
  )
  return tree?.[0] || viewEntries.value.find(([name]) => name.startsWith('All Weaknesses'))?.[0] || ''
}

function shortViewName(name) {
  const match = name.match(/^Tree of (CWE-\d+): (.+)$/)
  if (match) return `${match[1]} · ${match[2]}`
  return name.replace(' (could be very laggy)', '')
}

function viewId(name) {
  const match = name.match(/^Tree of (CWE-\d+):/)
  if (match) return match[1]
  if (name.startsWith('All Weaknesses')) return 'CWE-1000'
  return name.match(/CWE-\d+/)?.[0] || 'CWE-1000'
}

function shortName(name, length = 34) {
  if (!name) return 'Details unavailable'
  return name.length > length ? `${name.slice(0, length - 1)}…` : name
}

function descriptionSnippet(entry) {
  const text = String(entry.description || '')
  const query = searchQuery.value.trim().toLowerCase()
  if (!text) return 'No description available.'
  if (!query || searchScope.value !== 'description') return shortName(text, 110)
  const firstToken = query.split(/\s+/)[0]
  const index = text.toLowerCase().indexOf(firstToken)
  const start = Math.max(0, index - 38)
  const snippet = text.slice(start, start + 120)
  return `${start ? '…' : ''}${snippet}${start + 120 < text.length ? '…' : ''}`
}

function highlightedParts(text) {
  const value = String(text || '')
  const query = searchQuery.value.trim()
  if (!query) return [{ text: value, match: false }]
  const terms = query.split(/\s+/).filter(Boolean).map(escapeRegExp)
  if (!terms.length) return [{ text: value, match: false }]
  const regex = new RegExp(`(${terms.join('|')})`, 'gi')
  return value.split(regex).filter(Boolean).map((part) => ({
    text: part,
    match: terms.some((term) => new RegExp(`^${term}$`, 'i').test(part)),
  }))
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function graphOption() {
  const linked = new Set()
  if (selectedNodeId.value) {
    const active = selectedNodeId.value
    linked.add(active)
    filteredLinks.value.forEach((link) => {
      if (link.source === active) linked.add(link.target)
      if (link.target === active) linked.add(link.source)
    })
  }
  const dimUnrelated = linked.size > 0
  const degree = {}
  filteredLinks.value.forEach((link) => {
    degree[link.source] = (degree[link.source] || 0) + 1
    degree[link.target] = (degree[link.target] || 0) + 1
  })
  return {
    animationDuration: 360,
    animationDurationUpdate: 220,
    tooltip: {
      trigger: 'item',
      enterable: false,
      backgroundColor: '#17252e',
      borderWidth: 0,
      padding: [10, 12],
      textStyle: { color: '#fff', fontSize: 12 },
      formatter: (params) => {
        if (params.dataType !== 'node') return `${params.data.value}`
        const info = metadata.value[params.data.name] || {}
        return `<b>${escapeHtml(params.data.name)}</b><br/>${escapeHtml(shortName(info.name, 48))}<br/><span style="color:#b9c8cf">${escapeHtml(info.abstraction || params.data.category)} · ${degree[params.data.name] || 0} relationships</span>`
      },
    },
    series: [
      {
        id: 'cwe-graph',
        type: 'graph',
        layout: 'force',
        roam: true,
        roamTrigger: 'global',
        draggable: true,
        zoom: zoomLevel.value,
        left: 54,
        top: 64,
        right: 54,
        bottom: 64,
        categories: abstractionOrder.map((name) => ({
          name,
          itemStyle: { color: abstractionColors[name] },
        })),
        data: filteredNodes.value.map((node) => {
          const info = metadata.value[node.name] || {}
          const isActive = node.name === selectedNodeId.value
          const visible = !dimUnrelated || linked.has(node.name)
          return {
            ...node,
            symbol: abstractionSymbols[node.category] || 'circle',
            symbolSize:
              Math.max(14, Math.min(28, 13 + (degree[node.name] || 0) * 1.25)) -
              (node.category === 'Variant' ? 2 : 0),
            itemStyle: {
              color: abstractionColors[node.category] || '#71838c',
              opacity: visible ? 1 : 0.17,
              borderColor: isActive ? '#0b4f4a' : '#ffffff',
              borderWidth: isActive ? 4 : 1.5,
              shadowBlur: isActive ? 14 : 0,
              shadowColor: 'rgba(15,118,110,.35)',
            },
            label: {
              show: isActive || visible,
              opacity: visible ? 1 : 0.15,
              formatter: zoomLevel.value > 1.12 ? `${node.name}\n${shortName(info.name, 24)}` : node.name,
            },
          }
        }),
        links: filteredLinks.value.map((link) => {
          const active = selectedNodeId.value
          const connected = active && (link.source === active || link.target === active)
          return {
            ...link,
            lineStyle: {
              type: link.lineStyle?.type || (link.value === 'ParentOf' ? 'solid' : 'dashed'),
              color: connected ? '#0f766e' : '#9eb0b8',
              opacity: dimUnrelated ? (connected ? 0.95 : 0.08) : 0.42,
              width: connected ? 2.2 : 1,
              curveness: link.value === 'ParentOf' ? 0 : 0.12,
            },
          }
        }),
        label: {
          show: true,
          silent: true,
          position: 'bottom',
          distance: 5,
          color: '#334852',
          fontFamily: 'Inter, system-ui, sans-serif',
          fontSize: 10,
          lineHeight: 13,
        },
        lineStyle: { color: '#9eb0b8', opacity: 0.42, width: 1 },
        force: {
          repulsion: currentGraph.value.nodes.length > 400 ? 46 : 88,
          edgeLength: currentGraph.value.nodes.length > 400 ? [20, 48] : [42, 92],
          gravity: 0.07,
          friction: 0.65,
          layoutAnimation: currentGraph.value.nodes.length < 400,
        },
        emphasis: {
          focus: 'adjacency',
          scale: false,
          itemStyle: {
            borderColor: '#0b4f4a',
            borderWidth: 4,
            shadowBlur: 14,
            shadowColor: 'rgba(15,118,110,.35)',
          },
          label: { show: true, fontWeight: 700 },
          lineStyle: { opacity: 1, width: 2.2 },
        },
        blur: {
          itemStyle: { opacity: 0.17 },
          label: { opacity: 0.15 },
          lineStyle: { opacity: 0.08 },
        },
      },
    ],
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

async function loadData() {
  loading.value = true
  loadError.value = ''
  try {
    const [graphResponse, metadataResponse, infoResponse] = await Promise.all([
      fetch(`${import.meta.env.BASE_URL}graph_data.json`),
      fetch(`${import.meta.env.BASE_URL}cwe_metadata.json`),
      fetch(`${import.meta.env.BASE_URL}catalog_info.json`),
    ])
    if (!graphResponse.ok || !metadataResponse.ok || !infoResponse.ok) {
      throw new Error('Data files could not be loaded')
    }
    graphs.value = await graphResponse.json()
    metadata.value = await metadataResponse.json()
    dataInfo.value = await infoResponse.json()
    const defaultView = Object.keys(graphs.value).find((name) => name.includes('CWE-707'))
    const params = new URLSearchParams(window.location.search)
    selectedView.value = graphs.value[params.get('view')] ? params.get('view') : defaultView
    resetRelationFilters()
    loading.value = false
    await nextTick()
    initChart()
    const linkedNode = params.get('node')
    if (linkedNode && metadata.value[linkedNode]) selectNode(linkedNode, { addToTrail: false })
    showGuide.value = !window.localStorage.getItem('cwe-guide-seen')
  } catch (error) {
    loadError.value = error instanceof Error ? error.message : 'The graph is temporarily unavailable.'
    loading.value = false
  }
}

function initChart() {
  if (!chartEl.value) return
  chart?.dispose()
  chart = echarts.init(chartEl.value, null, { renderer: 'canvas' })
  chart.setOption(graphOption(), true)
  chart.on('click', (params) => {
    if (params.dataType === 'node') selectNode(params.data.name)
  })
  chart.on('graphroam', () => {
    const option = chart?.getOption()
    zoomLevel.value = Number(option?.series?.[0]?.zoom || 1)
  })
  chart.getZr().on('click', (event) => {
    if (!event.target) clearSelection()
  })
  window.addEventListener('resize', resizeChart)
}

function updateGraph() {
  if (!chart || loading.value) return
  chart.setOption(graphOption(), { notMerge: true, lazyUpdate: true })
}

function updateGraphHighlight() {
  if (!chart) return
  chart.dispatchAction({ type: 'downplay', seriesId: 'cwe-graph' })
  const dataIndex = filteredNodes.value.findIndex((node) => node.name === selectedNodeId.value)
  if (dataIndex >= 0) {
    chart.dispatchAction({ type: 'highlight', seriesId: 'cwe-graph', dataIndex })
  }
}

function switchView(name, nodeToKeep = '') {
  if (name === selectedView.value) return
  selectedView.value = name
  zoomLevel.value = 1
  resetAbstractionFilters()
  resetRelationFilters()
  if (!nodeToKeep || !graphs.value[name].nodes.some((node) => node.name === nodeToKeep)) {
    selectedNodeId.value = ''
  }
  nextTick(() => {
    updateGraph()
    resizeChart()
  })
}

function requestViewSwitch(name) {
  if (name === selectedView.value) return
  if (name.startsWith('All Weaknesses')) {
    pendingView.value = name
    modal.value = 'all'
    return
  }
  const keepsCurrentNode = currentGraph.value.nodes.some((node) => node.name === selectedNodeId.value)
  const targetHasCurrentNode = graphs.value[name].nodes.some((node) => node.name === selectedNodeId.value)
  if (selectedNodeId.value && keepsCurrentNode && !targetHasCurrentNode) {
    pendingView.value = name
    modal.value = 'view'
    return
  }
  switchView(name)
}

function confirmViewSwitch() {
  switchView(pendingView.value)
  pendingView.value = ''
  modal.value = ''
}

function selectNode(nodeId, options = {}) {
  const previousId = selectedNodeId.value
  const previousView = selectedView.value
  const targetView = findViewForNode(nodeId)
  if (targetView && targetView !== selectedView.value) switchView(targetView, nodeId)
  if (previousId && previousId !== nodeId && options.addToTrail !== false) {
    if (trail.value.at(-1)?.id !== previousId) {
      trail.value.push({ id: previousId, view: previousView })
    }
  }
  selectedNodeId.value = nodeId
  searchOpen.value = false
  mobileDetailExpanded.value = false
  syncUrl()
  nextTick(() => {
    resizeChart()
    updateGraphHighlight()
  })
}

function selectSearchResult(result) {
  if (!result) return
  if (result.view && result.view !== selectedView.value) switchView(result.view, result.id)
  selectNode(result.id)
}

function clearSelection() {
  if (!selectedNodeId.value) return
  selectedNodeId.value = ''
  syncUrl()
  nextTick(() => {
    resizeChart()
    updateGraphHighlight()
  })
}

function clearSearch() {
  searchQuery.value = ''
  searchOpen.value = false
  activeResult.value = 0
  clearSelection()
  fitGraph()
  searchInput.value?.focus()
}

function navigateTrail(index) {
  const target = trail.value[index]
  trail.value = trail.value.slice(0, index)
  if (target.view !== selectedView.value) switchView(target.view, target.id)
  selectNode(target.id, { addToTrail: false })
}

function toggleAbstraction(name) {
  if (name === 'Pillar') return

  const next = new Set(enabledAbstractions.value)
  next.has(name) ? next.delete(name) : next.add(name)
  enabledAbstractions.value = next
}

function toggleRelation(name) {
  const next = new Set(enabledRelations.value)
  if (next.has(name)) {
    next.delete(name)
    if (!next.size) {
      modal.value = 'relations'
      return
    }
  } else {
    next.add(name)
  }
  enabledRelations.value = next
}

function resetAbstractionFilters() {
  enabledAbstractions.value = new Set(abstractionOrder)
}

function resetRelationFilters() {
  const graph = graphs.value[selectedView.value]
  enabledRelations.value = new Set(
    graph?.links.some((link) => link.value === 'ParentOf') ? ['ParentOf'] : [],
  )
}

function clearFilters() {
  resetAbstractionFilters()
  const graph = graphs.value[selectedView.value]
  enabledRelations.value = new Set(graph ? graph.links.map((link) => link.value) : [])
}

function confirmRelationFilterChange() {
  enabledRelations.value = new Set()
  modal.value = ''
}

function zoomBy(amount) {
  zoomLevel.value = Math.max(0.35, Math.min(3, zoomLevel.value * amount))
  chart?.setOption({ series: [{ id: 'cwe-graph', zoom: zoomLevel.value }] })
}

function fitGraph() {
  zoomLevel.value = 1
  chart?.setOption({ series: [{ id: 'cwe-graph', zoom: 1, center: null }] })
}

function resetView() {
  clearSelection()
  fitGraph()
}

async function toggleFullscreen() {
  const stage = chartEl.value?.closest('.graph-stage')
  if (!stage) return
  if (document.fullscreenElement) await document.exitFullscreen()
  else await stage.requestFullscreen()
  setTimeout(resizeChart, 80)
}

async function copyLink() {
  syncUrl()
  try {
    await navigator.clipboard.writeText(window.location.href)
    showToast('Link copied to clipboard')
  } catch {
    showToast('Copy failed — copy the URL from your browser')
  }
}

function syncUrl() {
  const url = new URL(window.location.href)
  if (selectedView.value) url.searchParams.set('view', selectedView.value)
  if (selectedNodeId.value) url.searchParams.set('node', selectedNodeId.value)
  else url.searchParams.delete('node')
  window.history.replaceState({}, '', url)
}

function showToast(message) {
  toast.value = message
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => (toast.value = ''), 2400)
}

function abstractionBadgeClass(kind) {
  return {
    Pillar: 'bg-[#eeebff] text-[#5849ad]',
    Class: 'bg-[#e1f2f2] text-[#24686e]',
    Base: 'bg-[#fff0e6] text-[#9b542c]',
    Variant: 'bg-[#e9f0fc] text-[#315fa6]',
    Compound: 'bg-[#fae9ef] text-[#93405b]',
  }[kind] || 'bg-[#e8f0f2] text-[#3f5f69]'
}

function statusBadgeClass(status) {
  return {
    Stable: 'bg-[#e7f5ed] text-[#287552]',
    Draft: 'bg-[#fff2dc] text-[#9a641f]',
    Incomplete: 'bg-[#e9f1fc] text-[#376ba9]',
    Deprecated: 'bg-[#f3e8eb] text-[#8c485a]',
  }[status] || 'bg-[#e8f0f2] text-[#3f5f69]'
}

function structureBadgeClass(structure) {
  return {
    Simple: 'bg-[#eef2f4] text-[#4d6670]',
    Composite: 'bg-[#eeeafd] text-[#5c4aa8]',
    Chain: 'bg-[#f9e9f0] text-[#93405b]',
  }[structure] || 'bg-[#e8f0f2] text-[#3f5f69]'
}

function mappingText(value) {
  if (!value) return ''
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(mappingText).filter(Boolean).join('\n')
  if (typeof value === 'object') {
    return Object.entries(value)
      .filter(([key]) => !key.startsWith('@'))
      .map(([, child]) => mappingText(child))
      .filter(Boolean)
      .join('\n')
  }
  return String(value)
}

function mappingDescription(status) {
  if (status === 'Allowed') {
    return 'This weakness can be used for vulnerability mapping under the official guidance.'
  }
  if (status === 'Allowed-with-Review') {
    return 'Mapping is allowed, but the choice should be reviewed against the official guidance.'
  }
  if (status === 'Discouraged') {
    return 'Mapping to this weakness is discouraged when a more specific entry is available.'
  }
  return 'This entry is not intended for direct vulnerability mapping.'
}

function dismissGuide() {
  showGuide.value = false
  window.localStorage.setItem('cwe-guide-seen', '1')
}

function onSearchKeydown(event) {
  if (event.key === 'ArrowDown') {
    event.preventDefault()
    searchOpen.value = true
    activeResult.value = Math.min(activeResult.value + 1, searchResults.value.length - 1)
  } else if (event.key === 'ArrowUp') {
    event.preventDefault()
    activeResult.value = Math.max(activeResult.value - 1, 0)
  } else if (event.key === 'Enter' && searchOpen.value) {
    event.preventDefault()
    selectSearchResult(searchResults.value[activeResult.value])
  } else if (event.key === 'Escape') {
    searchOpen.value = false
  }
}

function onSearchFocusout(event) {
  if (!event.currentTarget.contains(event.relatedTarget)) searchOpen.value = false
}

function onGlobalKeydown(event) {
  if (event.key !== 'Escape') return
  if (modal.value) modal.value = ''
  else if (mobileFiltersOpen.value) mobileFiltersOpen.value = false
  else if (searchOpen.value) searchOpen.value = false
  else if (selectedNodeId.value) clearSelection()
}

function resizeChart() {
  chart?.resize()
}

watch([searchQuery, searchScope], () => {
  activeResult.value = 0
  if (searchQuery.value.trim()) searchOpen.value = true
})
watch([enabledAbstractions, enabledRelations], () => {
  if (selectedNodeId.value && !filteredNodeIds.value.has(selectedNodeId.value)) clearSelection()
  else updateGraph()
})

onMounted(() => {
  loadData()
  window.addEventListener('keydown', onGlobalKeydown)
})
onUnmounted(() => {
  clearTimeout(toastTimer)
  window.removeEventListener('resize', resizeChart)
  window.removeEventListener('keydown', onGlobalKeydown)
  chart?.dispose()
})
</script>

<template>
  <div class="app-shell grid h-full grid-rows-[68px_minmax(0,1fr)] max-[800px]:grid-rows-[auto_minmax(0,1fr)]">
    <a class="skip-link fixed top-2 left-2 z-[100] -translate-y-[150%] rounded-lg bg-accent-dark px-3 py-2 text-xs text-white transition-transform focus:translate-y-0" href="#graph-stage">Skip to graph</a>
    <a v-if="selectedNodeId" class="skip-link fixed top-2 left-[120px] z-[100] -translate-y-[150%] rounded-lg bg-accent-dark px-3 py-2 text-xs text-white transition-transform focus:translate-y-0" href="#node-details">Skip to node details</a>

    <header class="app-header relative z-20 grid grid-cols-[minmax(240px,1fr)_minmax(380px,640px)_minmax(240px,1fr)] items-center gap-6 border-b border-line bg-white/97 px-[22px] shadow-[0_1px_0_rgba(18,37,45,.02)] max-[1180px]:grid-cols-[215px_minmax(340px,1fr)_auto] max-[1180px]:gap-4 max-[800px]:grid-cols-[minmax(0,1fr)_auto] max-[800px]:gap-2 max-[800px]:px-3 max-[800px]:py-2.5">
      <div class="brand flex min-w-0 items-center gap-3 whitespace-nowrap">
        <span class="brand-mark grid size-[34px] shrink-0 place-items-center rounded-[10px] bg-accent text-white shadow-[0_5px_12px_rgba(15,118,110,.18)] max-[800px]:size-8"><Network :size="17" /></span>
        <div class="brand-copy flex min-w-0 flex-col gap-0.5">
          <strong class="text-sm tracking-[-.01em] max-[480px]:text-[13px]">CWE Navigation</strong>
          <span class="overflow-hidden text-[10.5px] text-muted text-ellipsis max-[800px]:hidden">Research Concepts · View 1000</span>
        </div>
      </div>

      <div class="search-area relative min-w-0 max-[800px]:col-span-full max-[800px]:row-start-2" @focusout="onSearchFocusout">
        <div class="search-shell flex h-11 items-center rounded-[11px] border bg-white text-muted shadow-[0_4px_18px_rgba(34,55,63,.07)] transition focus-within:border-[#58a29c] focus-within:shadow-[0_0_0_3px_rgba(15,118,110,.09),0_8px_24px_rgba(34,55,63,.1)]" :class="searchOpen ? 'border-[#58a29c] shadow-[0_0_0_3px_rgba(15,118,110,.09),0_8px_24px_rgba(34,55,63,.1)]' : 'border-line-strong'">
          <select v-model="searchScope" class="h-full w-28 cursor-pointer border-0 bg-transparent px-3 text-[11.5px] text-ink-soft outline-none max-[480px]:w-24 max-[480px]:px-2 max-[480px]:text-[10.5px]" aria-label="Search scope">
            <option value="all">All fields</option>
            <option value="id">CWE ID</option>
            <option value="name">Name</option>
            <option value="description">Description</option>
          </select>
          <span class="search-divider mr-3 h-[22px] w-px bg-line max-[480px]:mr-2"></span>
          <Search :size="18" class="mr-2 shrink-0 max-[480px]:mr-1.5" aria-hidden="true" />
          <input
            ref="searchInput"
            v-model="searchQuery"
            aria-label="Search CWE"
            aria-controls="search-results"
            :aria-expanded="searchOpen"
            placeholder="Search CWE ID, name, or description…"
            class="h-full min-w-0 flex-1 border-0 bg-transparent p-0 text-[13px] text-ink outline-none placeholder:text-[#91a0a7] max-[480px]:text-xs"
            autocomplete="off"
            @focus="searchOpen = true"
            @keydown="onSearchKeydown"
          />
          <button v-if="searchQuery" class="clear-search mr-1 grid size-[34px] shrink-0 place-items-center rounded-lg border-0 bg-transparent text-muted hover:bg-soft hover:text-ink" aria-label="Clear search" @click="clearSearch">
            <X :size="17" />
          </button>
        </div>

        <div v-if="searchOpen" id="search-results" class="search-results absolute top-[calc(100%+8px)] left-0 z-30 max-h-[min(550px,calc(100vh-94px))] w-full overflow-y-auto rounded-xl border border-line bg-white shadow-[0_18px_50px_rgba(19,42,51,.18)] max-[800px]:max-h-[calc(100vh-112px)]" role="listbox">
          <div v-if="!searchQuery.trim()" class="search-empty flex min-h-[88px] items-center justify-start gap-3 p-6 text-left text-muted">
            <Search :size="20" />
            <div class="grid gap-1"><strong class="text-[13px] text-ink">Find any weakness</strong><span class="text-[11.5px]">Try “79”, “injection”, or a phrase from a description.</span></div>
          </div>
          <template v-else-if="searchResults.length">
            <button
              v-for="(result, index) in searchResults"
              :key="result.id"
              class="search-result relative grid w-full cursor-pointer border-0 border-b border-[#edf2f3] bg-white px-4 py-3 pl-[18px] text-left before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:bg-transparent hover:bg-[#f0f7f6]"
              :class="index === activeResult ? 'bg-[#f0f7f6] before:!bg-accent' : ''"
              role="option"
              :aria-selected="index === activeResult"
              @mouseenter="activeResult = index"
              @click="selectSearchResult(result)"
            >
              <span class="result-topline flex items-center justify-between gap-2">
                <span class="result-id font-mono text-[11.5px] font-bold tracking-[.02em] text-accent-dark">
                  <template v-for="(part, partIndex) in highlightedParts(result.id)" :key="partIndex">
                    <mark v-if="part.match" class="rounded-sm bg-[#f8dfa0] px-px text-inherit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                  </template>
                </span>
                <span class="abstraction-badge inline-flex min-h-5 items-center rounded-full px-2 text-[9.5px] font-bold" :class="abstractionBadgeClass(result.abstraction)">{{ result.abstraction }}</span>
              </span>
              <span class="result-name mt-1 text-[12.5px] leading-[1.35] font-semibold text-ink">
                <template v-for="(part, partIndex) in highlightedParts(result.name)" :key="partIndex">
                  <mark v-if="part.match" class="rounded-sm bg-[#f8dfa0] px-px text-inherit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </span>
              <span class="result-description mt-1 overflow-hidden text-[11.5px] whitespace-nowrap text-muted text-ellipsis">
                <template v-for="(part, partIndex) in highlightedParts(descriptionSnippet(result))" :key="partIndex">
                  <mark v-if="part.match" class="rounded-sm bg-[#f8dfa0] px-px text-inherit">{{ part.text }}</mark><template v-else>{{ part.text }}</template>
                </template>
              </span>
              <span v-if="result.view !== selectedView" class="result-view mt-1 text-[10.5px] text-[#56717b]">In {{ shortViewName(result.view) }}</span>
            </button>
            <div class="result-count sticky bottom-0 flex justify-between gap-3 bg-[#f7fafb] px-4 py-2 text-[10.5px] text-muted shadow-[0_-1px_0_var(--color-line)]">Showing {{ searchResults.length }} matching weaknesses <span class="max-[480px]:hidden">↑↓ to navigate · Enter to open</span></div>
          </template>
          <div v-else class="search-empty flex min-h-[156px] items-center justify-center gap-3 p-6 text-left text-muted">
            <span class="empty-icon grid size-10 place-items-center rounded-full bg-accent-soft text-accent"><Search :size="21" /></span>
            <div class="grid gap-1"><strong class="text-[13px] text-ink">No CWE found</strong><span class="text-[11.5px]">Try another keyword or switch the search scope.</span></div>
          </div>
        </div>
      </div>

      <nav class="header-actions flex items-center justify-end gap-0.5 max-[800px]:col-start-2 max-[800px]:row-start-1" aria-label="Helpful links">
        <button class="header-action inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-transparent bg-transparent px-2 text-[11px] whitespace-nowrap text-ink-soft hover:border-line hover:bg-soft hover:text-ink max-[1180px]:w-9 max-[1180px]:justify-center max-[1180px]:px-0 max-[800px]:hidden" @click="modal = 'data'"><Info :size="17" /><span class="max-[1180px]:hidden">About this data</span></button>
        <a class="header-action grid size-9 place-items-center rounded-lg border border-transparent bg-transparent p-0 text-ink-soft no-underline hover:border-line hover:bg-soft hover:text-ink" href="https://github.com/habaneraa/cwe-navigation" target="_blank" rel="noreferrer" aria-label="GitHub"><Github :size="19" /></a>
        <button class="header-action grid size-9 place-items-center rounded-lg border border-transparent bg-transparent p-0 text-ink-soft hover:border-line hover:bg-soft hover:text-ink" aria-label="Help" @click="modal = 'help'"><CircleHelp :size="19" /></button>
      </nav>
    </header>

    <main
      class="workspace grid min-h-0 max-[800px]:relative max-[800px]:!block"
      :class="[
        selectedNodeId
          ? 'grid-cols-[268px_minmax(420px,1fr)_minmax(370px,410px)] max-[1180px]:!grid-cols-[42px_minmax(390px,1fr)_minmax(340px,370px)]'
          : 'grid-cols-[268px_minmax(0,1fr)] max-[1180px]:!grid-cols-[42px_minmax(390px,1fr)]',
        leftCollapsed
          ? selectedNodeId
            ? '!grid-cols-[42px_minmax(420px,1fr)_minmax(370px,410px)]'
            : '!grid-cols-[42px_minmax(0,1fr)]'
          : '',
      ]"
    >
      <aside
        class="control-rail relative z-[9] min-h-0 min-w-0 border-r border-line bg-[#f9fbfb] max-[800px]:fixed max-[800px]:inset-0 max-[800px]:z-[60] max-[800px]:w-full max-[800px]:border-0 max-[800px]:bg-white max-[800px]:transition-transform"
        :class="mobileFiltersOpen ? 'max-[800px]:translate-x-0' : 'max-[800px]:-translate-x-full'"
        aria-label="Graph controls"
      >
        <div class="rail-mobile-heading hidden h-[58px] items-center justify-between border-b border-line px-[18px] max-[800px]:flex">
          <strong>Graph controls</strong>
          <button class="plain-icon grid size-[34px] place-items-center rounded-lg border-0 bg-transparent text-muted hover:bg-soft hover:text-ink" aria-label="Close filters" @click="mobileFiltersOpen = false"><X :size="20" /></button>
        </div>
        <button class="collapse-rail absolute top-4 right-[-13px] z-[2] grid size-[26px] place-items-center rounded-full border border-line bg-white p-0 text-muted shadow-[0_3px_10px_rgba(22,43,51,.08)] hover:border-[#9fc4c1] hover:text-accent max-[1180px]:right-2 max-[800px]:hidden" :aria-label="leftCollapsed ? 'Expand controls' : 'Collapse controls'" @click="leftCollapsed = !leftCollapsed">
          <ChevronLeft v-if="!leftCollapsed" :size="17" /><ChevronRight v-else :size="17" />
        </button>
        <div class="rail-content h-full overflow-y-auto px-4 pt-5 pb-6 max-[800px]:block max-[800px]:h-[calc(100%-58px)] max-[800px]:px-5 max-[800px]:pt-2 max-[800px]:pb-[30px]" :class="leftCollapsed ? 'hidden max-[800px]:block' : 'max-[1180px]:hidden max-[800px]:block'">
          <section class="control-section border-b border-line pt-1 pb-[18px] max-[800px]:pt-2.5">
            <p class="section-label m-0 text-[9.5px] font-extrabold tracking-[.13em] text-muted uppercase">Graph view</p>
            <div class="select-wrap relative mt-2">
              <select class="graph-view-select h-[47px] w-full cursor-pointer appearance-none overflow-hidden rounded-[10px] border border-line-strong bg-white pr-10 pl-4 text-[12.5px] font-semibold tracking-[.01em] text-transparent text-ellipsis shadow-[0_2px_8px_rgba(24,46,55,.04)] outline-none transition-[border-color,box-shadow] hover:border-[#9fc4c1] focus:border-[#58a29c] focus:shadow-[0_0_0_3px_rgba(15,118,110,.09)]" :value="selectedView" aria-label="Graph view" @change="requestViewSwitch($event.target.value)">
                <option v-for="([name, graph]) in viewEntries" :key="name" :value="name">
                  {{ shortViewName(name) }} · {{ graph.nodes.length }}
                </option>
              </select>
              <span class="pointer-events-none absolute top-0 bottom-0 left-4 flex items-center text-[12.5px] font-semibold tracking-[.01em] text-ink" aria-hidden="true">{{ viewId(selectedView) }}</span>
              <ChevronDown :size="18" class="pointer-events-none absolute top-[14px] right-3 text-muted" />
            </div>
            <p class="section-note mt-2 mx-0.5 mb-0 text-[10.5px] text-muted">{{ currentGraph.nodes.length }} nodes · {{ currentGraph.links.length }} relationships</p>
          </section>

          <section class="control-section border-b border-line py-[18px]">
            <div class="section-heading mb-2 flex items-start justify-between gap-2.5">
              <div><p class="section-label m-0 text-[9.5px] font-extrabold tracking-[.13em] text-muted uppercase">Abstraction</p><span class="mt-1 block text-[10px] text-muted">Node type</span></div>
              <span class="size-key flex items-center gap-1 text-[9px] whitespace-nowrap text-muted"><i class="inline-block size-2.5 rounded-full border-2 border-[#7d9099]"></i> Size = relations</span>
            </div>
            <button
              v-for="name in abstractionOrder"
              :key="name"
              class="filter-row grid min-h-[34px] w-full cursor-pointer grid-cols-[20px_minmax(0,1fr)_auto_18px] items-center gap-[7px] rounded-[7px] border-0 bg-transparent px-1 py-[3px] text-left text-[11.5px] text-ink-soft hover:bg-[#eef4f5] max-[800px]:min-h-11"
              :class="!enabledAbstractions.has(name) ? 'opacity-40' : name === 'Pillar' ? 'cursor-default' : ''"
              :aria-pressed="enabledAbstractions.has(name)"
              :aria-disabled="name === 'Pillar'"
              :title="name === 'Pillar' ? 'Pillar nodes are always visible' : undefined"
              @click="toggleAbstraction(name)"
            >
              <span class="node-swatch" :data-kind="name" :style="{ '--swatch': abstractionColors[name] }"></span>
              <span>{{ name }}</span>
              <span class="filter-count font-mono text-[10px] text-muted">{{ abstractionCounts[name] || 0 }}</span>
              <span v-if="name !== 'Pillar'" class="filter-check grid size-4 place-items-center rounded border text-white" :class="enabledAbstractions.has(name) ? 'border-accent bg-accent' : 'border-line-strong bg-white'"><Check v-if="enabledAbstractions.has(name)" :size="13" /></span>
            </button>
          </section>

          <section class="control-section border-b border-line py-[18px]">
            <div class="section-heading mb-2 flex items-start justify-between gap-2.5">
              <div><p class="section-label m-0 text-[9.5px] font-extrabold tracking-[.13em] text-muted uppercase">Relationships</p><span class="mt-1 block text-[10px] text-muted">Edge type</span></div>
            </div>
            <button
              v-for="([name, count]) in relationTypes"
              :key="name"
              class="filter-row grid min-h-[34px] w-full cursor-pointer grid-cols-[20px_minmax(0,1fr)_auto_18px] items-center gap-[7px] rounded-[7px] border-0 bg-transparent px-1 py-[3px] text-left text-[11.5px] text-ink-soft hover:bg-[#eef4f5] max-[800px]:min-h-11"
              :class="!enabledRelations.has(name) ? 'opacity-40' : ''"
              :aria-pressed="enabledRelations.has(name)"
              @click="toggleRelation(name)"
            >
              <span class="line-swatch" :class="{ dashed: name !== 'ParentOf' }"></span>
              <span>{{ name }}</span>
              <span class="filter-count font-mono text-[10px] text-muted">{{ count }}</span>
              <span class="filter-check grid size-4 place-items-center rounded border text-white" :class="enabledRelations.has(name) ? 'border-accent bg-accent' : 'border-line-strong bg-white'"><Check v-if="enabledRelations.has(name)" :size="13" /></span>
            </button>
          </section>

          <section v-if="filtersActive" class="active-filter-summary mt-4 rounded-[9px] border border-[#bedbd8] bg-accent-soft p-3">
            <div class="flex items-center gap-1.5 text-[11px] text-accent-dark"><Filter :size="15" /><strong>Filters active</strong></div>
            <p class="mt-1 mb-2.5 text-[10.5px] text-[#53716f]">{{ filteredNodes.length }} of {{ currentGraph.nodes.length }} nodes visible</p>
            <button class="border-0 bg-transparent p-0 text-[10.5px] font-bold text-accent-dark underline" @click="clearFilters">Clear all</button>
          </section>
        </div>
      </aside>

      <section id="graph-stage" class="graph-stage relative min-w-0 overflow-hidden bg-canvas bg-[radial-gradient(#cbd8dc_1px,transparent_1px)] [background-size:22px_22px] max-[800px]:h-full max-[800px]:w-full" aria-label="CWE relationship graph" tabindex="-1">
        <div class="graph-topbar pointer-events-none absolute top-[17px] right-[22px] left-[22px] z-[4] flex items-center justify-between max-[800px]:top-[13px] max-[800px]:right-[13px] max-[800px]:left-[13px]">
          <nav class="breadcrumb pointer-events-auto flex max-w-[70%] items-center overflow-hidden rounded-lg border border-line/80 bg-white/92 px-2 py-1 font-mono text-[10.5px] whitespace-nowrap text-muted shadow-[0_4px_14px_rgba(24,46,55,.08)] backdrop-blur-[8px] max-[800px]:max-w-[calc(100%-94px)]" aria-label="Exploration path">
            <button class="cursor-pointer border-0 bg-transparent p-[3px] text-muted hover:text-accent hover:underline" @click="clearSelection">All nodes</button>
            <template v-for="(item, index) in trail" :key="`${item.id}-${index}`">
              <ChevronRight :size="13" />
              <button class="cursor-pointer border-0 bg-transparent p-[3px] text-muted hover:text-accent hover:underline" @click="navigateTrail(index)">{{ item.id }}</button>
            </template>
            <template v-if="selectedNodeId">
              <ChevronRight :size="13" />
              <span class="text-ink-soft">{{ selectedNodeId }}</span>
            </template>
          </nav>
          <button class="mobile-filter-button pointer-events-auto hidden min-h-9 items-center gap-1.5 rounded-lg border border-[#b8d4d1] bg-white/90 px-2.5 text-[10.5px] text-accent-dark shadow-[0_4px_12px_rgba(22,43,51,.06)] max-[800px]:inline-flex" @click="mobileFiltersOpen = true"><SlidersHorizontal :size="17" /> Filters</button>
        </div>

        <div ref="chartEl" class="chart absolute inset-0 size-full"></div>

        <div v-if="loading" class="graph-state absolute inset-0 z-[8] flex flex-col items-center justify-center gap-[7px] bg-canvas text-center text-[11px] text-muted">
          <span class="loading-orbit"><i></i></span>
          <strong class="text-[13px] text-ink">Preparing research graph</strong>
          <span>Loading CWE relationships and metadata…</span>
        </div>
        <div v-else-if="loadError" class="graph-state absolute inset-0 z-[8] flex flex-col items-center justify-center gap-[7px] bg-canvas text-center text-[11px] text-muted">
          <span class="state-icon mb-0.5 grid size-[42px] place-items-center rounded-full bg-accent-soft text-accent"><Network :size="22" /></span>
          <strong class="text-[13px] text-ink">Graph unavailable</strong>
          <span>{{ loadError }}</span>
          <button class="mt-1 cursor-pointer rounded-[7px] border-0 bg-accent px-3.5 py-2 text-[11px] text-white" @click="loadData">Retry</button>
        </div>
        <div v-else-if="!filteredNodes.length" class="graph-state absolute inset-0 z-[8] flex flex-col items-center justify-center gap-[7px] bg-canvas text-center text-[11px] text-muted">
          <span class="state-icon mb-0.5 grid size-[42px] place-items-center rounded-full bg-accent-soft text-accent"><Filter :size="22" /></span>
          <strong class="text-[13px] text-ink">No nodes match these filters</strong>
          <span>Restore all node and relationship types to continue exploring.</span>
          <button class="mt-1 cursor-pointer rounded-[7px] border-0 bg-accent px-3.5 py-2 text-[11px] text-white" @click="clearFilters">Show all nodes</button>
        </div>

        <div v-if="showGuide && !loading" class="first-run-guide absolute bottom-[74px] left-1/2 z-[5] grid w-[min(430px,calc(100%-40px))] -translate-x-1/2 grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-2.5 rounded-[11px] border border-[#b9d8d4] bg-white/97 p-[13px] shadow-[0_10px_35px_rgba(24,54,60,.14)] max-[800px]:bottom-[68px]">
          <div class="guide-icon grid size-[34px] place-items-center rounded-[9px] bg-accent-soft text-accent"><Network :size="21" /></div>
          <div><strong class="text-[11.5px]">Explore the CWE landscape</strong><p class="mt-1 mb-0 text-[10.5px] leading-[1.45] text-muted">Search for a weakness, drag to move, scroll to zoom, and select a node for details.</p></div>
          <button class="grid size-[26px] place-items-center rounded-md border-0 bg-transparent text-muted" aria-label="Dismiss guide" @click="dismissGuide"><X :size="16" /></button>
        </div>

        <div v-if="!selectedNodeId && !loading" class="inspect-hint pointer-events-none absolute top-1/2 right-5 z-[3] flex origin-right translate-x-1/2 -rotate-90 items-center gap-[7px] text-[10px] text-[#83949c] max-[800px]:hidden"><span class="size-[5px] rounded-full bg-accent"></span>Select a node to inspect its details</div>

        <div class="graph-footer pointer-events-none absolute right-[18px] bottom-4 left-5 z-[4] flex items-end justify-between max-[800px]:right-2.5 max-[800px]:bottom-2.5 max-[800px]:left-3">
          <div class="zoom-readout flex items-center gap-2 text-[9.5px] text-muted"><strong class="font-mono text-[10px] text-ink-soft">{{ Math.round(zoomLevel * 100) }}%</strong><span class="max-[800px]:hidden">Scroll to zoom · Drag to pan</span></div>
          <div class="canvas-tools pointer-events-auto flex items-center rounded-[9px] border border-line bg-white/95 p-[3px] shadow-[0_6px_18px_rgba(24,46,55,.1)]" aria-label="Canvas tools">
            <button class="grid size-8 place-items-center rounded-md border-0 bg-transparent text-ink-soft hover:bg-accent-soft hover:text-accent max-[800px]:size-9" aria-label="Zoom in" title="Zoom in" @click="zoomBy(1.2)"><Plus :size="18" /></button>
            <button class="grid size-8 place-items-center rounded-md border-0 bg-transparent text-ink-soft hover:bg-accent-soft hover:text-accent max-[800px]:size-9" aria-label="Zoom out" title="Zoom out" @click="zoomBy(0.82)"><Minus :size="18" /></button>
            <span class="mx-[3px] h-5 w-px bg-line"></span>
            <button class="grid size-8 place-items-center rounded-md border-0 bg-transparent text-ink-soft hover:bg-accent-soft hover:text-accent max-[800px]:size-9" aria-label="Fit graph" title="Fit graph" @click="fitGraph"><Focus :size="17" /></button>
            <button class="grid size-8 place-items-center rounded-md border-0 bg-transparent text-ink-soft hover:bg-accent-soft hover:text-accent max-[800px]:size-9 max-[480px]:hidden" aria-label="Reset view" title="Reset view" @click="resetView"><RotateCcw :size="17" /></button>
            <button class="grid size-8 place-items-center rounded-md border-0 bg-transparent text-ink-soft hover:bg-accent-soft hover:text-accent max-[800px]:size-9" aria-label="Fullscreen" title="Fullscreen" @click="toggleFullscreen"><Maximize2 :size="17" /></button>
          </div>
        </div>
      </section>

      <aside v-if="selectedNodeId" id="node-details" class="detail-panel z-[8] min-w-0 overflow-y-auto border-l border-line bg-white shadow-[-6px_0_24px_rgba(27,48,56,.05)] max-[800px]:fixed max-[800px]:right-0 max-[800px]:bottom-0 max-[800px]:left-0 max-[800px]:z-50 max-[800px]:w-full max-[800px]:rounded-t-[18px] max-[800px]:border max-[800px]:border-b-0 max-[800px]:shadow-[0_-12px_40px_rgba(23,43,51,.18)] max-[800px]:transition-[height]" :class="mobileDetailExpanded ? 'max-[800px]:h-[91vh]' : 'max-[800px]:h-[52vh]'" tabindex="-1" aria-label="Node details">
        <button class="detail-dragger sticky top-0 z-[4] hidden h-[22px] w-full place-items-center border-0 bg-white p-0 max-[800px]:grid" aria-label="Toggle detail panel height" @click="mobileDetailExpanded = !mobileDetailExpanded"><span class="h-1 w-[38px] rounded-full bg-[#c8d3d6]"></span></button>
        <header class="detail-header sticky top-0 z-[2] border-b border-line bg-white/97 px-6 pt-[22px] pb-[18px] backdrop-blur-[10px] max-[800px]:top-[22px] max-[800px]:px-[18px] max-[800px]:pt-2.5 max-[800px]:pb-[15px]">
          <div class="detail-id-row flex items-center justify-between">
            <span class="detail-id font-mono text-[11px] font-bold tracking-[.02em] text-accent">{{ selectedNodeId }}</span>
            <button class="plain-icon grid size-[34px] place-items-center rounded-lg border-0 bg-transparent text-muted hover:bg-soft hover:text-ink" aria-label="Close details" @click="clearSelection"><X :size="20" /></button>
          </div>
          <h2 class="mt-2.5 mb-3 text-[clamp(17px,1.3vw,21px)] leading-tight font-semibold tracking-[-.025em] max-[800px]:text-[17px]">{{ selectedNode?.name || 'Details unavailable' }}</h2>
          <div class="detail-meta flex flex-wrap items-center gap-1.5 text-[10px] text-muted">
            <span v-if="selectedNode?.status" class="inline-flex min-h-5 items-center rounded-full px-2 text-[9.5px] font-bold" :class="statusBadgeClass(selectedNode.status)" title="Catalog status">{{ selectedNode.status }}</span>
            <span v-if="selectedNode?.structure" class="inline-flex min-h-5 items-center rounded-full px-2 text-[9.5px] font-bold" :class="structureBadgeClass(selectedNode.structure)" title="Weakness structure">{{ selectedNode.structure }}</span>
            <span v-if="selectedNode?.abstraction" class="abstraction-badge inline-flex min-h-5 items-center rounded-full px-2 text-[9.5px] font-bold" :class="abstractionBadgeClass(selectedNode.abstraction)">{{ selectedNode.abstraction }}</span>
            <span class="ml-1">{{ relatedWeaknesses.length }} direct relationships</span>
          </div>
          <div class="detail-actions mt-4 flex gap-[7px] max-[480px]:grid max-[480px]:grid-cols-[1fr_auto]">
            <a class="inline-flex min-h-[37px] flex-1 items-center justify-center gap-1.5 rounded-lg border border-accent bg-accent px-3 text-[10.5px] font-semibold text-white no-underline hover:bg-accent-dark" :href="`https://cwe.mitre.org/data/definitions/${selectedNodeId.slice(4)}.html`" target="_blank" rel="noreferrer">
              Open official document <ArrowUpRight :size="16" />
            </a>
            <button class="inline-flex min-h-[37px] items-center justify-center gap-1.5 rounded-lg border border-line-strong bg-white px-3 text-[10.5px] font-semibold text-ink-soft hover:border-[#8eb9b5] hover:text-accent" @click="copyLink"><Clipboard :size="16" />Copy link</button>
          </div>
        </header>

        <div class="detail-body px-6 pb-9 max-[800px]:px-[18px] max-[800px]:pb-7">
          <section class="border-b border-line py-[21px]">
            <p class="section-label m-0 text-[9.5px] font-extrabold tracking-[.13em] text-muted uppercase">Description</p>
            <p v-if="selectedNode?.description" class="description mt-2.5 mb-0 text-xs leading-[1.72] text-[#3e515a]">{{ selectedNode.description }}</p>
            <div v-else class="missing-detail mt-2.5 rounded-lg bg-soft p-3 text-[11px] text-muted">Detailed metadata is not available for this entry.</div>
          </section>

          <section v-if="selectedNode?.vulnerability_mapping" class="border-b border-line py-[21px]">
            <p class="section-label m-0 text-[9.5px] font-extrabold tracking-[.13em] text-muted uppercase">Vulnerability mapping</p>
            <div class="mapping-status mt-2.5 flex gap-2.5 rounded-[9px] border p-3" :class="['Allowed', 'Allowed-with-Review'].includes(selectedNode.vulnerability_mapping) ? 'border-[#c3ded3] bg-[#f0f8f5]' : 'border-[#ead5b6] bg-[#fff8ed]'">
              <span class="grid size-6 shrink-0 place-items-center rounded-full text-white" :class="['Allowed', 'Allowed-with-Review'].includes(selectedNode.vulnerability_mapping) ? 'bg-[#398a69]' : 'bg-[#c5803b]'">
                <Check v-if="['Allowed', 'Allowed-with-Review'].includes(selectedNode.vulnerability_mapping)" :size="15" />
                <TriangleAlert v-else :size="15" />
              </span>
              <div><strong class="text-[11px] text-[#26654d]">{{ selectedNode.vulnerability_mapping }}</strong><p class="mt-1 mb-0 text-[10px] leading-[1.45] text-[#5d756c]">{{ mappingDescription(selectedNode.vulnerability_mapping) }}</p></div>
            </div>
            <div v-if="selectedNode?.mapping_rationale || selectedNode?.mapping_comments || selectedNode?.mapping_reasons?.length" class="mt-2.5 grid gap-2.5 rounded-[9px] border border-[#d9e3e5] bg-[#f7faf9] p-3">
              <div v-if="selectedNode?.mapping_rationale">
                <strong class="text-[10.5px] text-ink-soft">Official rationale</strong>
                <p class="mt-1 mb-0 text-[10.5px] leading-[1.55] text-[#536a72]">{{ mappingText(selectedNode.mapping_rationale) }}</p>
              </div>
              <div v-if="selectedNode?.mapping_comments">
                <strong class="text-[10.5px] text-ink-soft">Mapping guidance</strong>
                <p class="mt-1 mb-0 whitespace-pre-line text-[10.5px] leading-[1.55] text-[#536a72]">{{ mappingText(selectedNode.mapping_comments) }}</p>
              </div>
              <div v-if="selectedNode?.mapping_reasons?.length" class="flex flex-wrap items-center gap-1.5">
                <strong class="mr-0.5 text-[10.5px] text-ink-soft">Reason</strong>
                <span v-for="reason in selectedNode.mapping_reasons" :key="reason" class="inline-flex min-h-5 items-center rounded-full bg-[#e5f1ee] px-2 text-[9.5px] font-semibold text-[#34766a]">{{ reason }}</span>
              </div>
            </div>
          </section>

          <section v-if="relatedWeaknesses.length" class="border-b border-line py-[21px]">
            <div class="related-heading flex items-center justify-between"><p class="section-label m-0 text-[9.5px] font-extrabold tracking-[.13em] text-muted uppercase">Related weaknesses</p><span class="grid h-[21px] min-w-[21px] place-items-center rounded-full bg-soft font-mono text-[9px] text-muted">{{ relatedWeaknesses.length }}</span></div>
            <div class="related-list mt-2 overflow-hidden rounded-[9px] border border-line">
              <button class="grid min-h-[58px] w-full grid-cols-[60px_minmax(0,1fr)_auto] items-center gap-2 border-0 border-b border-line bg-white px-2.5 py-2 text-left last:border-b-0 hover:bg-[#f3f8f8]" v-for="item in relatedWeaknesses" :key="item.id" @click="selectNode(item.id)">
                <span class="related-id font-mono text-[11.5px] font-bold tracking-[.02em] text-accent-dark">{{ item.id }}</span>
                <span class="related-copy grid min-w-0 gap-1"><strong class="overflow-hidden text-[10.5px] leading-[1.3] font-semibold whitespace-nowrap text-ellipsis">{{ item.node.name }}</strong><small class="text-[9.5px] text-muted">{{ item.nature }}</small></span>
                <ChevronRight :size="17" class="text-[#93a2a8]" />
              </button>
            </div>
          </section>

          <section class="accessible-relations py-[21px]" aria-label="Current node relationship summary">
            <p class="section-label m-0 text-[9.5px] font-extrabold tracking-[.13em] text-muted uppercase">Graph context</p>
            <p class="mt-2 mb-0 text-[10.5px] leading-[1.55] text-muted">{{ selectedNodeId }} is visible in {{ shortViewName(selectedView) }}. Use the related weaknesses above to continue exploring without interacting with the graph canvas.</p>
          </section>
        </div>
      </aside>
    </main>

    <div v-if="mobileFiltersOpen" class="drawer-scrim fixed inset-0 z-[55] hidden bg-[rgba(15,35,42,.3)] max-[800px]:block" @click="mobileFiltersOpen = false"></div>

    <div v-if="modal" class="modal-backdrop fixed inset-0 z-80 grid place-items-center bg-[rgba(11,30,37,.35)] p-5 backdrop-blur-[3px]" role="presentation" @click.self="modal = ''">
      <section class="modal relative w-full rounded-[14px] border border-line bg-white shadow-[0_22px_70px_rgba(15,35,43,.24)]" :class="modal === 'help' ? 'max-w-[560px] p-8' : 'max-w-[430px] p-7'" role="dialog" aria-modal="true" :aria-labelledby="`${modal}-title`">
        <button class="modal-close absolute top-[13px] right-[13px] grid size-[34px] place-items-center rounded-lg border-0 bg-transparent text-muted hover:bg-soft" aria-label="Close dialog" @click="modal = ''"><X :size="20" /></button>
        <template v-if="modal === 'data'">
          <span class="modal-icon mb-4 grid size-11 place-items-center rounded-xl bg-accent-soft text-accent"><Info :size="22" /></span>
          <p class="section-label m-0 text-[11px] font-extrabold tracking-[.13em] text-muted uppercase">Data source</p>
          <h2 id="data-title" class="mt-1.5 mb-2.5 text-[24px] tracking-[-.025em]">About this data</h2>
          <p class="m-0 text-sm leading-[1.65] text-ink-soft">This site visualizes the CWE Research Concepts view (View ID 1000), generated from the official MITRE CWE catalog.</p>
          <dl class="my-5 border-t border-line"><div class="flex justify-between border-b border-line py-2.5 text-[13px]"><dt class="text-muted">Catalog version</dt><dd class="m-0 font-semibold">CWE {{ dataInfo.cwe_version }}</dd></div><div class="flex justify-between border-b border-line py-2.5 text-[13px]"><dt class="text-muted">Catalog updated</dt><dd class="m-0 font-semibold">{{ dataInfo.updated_at }}</dd></div><div class="flex justify-between border-b border-line py-2.5 text-[13px]"><dt class="text-muted">Research view</dt><dd class="m-0 font-semibold">View {{ dataInfo.view_id }}</dd></div><div class="flex justify-between border-b border-line py-2.5 text-[13px]"><dt class="text-muted">Weakness metadata</dt><dd class="m-0 font-semibold">{{ searchableEntries.length.toLocaleString() }} entries</dd></div><div class="flex justify-between border-b border-line py-2.5 text-[13px]"><dt class="text-muted">Graph views</dt><dd class="m-0 font-semibold">{{ viewEntries.length }} views</dd></div><div class="flex justify-between border-b border-line py-2.5 text-[13px]"><dt class="text-muted">Source</dt><dd class="m-0 font-semibold">MITRE CWE Catalog</dd></div></dl>
          <a class="modal-link inline-flex items-center gap-2 text-[13px] font-bold text-accent no-underline" href="https://cwe.mitre.org/data/definitions/1000.html" target="_blank" rel="noreferrer">View Research Concepts on MITRE <ExternalLink :size="16" /></a>
        </template>
        <template v-else-if="modal === 'help'">
          <span class="modal-icon mb-4 grid size-11 place-items-center rounded-xl bg-accent-soft text-accent"><CircleHelp :size="22" /></span>
          <p class="section-label m-0 text-[11px] font-extrabold tracking-[.13em] text-muted uppercase">Quick guide</p>
          <h2 id="help-title" class="mt-1.5 mb-2.5 text-[24px] tracking-[-.025em]">Navigate the graph</h2>
          <div class="shortcut-list mt-[18px] grid grid-cols-2 gap-px overflow-hidden rounded-[9px] border border-line bg-line max-[480px]:grid-cols-1"><div class="grid gap-1 bg-white p-3"><strong class="text-[13px]">Select</strong><span class="text-xs text-muted">Click or tap a node</span></div><div class="grid gap-1 bg-white p-3"><strong class="text-[13px]">Move</strong><span class="text-xs text-muted">Drag the canvas</span></div><div class="grid gap-1 bg-white p-3"><strong class="text-[13px]">Zoom</strong><span class="text-xs text-muted">Scroll, pinch, or use the controls</span></div><div class="grid gap-1 bg-white p-3"><strong class="text-[13px]">Close</strong><span class="text-xs text-muted">Press Esc</span></div></div>
        </template>
        <template v-else-if="modal === 'relations'">
          <span class="modal-icon mb-4 grid size-11 place-items-center rounded-xl bg-[#fff3df] text-[#b66d1f]"><TriangleAlert :size="22" /></span>
          <p class="section-label m-0 text-[11px] font-extrabold tracking-[.13em] text-muted uppercase">Relationship filters</p>
          <h2 id="relations-title" class="mt-1.5 mb-2.5 text-[24px] tracking-[-.025em]">Remove all relationship types?</h2>
          <p class="m-0 text-sm leading-[1.65] text-ink-soft">The nodes currently on the canvas will lose all edges. Do you want to continue?</p>
          <div class="mt-5 flex justify-end gap-2">
            <button class="min-h-9 rounded-lg border border-line-strong bg-white px-3 text-[13px] text-ink-soft" @click="modal = ''">Cancel</button>
            <button class="min-h-9 rounded-lg border border-accent bg-accent px-3 text-[13px] font-semibold text-white" @click="confirmRelationFilterChange">Confirm</button>
          </div>
        </template>
        <template v-else-if="modal === 'all'">
          <span class="modal-icon mb-4 grid size-11 place-items-center rounded-xl bg-[#fff3df] text-[#b66d1f]"><TriangleAlert :size="22" /></span>
          <p class="section-label m-0 text-[11px] font-extrabold tracking-[.13em] text-muted uppercase">Large graph view</p>
          <h2 id="all-title" class="mt-1.5 mb-2.5 text-[24px] tracking-[-.025em]">Load all weaknesses?</h2>
          <p class="m-0 text-sm leading-[1.65] text-ink-soft">This view loads {{ graphs[pendingView].nodes.length.toLocaleString() }} nodes and {{ graphs[pendingView].links.length.toLocaleString() }} relationships. It may make your browser slow or temporarily unresponsive.</p>
          <div class="mt-5 flex justify-end gap-2">
            <button class="min-h-9 rounded-lg border border-line-strong bg-white px-3 text-[13px] text-ink-soft" @click="modal = ''">Cancel</button>
            <button class="min-h-9 rounded-lg border border-accent bg-accent px-3 text-[13px] font-semibold text-white" @click="confirmViewSwitch">Load graph</button>
          </div>
        </template>
        <template v-else>
          <span class="modal-icon mb-4 grid size-11 place-items-center rounded-xl bg-accent-soft text-accent"><Network :size="22" /></span>
          <p class="section-label m-0 text-[11px] font-extrabold tracking-[.13em] text-muted uppercase">Switch graph view</p>
          <h2 id="view-title" class="mt-1.5 mb-2.5 text-[24px] tracking-[-.025em]">Current node is not in this view</h2>
          <p class="m-0 text-sm leading-[1.65] text-ink-soft">{{ selectedNodeId }} will be closed when you switch to {{ shortViewName(pendingView) }}. Your filters and exploration path remain available.</p>
          <div class="mt-5 flex justify-end gap-2">
            <button class="min-h-9 rounded-lg border border-line-strong bg-white px-3 text-[13px] text-ink-soft" @click="modal = ''">Cancel</button>
            <button class="min-h-9 rounded-lg border border-accent bg-accent px-3 text-[13px] font-semibold text-white" @click="confirmViewSwitch">Switch view</button>
          </div>
        </template>
      </section>
    </div>

    <transition name="toast"><div v-if="toast" class="toast fixed bottom-[22px] left-1/2 z-[100] flex min-h-10 -translate-x-1/2 items-center gap-[7px] rounded-[9px] bg-[#183b3a] px-3.5 text-[11px] text-white shadow-[0_9px_30px_rgba(18,42,48,.22)]" role="status"><Check :size="16" />{{ toast }}</div></transition>
  </div>
</template>
