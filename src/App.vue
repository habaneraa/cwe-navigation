<template>
  <div class="flex h-screen">
    <!-- 左侧边栏 -->
    <div class="w-1/3 min-w-[250px] max-w-[800px] bg-gray-100 p-4 overflow-y-auto space-y-4">
      <h2 class="text-3xl font-bold">Common Weakness Enumeration Tree Navigation</h2>

      <h3 class="text-xl font-semibold">CWE View: Research Concepts</h3>

      <div class="flex justify-center items-center">
        <button
          @click="goToGitHub"
          class="bg-gray-300 hover:bg-gray-400 font-bold py-3 px-6 rounded-lg shadow-lg w-full max-w-md text-sm"
        >
          View Source on GitHub
        </button>
      </div>

      <h3>Choose a graph visualization:</h3>

      <select v-model="selectedChart" @change="updateChart" class="w-full p-2 border rounded mb-4">
        <option v-for="chartName in chartNames" :key="chartName" :value="chartName">
          {{ chartName }}
        </option>
      </select>

      <!-- 节点信息显示区域 -->
      <div v-if="selectedNodeInfo" class="mt-4 bg-white p-4 rounded shadow">
        <h3 class="font-bold text-lg mb-2">{{ selectedNodeName }}: {{ selectedNodeInfo.name }}</h3>
        <div class="mb-2">
          <span class="font-semibold">
            <a
              :href="selectedNodeInfo.link"
              target="_blank"
              rel="noopener noreferrer"
              class="text-blue-600 hover:text-blue-800 hover:underline transition duration-300 ease-in-out inline-flex items-center"
            >
              <span>Official document</span>
              <svg
                class="w-4 h-4 ml-1"
                fill="currentColor"
                viewBox="0 0 20 20"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M11 3a1 1 0 100 2h2.586l-6.293 6.293a1 1 0 101.414 1.414L15 6.414V9a1 1 0 102 0V4a1 1 0 00-1-1h-5z"
                ></path>
                <path
                  d="M5 5a2 2 0 00-2 2v8a2 2 0 002 2h8a2 2 0 002-2v-3a1 1 0 10-2 0v3H5V7h3a1 1 0 000-2H5z"
                ></path>
              </svg>
            </a>
          </span>
        </div>
        <div class="mb-2">
          <span class="font-semibold">Abstraction:</span>
          <span class="ml-2">{{ selectedNodeInfo.abstraction }}</span>
        </div>
        <div class="mb-2">
          <span class="font-semibold">Description:</span>
          <p class="mt-1 text-sm">{{ selectedNodeInfo.description }}</p>
        </div>
        <div class="mb-2">
          <span class="font-semibold">Vulnerability Mapping:</span>
          <span class="ml-2">{{ selectedNodeInfo.vulnerability_mapping }}</span>
        </div>
        <div v-if="selectedNodeInfo.related_weaknesses.length > 0">
          <span class="font-semibold">Related Weaknesses:</span>
          <ul class="list-disc list-inside mt-1 text-sm">
            <li v-for="weakness in selectedNodeInfo.related_weaknesses" :key="weakness">
              {{ weakness }}
            </li>
          </ul>
        </div>
      </div>
      <div v-else class="mt-4 text-gray-500 italic">Click on a node to view its information</div>
    </div>

    <!-- 主要内容区域 -->
    <div class="flex-1">
      <div ref="chartContainer" class="w-full h-full"></div>
    </div>
  </div>
</template>

<style scoped>
.overflow-y-auto {
  scrollbar-width: thin;
  scrollbar-color: #cbd5e0 #edf2f7;
}

.overflow-y-auto::-webkit-scrollbar {
  width: 8px;
}

.overflow-y-auto::-webkit-scrollbar-track {
  background: #edf2f7;
}

.overflow-y-auto::-webkit-scrollbar-thumb {
  background-color: #cbd5e0;
  border-radius: 4px;
  border: 2px solid #edf2f7;
}
</style>

<script>
import { onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts'

export default {
  name: 'ChartPage',

  setup() {
    const chartContainer = ref(null)
    const chart = ref(null)
    const chartData = ref({})
    const selectedChart = ref('')
    const chartNames = ref([])
    const selectedNodeInfo = ref(null)
    const selectedNodeName = ref('')
    const nodeMetadata = ref({})

    // 从JSON文件加载数据
    const loadChartData = async () => {
      try {
        const response1 = await fetch('/cwe-navigation/graph_data.json')
        chartData.value = await response1.json()
        chartNames.value = Object.keys(chartData.value)
        selectedChart.value = chartNames.value[2]

        const response2 = await fetch('/cwe-navigation/cwe_metadata.json')
        nodeMetadata.value = await response2.json()

        console.log('Chart data loaded successfully.')
      } catch (error) {
        console.error('Load data failed:', error)
      }
    }

    // 初始化ECharts实例
    const initChart = () => {
      if (chartContainer.value) {
        chart.value = echarts.init(chartContainer.value, null, { renderer: 'svg' })
        chart.value.on('click', handleChartClick)
      }
    }

    // 处理图表点击事件
    const handleChartClick = (params) => {
      if (params.componentType === 'series' && params.seriesType === 'graph') {
        if (params.dataType === 'node') {
          // 点击到了图的节点上
          console.log('Clicked:', params.data.name)
          selectedNodeName.value = params.data.name
          selectedNodeInfo.value = nodeMetadata.value[params.data.name]
          selectedNodeInfo.value.link =
            'https://cwe.mitre.org/data/definitions/' + params.data.name.substring(4) + '.html'
        } else {
          // 点击到了其他地方，清除选中状态
          selectedNodeInfo.value = null
        }
      }
    }

    // 更新图表
    const updateChart = () => {
      if (chart.value && selectedChart.value) {
        const option = generateChartOption(chartData.value[selectedChart.value])
        chart.value.setOption(option)
      }
    }

    // 生成ECharts配置项
    const generateChartOption = (graph_data) => {
      return {
        legend: {
          data: graph_data.abstractions
        },
        tooltip: {},
        series: [
          {
            type: 'graph',
            layout: 'force',
            animation: false,
            roam: true,
            draggable: true,
            label: {
              position: 'right',
              formatter: '{b}'
            },
            data: graph_data.nodes,
            categories: graph_data.categories,
            force: {
              edgeLength: 10,
              repulsion: 10,
              gravity: 0.02
            },
            edges: graph_data.links,

            emphasis: {
              focus: 'adjacency', // Highlight adjacent nodes and edges
              lineStyle: {
                opacity: 1, // Set opacity of highlighted edges
                width: 2 // Optionally set the width of highlighted edges
              },
              itemStyle: {
                borderColor: '#aa0000', // Optionally set border color of highlighted nodes
                borderWidth: 2 // Optionally set border width of highlighted nodes
              }
            }
          }
        ]
      }
    }

    const goToGitHub = () => {
      window.open('https://github.com/habaneraa/cwe-navigation', '_blank')
    }

    onMounted(async () => {
      await loadChartData()
      initChart()
      updateChart()
    })

    watch(selectedChart, updateChart)

    return {
      chartContainer,
      selectedChart,
      chartNames,
      updateChart,
      selectedNodeName,
      selectedNodeInfo,
      goToGitHub
    }
  }
}
</script>
