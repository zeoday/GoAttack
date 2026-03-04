<template>
  <div class="container">
    <Breadcrumb :items="['menu.vuln', 'menu.vuln.pocs']" />
    <a-card class="general-card" :title="$t('menu.vuln.pocs')">
      <template #extra>
        <a-space>
          <template v-if="!batchMode">
            <a-button @click="toggleBatchMode">
              <template #icon>
                <icon-check-square />
              </template>
              批量操作
            </a-button>
            <a-button type="primary" @click="handleTriggerUpload" :loading="scanLoading">
              <template #icon>
                <icon-sync />
              </template>
              批量导入
            </a-button>
            <input type="file" ref="fileInputRef" webkitdirectory directory multiple style="display: none" @change="handleFilesSelected" />
            <a-button @click="handleManualImport">
              <template #icon>
                <icon-plus />
              </template>
              手动导入
            </a-button>
          </template>
          <template v-else>
            <a-tag color="blue">已选择 {{ selectedKeys.length }} �?/a-tag>
            <a-button type="primary" :disabled="selectedKeys.length === 0" @click="handleBatchVerify">
              <template #icon>
                <icon-play-arrow />
              </template>
              批量验证
            </a-button>
            <a-button status="danger" :disabled="selectedKeys.length === 0" @click="handleBatchDelete">
              <template #icon>
                <icon-delete />
              </template>
              批量删除
            </a-button>
            <a-button @click="cancelBatchMode">取消</a-button>
          </template>
        </a-space>
      </template>

      <a-row>
        <a-col :flex="1">
          <a-form :model="formModel" :label-col-props="{ span: 8 }" :wrapper-col-props="{ span: 16 }" label-align="left">
            <a-row :gutter="16">
              <a-col :span="6">
                <a-form-item field="name" label="POC名称">
                  <a-input v-model="formModel.name" placeholder="搜索POC名称" />
                </a-form-item>
              </a-col>
              <a-col :span="6">
                <a-form-item field="cve_id" label="CVE编号">
                  <a-input v-model="formModel.cve_id" placeholder="搜索CVE编号" />
                </a-form-item>
              </a-col>
              <a-col :span="6">
                <a-form-item field="cnvd_id" label="CNVD编号">
                  <a-input v-model="formModel.cnvd_id" placeholder="搜索CNVD编号" />
                </a-form-item>
              </a-col>
              <a-col :span="6">
                <a-form-item field="severity" label="危害等级">
                  <a-select v-model="formModel.severity" placeholder="请选择危害等级" allow-clear>
                    <a-option value="严重">严重</a-option>
                    <a-option value="高危">高危</a-option>
                    <a-option value="中危">中危</a-option>
                    <a-option value="低危">低危</a-option>
                    <a-option value="信息">信息</a-option>
                  </a-select>
                </a-form-item>
              </a-col>
            </a-row>
          </a-form>
        </a-col>
        <a-divider style="height: 32px" direction="vertical" />
        <a-col :flex="'86px'" style="text-align: right">
          <a-space direction="vertical" :size="18">
            <a-button type="primary" @click="fetchData">
              <template #icon>
                <icon-search />
              </template>
              查询
            </a-button>
            <a-button @click="reset">
              <template #icon>
                <icon-refresh />
              </template>
              重置
            </a-button>
          </a-space>
        </a-col>
      </a-row>
      <a-divider style="margin-top: 0" />
      <a-table
        row-key="id"
        :loading="loading"
        :pagination="pagination"
        :columns="columns"
        :data="renderData"
        :bordered="false"
        :row-selection="batchMode ? rowSelection : undefined"
        v-model:selectedKeys="selectedKeys"
        size="medium"
        @page-change="onPageChange"
        @page-size-change="onPageSizeChange"
        @sorter-change="onSorterChange"
      >
        <template #severity="{ record }">
          <a-tag :color="getSeverityColor(record.severity)">
            {{ getSeverityText(record.severity) }}
          </a-tag>
        </template>
        <template #cve_id="{ record }">
          <span :style="{ color: record.cve_id === '-' ? 'var(--color-text-3)' : 'inherit' }">
            {{ record.cve_id }}
          </span>
        </template>
        <template #cnvd_id="{ record }">
          <span :style="{ color: record.cnvd_id === '-' ? 'var(--color-text-3)' : 'inherit' }">
            {{ record.cnvd_id || '-' }}
          </span>
        </template>
        <template #author="{ record }">
          <span :title="record.author">{{ getFirstAuthor(record.author) }}</span>
        </template>
        <template #operations="{ record }">
          <a-space>
            <a-button type="text" size="small" @click="showDetail(record)">查看</a-button>
            <a-button type="text" size="small" status="danger" @click="handleDelete(record)">删除</a-button>
          </a-space>
        </template>
      </a-table>
    </a-card>

    <!-- POC详情弹窗 -->
    <a-modal v-model:visible="detailVisible" title="POC详细信息" width="800px" :footer="false">
      <div v-if="currentDetail">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="POC名称" :span="2">{{ currentDetail.name }}</a-descriptions-item>
          <a-descriptions-item label="模板ID" :span="2">{{ currentDetail.template_id }}</a-descriptions-item>
          <a-descriptions-item label="CVE编号">{{ currentDetail.cve_id }}</a-descriptions-item>
          <a-descriptions-item label="危害等级">
            <a-tag :color="getSeverityColor(currentDetail.severity)">
              {{ getSeverityText(currentDetail.severity) }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="作�?>{{ currentDetail.author || '-' }}</a-descriptions-item>
          <a-descriptions-item label="分类">{{ currentDetail.category }}</a-descriptions-item>
          <a-descriptions-item label="协议">{{ currentDetail.protocol }}</a-descriptions-item>
          <a-descriptions-item label="创建时间">{{ formatTime(currentDetail.created_at) }}</a-descriptions-item>
          <a-descriptions-item label="标签" :span="2">
            <a-space wrap v-if="getTagsArray(currentDetail.tags).length > 0">
              <a-tag v-for="tag in getTagsArray(currentDetail.tags)" :key="tag" color="arcoblue" size="small">{{ tag }}</a-tag>
            </a-space>
            <span v-else style="color: var(--color-text-3)">-</span>
          </a-descriptions-item>
        </a-descriptions>

        <div style="margin-top: 20px">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px">
            <h3 style="margin: 0; font-size: 16px">POC 模板内容</h3>
            <a-button type="primary" size="small" @click="handleUpdateTemplate" :loading="updateLoading">保存修改</a-button>
          </div>
          <a-textarea
            v-model="currentDetail.template_content"
            :auto-size="{ minRows: 15, maxRows: 25 }"
            style="font-family: monospace; font-size: 12px; background-color: var(--color-fill-1)"
            placeholder="POC 模板内容为空"
          />
        </div>
      </div>
    </a-modal>

    <!-- 手动导入弹窗 -->
    <a-modal v-model:visible="manualVisible" title="手动导入POC模板" width="900px" @cancel="handleManualCancel">
      <a-tabs v-model:active-key="manualTabKey" type="rounded">
        <!-- Tab 1: 直接粘贴YAML -->
        <a-tab-pane key="yaml" title="YAML模板">
          <div style="margin-bottom: 10px">
            <span style="font-weight: bold">YAML 模板内容</span>
          </div>
          <a-textarea
            v-model="manualContent"
            placeholder="请粘�?Nuclei YAML 格式的模板内�?.."
            :auto-size="{ minRows: 20, maxRows: 30 }"
            style="font-family: monospace; font-size: 12px; background-color: var(--color-fill-1)"
          />
        </a-tab-pane>

        <!-- Tab 2: HTTP请求包转�?-->
        <a-tab-pane key="http" title="HTTP请求包转�?>
          <!-- Step 1: 输入HTTP请求�?+ 配置 -->
          <div v-show="httpStep === 1">
            <a-row :gutter="16">
              <a-col :span="12">
                <div style="margin-bottom: 10px">
                  <span style="font-weight: bold">原始HTTP请求�?/span>
                  <a-tooltip content="粘贴完整的HTTP请求包，包括请求行、请求头和请求体">
                    <icon-question-circle style="margin-left: 4px; color: var(--color-text-3); cursor: help" />
                  </a-tooltip>
                </div>
                <a-textarea
                  v-model="httpRawContent"
                  placeholder='粘贴HTTP请求包，例如�?#10;POST /api/login HTTP/1.1&#10;Host: example.com&#10;Content-Type: application/json&#10;&#10;{"user":"admin","pass":"123"}'
                  :auto-size="{ minRows: 25, maxRows: 100 }"
                  style="font-family: monospace; font-size: 12px; background-color: var(--color-fill-1)"
                />
              </a-col>
              <a-col :span="12">
                <div style="margin-bottom: 10px">
                  <span style="font-weight: bold">转换配置</span>
                </div>
                <a-form :model="httpConvertForm" layout="vertical" size="small">
                  <a-form-item label="POC名称">
                    <a-input v-model="httpConvertForm.poc_name" placeholder="可选，自定义POC名称" />
                  </a-form-item>
                  <a-form-item label="作�?>
                    <a-input v-model="httpConvertForm.author" placeholder="可选，默认 GoAttack" />
                  </a-form-item>
                  <a-form-item label="危害等级">
                    <a-select v-model="httpConvertForm.severity" placeholder="默认 medium">
                      <a-option value="critical">严重 (critical)</a-option>
                      <a-option value="high">高危 (high)</a-option>
                      <a-option value="medium">中危 (medium)</a-option>
                      <a-option value="low">低危 (low)</a-option>
                      <a-option value="info">信息 (info)</a-option>
                    </a-select>
                  </a-form-item>
                  <a-form-item label="描述">
                    <a-input v-model="httpConvertForm.description" placeholder="可选，POC描述信息" />
                  </a-form-item>
                  <a-form-item label="匹配方式">
                    <a-select v-model="httpConvertForm.match_type" placeholder="默认状态码匹配">
                      <a-option value="status">状态码匹配</a-option>
                      <a-option value="word">关键词匹�?/a-option>
                      <a-option value="regex">正则匹配</a-option>
                    </a-select>
                  </a-form-item>
                  <a-form-item label="匹配�?>
                    <a-input v-model="httpConvertForm.match_value" :placeholder="getMatchPlaceholder()" />
                  </a-form-item>
                </a-form>
              </a-col>
            </a-row>
          </div>
          <!-- Step 2: 生成结果 -->
          <div v-show="httpStep === 2">
            <div v-if="convertedInfo" style="margin-bottom: 12px">
              <a-alert type="success">
                <template #title>解析成功</template>
                方法: {{ convertedInfo.method }} | 路径: {{ convertedInfo.path }} | Host: {{ convertedInfo.host }} | 请求�?
                {{ convertedInfo.headers_count }}�?| 请求�? {{ convertedInfo.has_body ? '�? : '�? }}
              </a-alert>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px">
              <span style="font-weight: bold">生成�?YAML 模板（可编辑�?/span>
              <a-space>
                <a-button size="small" @click="handleCopyYaml">
                  <template #icon><icon-copy /></template>
                  复制
                </a-button>
                <a-button type="primary" size="small" @click="handleUseConverted">使用此模板导�?/a-button>
              </a-space>
            </div>
            <a-textarea
              v-model="convertedYaml"
              :auto-size="{ minRows: 20, maxRows: 30 }"
              style="font-family: monospace; font-size: 12px; background-color: var(--color-fill-1)"
            />
          </div>
        </a-tab-pane>
      </a-tabs>
      <template #footer>
        <a-space>
          <a-button @click="handleManualCancel">取消</a-button>
          <!-- HTTP转换Tab的分步按�?-->
          <template v-if="manualTabKey === 'http'">
            <a-button v-if="httpStep === 2" @click="httpStep = 1">
              <template #icon><icon-left /></template>
              上一�?
            </a-button>
            <a-button
              v-if="httpStep === 1"
              type="primary"
              :loading="convertLoading"
              :disabled="!httpRawContent.trim()"
              @click="handleConvertHTTP"
            >
              <template #icon><icon-swap /></template>
              生成 YAML 模板
            </a-button>
          </template>
          <!-- YAML Tab的导入按�?-->
          <a-button
            v-if="manualTabKey === 'yaml'"
            type="primary"
            :disabled="!manualContent.trim()"
            @click="handleSaveManual"
            :loading="saveManualLoading"
          >
            开始导�?
          </a-button>
        </a-space>
      </template>
    </a-modal>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { Message, Modal } from '@arco-design/web-vue'
import { useRouter } from 'vue-router'
import {
  IconSync,
  IconSearch,
  IconRefresh,
  IconPlus,
  IconCheckSquare,
  IconDelete,
  IconPlayArrow,
  IconQuestionCircle,
  IconSwap,
  IconCopy,
  IconLeft,
} from '@arco-design/web-vue/es/icon'
import {
  getPocTemplateList,
  getPocTemplateDetail,
  updatePocTemplate,
  deletePocTemplate,
  batchDeletePocs,
  scanAndImportPocs,
  uploadDirectoryPocs,
  saveManualPoc,
  convertHTTPToYaml,
  type PocTemplate,
  type ConvertHTTPToYamlResponse,
} from '@/api/poc'

const router = useRouter()
const loading = ref(false)
const scanLoading = ref(false)
const updateLoading = ref(false)
const saveManualLoading = ref(false)
const convertLoading = ref(false)
const detailVisible = ref(false)
const manualVisible = ref(false)
const fileInputRef = ref<HTMLInputElement | null>(null)
const manualTabKey = ref('yaml')
const httpStep = ref(1)
const manualContent = ref('')
const httpRawContent = ref('')
const convertedYaml = ref('')
const convertedInfo = ref<ConvertHTTPToYamlResponse['parsed_info'] | null>(null)
const currentDetail = ref<PocTemplate | null>(null)

const httpConvertForm = reactive({
  poc_name: '',
  severity: 'medium',
  description: '',
  author: '',
  match_type: 'status',
  match_value: '',
})
const renderData = ref<PocTemplate[]>([])

// 批量操作相关
const batchMode = ref(false)
const selectedKeys = ref<number[]>([])

const rowSelection = reactive({
  type: 'checkbox',
  showCheckedAll: true,
  onlyCurrent: false,
})

const formModel = reactive({
  name: '',
  cve_id: '',
  cnvd_id: '',
  severity: '',
})

const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
  showTotal: true,
  showPageSize: true,
})

const sorter = reactive({
  field: 'id',
  direction: 'asc',
})

// --- 辅助函数 ---
const getFirstAuthor = (author: string) => {
  if (!author) return '-'
  const authors = author.split(',')
  return authors[0].trim()
}

const getSeverityColor = (severity: string) => {
  if (!severity) return 'gray'
  const s = severity.toLowerCase()
  const colors: Record<string, string> = {
    严重: 'red',
    critical: 'red',
    高危: 'orange',
    high: 'orange',
    中危: 'gold',
    medium: 'gold',
    low: 'blue',
    低危: 'blue',
    info: 'gray',
    信息: 'gray',
    安全: 'green',
    safe: 'green',
  }
  return colors[s] || colors[severity] || 'gray'
}

const getSeverityText = (severity: string) => {
  if (!severity) return '-'
  const map: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
    safe: '安全',
  }
  return map[severity.toLowerCase()] || severity
}

const getTagsArray = (tags: any): string[] => {
  if (!tags) return []
  if (Array.isArray(tags)) return tags
  if (typeof tags === 'string') {
    try {
      const parsed = JSON.parse(tags)
      if (Array.isArray(parsed)) return parsed
      return tags
        .split(',')
        .map((t: string) => t.trim())
        .filter(Boolean)
    } catch (e) {
      return tags
        .split(',')
        .map((t: string) => t.trim())
        .filter(Boolean)
    }
  }
  return []
}

const formatTime = (timeStr: string) => {
  if (!timeStr || timeStr === '0001-01-01T00:00:00Z') return '-'
  try {
    const date = new Date(timeStr)
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch (e) {
    return timeStr
  }
}

// --- 数据获取与表格逻辑 ---
const fetchData = async () => {
  loading.value = true
  try {
    const { data } = await getPocTemplateList({
      page: pagination.current,
      pageSize: pagination.pageSize,
      name: formModel.name || undefined,
      cve_id: formModel.cve_id || undefined,
      cnvd_id: formModel.cnvd_id || undefined,
      severity: formModel.severity || undefined,
      sort: sorter.field,
      order: sorter.direction,
    })

    renderData.value = data.list || []
    pagination.total = data.total || 0
  } catch (err: any) {
    // 拦截器已处理
  } finally {
    loading.value = false
  }
}

const reset = () => {
  formModel.name = ''
  formModel.cve_id = ''
  formModel.cnvd_id = ''
  formModel.severity = ''
  pagination.current = 1
  fetchData()
}

const onPageChange = (page: number) => {
  pagination.current = page
  fetchData()
}

const onPageSizeChange = (pageSize: number) => {
  pagination.pageSize = pageSize
  pagination.current = 1
  fetchData()
}

const onSorterChange = (dataIndex: string, direction: string) => {
  sorter.field = dataIndex
  sorter.direction = direction === 'ascend' ? 'asc' : 'desc'
  fetchData()
}

// --- 弹窗与详情操�?---
const showDetail = async (record: PocTemplate) => {
  try {
    const { data } = await getPocTemplateDetail(record.id)
    currentDetail.value = data
    detailVisible.value = true
  } catch (err) {
    Message.error('获取详情失败')
  }
}

const handleUpdateTemplate = async () => {
  if (!currentDetail.value) return
  updateLoading.value = true
  try {
    await updatePocTemplate(currentDetail.value.id, {
      template_content: currentDetail.value.template_content,
    })
    Message.success('保存成功')
  } catch (err) {
    // 拦截器已处理
  } finally {
    updateLoading.value = false
  }
}

const handleDelete = async (record: PocTemplate) => {
  try {
    await deletePocTemplate(record.id)
    Message.success('删除成功')
    fetchData()
  } catch (err: any) {
    // 拦截器已处理
  }
}

// --- 批量操作 ---
const toggleBatchMode = () => {
  batchMode.value = true
}

const cancelBatchMode = () => {
  batchMode.value = false
  selectedKeys.value = []
}

const handleBatchDelete = async () => {
  if (selectedKeys.value.length === 0) return
  Modal.confirm({
    title: '确认删除',
    content: `确认要删除选中�?${selectedKeys.value.length} �?POC 模板吗？此操作不可撤销。`,
    onOk: async () => {
      try {
        loading.value = true
        await batchDeletePocs(selectedKeys.value)
        Message.success('批量删除成功')
        selectedKeys.value = []
        fetchData()
      } catch (err: any) {
        Message.error(`批量删除失败: ${err.message || '未知错误'}`)
      } finally {
        loading.value = false
      }
    },
  })
}

const handleBatchVerify = () => {
  if (selectedKeys.value.length === 0) {
    Message.warning('请先选择要验证的 POC')
    return
  }
  router.push({
    path: '/vuln/verify',
    query: {
      pocIds: selectedKeys.value.join(','),
    },
  })
}

// --- 导入处理 ---
const handleTriggerUpload = () => {
  if (fileInputRef.value) {
    fileInputRef.value.click()
  }
}

const handleFilesSelected = async (e: Event) => {
  const target = e.target as HTMLInputElement
  const files = target.files
  if (!files || files.length === 0) return

  scanLoading.value = true
  const formData = new FormData()
  let yamlCount = 0
  for (let i = 0; i < files.length; i++) {
    const file = files[i]
    if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
      formData.append('files', file)
      yamlCount++
    }
  }

  if (yamlCount === 0) {
    Message.warning('未在所选目录中找到 YAML 格式�?POC 模板')
    scanLoading.value = false
    if (fileInputRef.value) fileInputRef.value.value = ''
    return
  }

  try {
    Message.info(`开始上传并导入 ${yamlCount} 个模板文件，请耐心等待...`)
    const { data } = await uploadDirectoryPocs(formData)
    Message.success(`扫描导入成功！共发现有效POC模板�?{data.valid_files}个`)
    fetchData()
  } catch (err: any) {
    // 拦截器已处理
  } finally {
    scanLoading.value = false
    if (fileInputRef.value) {
      fileInputRef.value.value = ''
    }
  }
}

const handleManualImport = () => {
  manualVisible.value = true
}

const handleManualCancel = () => {
  manualVisible.value = false
  manualContent.value = ''
  manualTabKey.value = 'yaml'
  httpStep.value = 1
  httpRawContent.value = ''
  convertedYaml.value = ''
  convertedInfo.value = null
  httpConvertForm.poc_name = ''
  httpConvertForm.severity = 'medium'
  httpConvertForm.description = ''
  httpConvertForm.author = ''
  httpConvertForm.match_type = 'status'
  httpConvertForm.match_value = ''
}

const getMatchPlaceholder = () => {
  switch (httpConvertForm.match_type) {
    case 'status':
      return '状态码，如 200'
    case 'word':
      return '关键词，多个用逗号分隔'
    case 'regex':
      return '正则表达�?
    default:
      return '匹配�?
  }
}

const handleConvertHTTP = async () => {
  if (!httpRawContent.value.trim()) return
  convertLoading.value = true
  try {
    const { data } = await convertHTTPToYaml({
      raw_http: httpRawContent.value,
      poc_name: httpConvertForm.poc_name || undefined,
      severity: httpConvertForm.severity || undefined,
      description: httpConvertForm.description || undefined,
      author: httpConvertForm.author || undefined,
      match_type: httpConvertForm.match_type || undefined,
      match_value: httpConvertForm.match_value || undefined,
    })
    convertedYaml.value = data.yaml_content
    convertedInfo.value = data.parsed_info
    httpStep.value = 2
    Message.success('HTTP请求包转换成�?)
  } catch (err: any) {
    // 拦截器处�?
  } finally {
    convertLoading.value = false
  }
}

const handleUseConverted = () => {
  if (!convertedYaml.value) return
  manualContent.value = convertedYaml.value
  manualTabKey.value = 'yaml'
  Message.success('已切换到YAML模板标签页，可直接导�?)
}

const handleCopyYaml = () => {
  if (!convertedYaml.value) return
  navigator.clipboard
    .writeText(convertedYaml.value)
    .then(() => {
      Message.success('已复制到剪贴�?)
    })
    .catch(() => {
      Message.error('复制失败')
    })
}

const handleSaveManual = async () => {
  if (!manualContent.value.trim()) return
  saveManualLoading.value = true
  try {
    const { data } = await saveManualPoc({ content: manualContent.value })
    Message.success({
      content: `导入并保存成功！\n名称�?{data.name}\nID�?{data.id}\n位置�?{data.location}`,
      duration: 5000,
    })
    handleManualCancel()
    fetchData()
  } catch (err: any) {
    // 拦截器处�?
  } finally {
    saveManualLoading.value = false
  }
}

const columns = computed(() => [
  { title: 'ID', dataIndex: 'id', width: 80, sortable: { sortDirections: ['ascend', 'descend'] } },
  { title: 'POC名称', dataIndex: 'name', ellipsis: true, tooltip: true },
  { title: 'CVE编号', slotName: 'cve_id', width: 160 },
  { title: 'CNVD编号', slotName: 'cnvd_id', width: 160 },
  { title: '危害等级', slotName: 'severity', width: 100 },
  { title: '作�?, slotName: 'author', width: 160 },
  { title: '创建时间', dataIndex: 'created_at', width: 180, sortable: { sortDirections: ['ascend', 'descend'] } },
  { title: '操作', slotName: 'operations', fixed: 'right', width: 150 },
])

onMounted(fetchData)
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}
</style>
