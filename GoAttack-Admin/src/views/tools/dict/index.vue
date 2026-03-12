<template>
  <div class="container">
    <Breadcrumb :items="['menu.tools', 'menu.tools.dict']" />
    <a-card class="general-card" :title="$t('menu.tools.dict')">
      <a-tabs v-model:active-key="activeTab" @change="onTabChange">
        <!-- ————— Tab 1: 字典管理 ————— -->
        <a-tab-pane key="1" title="字典管理">
          <div class="tab-content">
            <a-space style="margin-bottom: 16px">
              <a-button type="primary" @click="fetchData">
                <template #icon><icon-refresh /></template>
                刷新列表
              </a-button>
            </a-space>
            <a-table :data="dictData" :loading="loading" row-key="id" :pagination="{ pageSize: 15 }">
              <template #columns>
                <a-table-column title="字典名称" data-index="name" :width="220" ellipsis tooltip />
                <a-table-column title="类型" data-index="type" :width="90">
                  <template #cell="{ record }">
                    <a-tag :color="typeColor(record.type)">{{ typeLabel(record.type) }}</a-tag>
                  </template>
                </a-table-column>
                <a-table-column title="分类" data-index="category" :width="110" />
                <a-table-column title="大小" data-index="size" :width="90">
                  <template #cell="{ record }">{{ formatSize(record.size) }}</template>
                </a-table-column>
                <a-table-column title="行数" data-index="lines_cnt" :width="90" />
                <a-table-column title="创建时间" data-index="created_at" :width="160" />
                <a-table-column title="操作" :width="150">
                  <template #cell="{ record }">
                    <a-space>
                      <a-button type="text" size="small" @click="handleView(record)">查看</a-button>
                      <a-button type="text" size="small" @click="handleDownload(record)">导出</a-button>
                      <a-button type="text" size="small" status="danger" @click="handleDelete(record)">删除</a-button>
                    </a-space>
                  </template>
                </a-table-column>
              </template>
            </a-table>
          </div>
        </a-tab-pane>

        <!-- ————— Tab 2: 导入字典 ————— -->
        <a-tab-pane key="2" title="导入字典">
          <div class="tab-content">
            <a-upload
              draggable
              :action="uploadUrl"
              :headers="uploadHeaders"
              tip="点击或拖拽文件到此处上传（支持 .txt .dic 格式）"
              style="margin-bottom: 20px"
              @success="handleUploadSuccess"
              @error="handleUploadError"
            />
          </div>
        </a-tab-pane>

        <!-- ————— Tab 3: 社会工程字典生成 ————— -->
        <a-tab-pane key="3" title="社会工程字典">
          <div class="tab-content gen-panel">
            <div class="gen-header">
              <div class="gen-title">
                <icon-user class="gen-icon" />
                <span>社会工程字典生成</span>
              </div>
              <p class="gen-desc">根据目标的个人信息（姓名、生日、公司等）智能组合，生成高命中率的密码字典。</p>
            </div>

            <a-row :gutter="24">
              <a-col :span="14">
                <a-form :model="socialForm" layout="vertical" label-align="right">
                  <a-row :gutter="16">
                    <a-col :span="12">
                      <a-form-item field="name" label="姓名 / 拼音">
                        <a-input v-model="socialForm.name" placeholder="如：zhangsan / 张三" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="nickname" label="昵称 / 常用ID">
                        <a-input v-model="socialForm.nickname" placeholder="如：xiao_san / admin" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="birthday" label="生日（YYYYMMDD）">
                        <a-input v-model="socialForm.birthday" placeholder="如：19901231" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="phone" label="手机号 / 关键数字">
                        <a-input v-model="socialForm.phone" placeholder="如：13812345678" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="email" label="邮箱">
                        <a-input v-model="socialForm.email" placeholder="如：user@example.com" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="company" label="公司 / 组织">
                        <a-input v-model="socialForm.company" placeholder="如：alibaba / tencent" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="address" label="城市 / 地址">
                        <a-input v-model="socialForm.address" placeholder="如：beijing / shanghai" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="system_tag" label="系统名 / 项目名">
                        <a-input v-model="socialForm.system_tag" placeholder="如：oa / erp / crm" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="pet_name" label="宠物名 / 特殊词">
                        <a-input v-model="socialForm.pet_name" placeholder="如：lucky / mimi" allow-clear />
                      </a-form-item>
                    </a-col>
                    <a-col :span="12">
                      <a-form-item field="extra" label="其他关键词（逗号分隔）">
                        <a-input v-model="socialForm.extra" placeholder="如：test,dev,2024" allow-clear />
                      </a-form-item>
                    </a-col>
                  </a-row>

                  <a-form-item label="生成规则">
                    <a-checkbox-group v-model="socialForm.rules">
                      <a-space wrap>
                        <a-checkbox value="date">组合日期变体</a-checkbox>
                        <a-checkbox value="leet">Leet 变换（a→4，e→3…）</a-checkbox>
                        <a-checkbox value="special">追加特殊字符（! @ #）</a-checkbox>
                        <a-checkbox value="reverse">倒序变体</a-checkbox>
                        <a-checkbox value="double">双写变体（abcabc）</a-checkbox>
                      </a-space>
                    </a-checkbox-group>
                  </a-form-item>

                  <a-form-item field="dict_name" label="字典文件名（可选）">
                    <a-input v-model="socialForm.dict_name" placeholder="留空则自动命名，如：social_zhangsan_xxx.txt" allow-clear />
                  </a-form-item>

                  <a-form-item>
                    <a-button
                      type="primary"
                      :loading="socialGenerating"
                      @click="handleSocialGenerate"
                    >
                      <template #icon><icon-thunderbolt /></template>
                      生成字典
                    </a-button>
                  </a-form-item>
                </a-form>
              </a-col>

              <a-col :span="10">
                <div class="gen-result-box" v-if="socialResult">
                  <div class="gen-result-header">
                    <icon-check-circle class="result-icon success" />
                    <span>生成成功</span>
                  </div>
                  <a-descriptions :column="1" bordered size="small">
                    <a-descriptions-item label="文件名">{{ socialResult.name }}</a-descriptions-item>
                    <a-descriptions-item label="行数">{{ socialResult.lines_cnt.toLocaleString() }}</a-descriptions-item>
                    <a-descriptions-item label="文件大小">{{ formatSize(socialResult.size) }}</a-descriptions-item>
                  </a-descriptions>
                  <div style="margin-top: 12px">
                    <a-button type="outline" size="small" @click="activeTab = '1'; fetchData()">
                      <template #icon><icon-list /></template>
                      查看字典列表
                    </a-button>
                  </div>
                </div>
                <div class="gen-tips-box">
                  <div class="gen-tips-title">
                    <icon-bulb /> 使用提示
                  </div>
                  <ul class="gen-tips-list">
                    <li>信息越详细，字典命中率越高</li>
                    <li>姓名/昵称支持中文拼音和英文</li>
                    <li>生日格式：YYYYMMDD（如 19901231）</li>
                    <li>会自动生成大小写、数字后缀等变体</li>
                    <li>生成的字典会保存到字典管理列表</li>
                  </ul>
                </div>
              </a-col>
            </a-row>
          </div>
        </a-tab-pane>

        <!-- ————— Tab 4: Combo 字典生成 ————— -->
        <a-tab-pane key="4" title="Combo 字典生成">
          <div class="tab-content gen-panel">
            <div class="gen-header">
              <div class="gen-title">
                <icon-apps class="gen-icon" />
                <span>Combo 字典生成</span>
              </div>
              <p class="gen-desc">基于多列基础词进行笛卡尔积组合，支持自定义连接符和变换规则，适合生成大规模爆破字典。</p>
            </div>

            <a-row :gutter="24">
              <a-col :span="15">
                <div class="combo-columns-header">
                  <span class="combo-columns-label">基础词列（每列单独一行，用字母 A/B/C… 标识）</span>
                  <a-button size="small" @click="addComboColumn">
                    <template #icon><icon-plus /></template>
                    添加列
                  </a-button>
                </div>

                <div class="combo-columns-wrap">
                  <div
                    v-for="(col, ci) in comboForm.bases"
                    :key="ci"
                    class="combo-column-card"
                  >
                    <div class="combo-col-header">
                      <span class="combo-col-label combo-col-letter">{{ colLetter(ci) }}</span>
                      <a-button
                        v-if="comboForm.bases.length > 1"
                        size="mini"
                        type="text"
                        status="danger"
                        @click="removeComboColumn(ci)"
                      >
                        <template #icon><icon-delete /></template>
                      </a-button>
                    </div>
                    <a-textarea
                      v-model="comboForm.bases[ci]"
                      :placeholder="`列 ${colLetter(ci)}（每行一个词）\n如：admin\nroot\nuser`"
                      :auto-size="{ minRows: 6, maxRows: 12 }"
                      style="font-family: monospace; font-size: 12px"
                    />
                  </div>
                </div>

                <a-divider />

                <!-- 列顺序组合 -->
                <div class="order-section">
                  <div class="order-section-header">
                    <span class="order-section-label">列顺序组合（每种组合生成一份笛卡尔积，最终合并去重）</span>
                  </div>
                  <!-- 快捷按钮 -->
                  <div class="order-presets">
                    <span class="order-preset-label">快捷添加：</span>
                    <a-space wrap>
                      <a-button
                        v-for="preset in orderPresets"
                        :key="preset.label"
                        size="mini"
                        :type="isOrderActive(preset.order) ? 'primary' : 'outline'"
                        @click="toggleOrderPreset(preset.order)"
                      >
                        {{ preset.label }}
                      </a-button>
                    </a-space>
                  </div>
                  <!-- 自定义输入 -->
                  <div class="order-custom">
                    <span class="order-preset-label">自定义组合：</span>
                    <div class="order-tags-wrap">
                      <a-tag
                        v-for="(ord, oi) in comboForm.orders"
                        :key="oi"
                        closable
                        color="arcoblue"
                        @close="removeOrder(oi)"
                      >
                        {{ orderLabel(ord) }}
                      </a-tag>
                      <a-input
                        v-model="customOrderInput"
                        size="mini"
                        placeholder="如 BA 或 ACB，回车添加"
                        style="width: 140px"
                        @keydown.enter="addCustomOrder"
                      />
                      <a-button size="mini" @click="addCustomOrder">添加</a-button>
                    </div>
                    <div v-if="comboForm.orders.length === 0" class="order-empty-hint">未添加任何顺序组合，默认按 A→B→C… 顺序全列组合</div>
                  </div>
                </div>

                <a-divider />

                <a-form :model="comboForm" layout="inline">
                  <a-form-item label="连接符（可多选）">
                    <a-checkbox-group v-model="comboForm.joins">
                      <a-checkbox value="">（空）直接拼接</a-checkbox>
                      <a-checkbox value="_">下划线 _</a-checkbox>
                      <a-checkbox value="-">短横线 -</a-checkbox>
                      <a-checkbox value=".">点号 .</a-checkbox>
                      <a-checkbox value="@">@ 符</a-checkbox>
                    </a-checkbox-group>
                  </a-form-item>
                </a-form>

                <a-form :model="comboForm" layout="vertical" style="margin-top: 12px">
                  <a-form-item label="附加变换规则">
                    <a-checkbox-group v-model="comboForm.rules">
                      <a-space wrap>
                        <a-checkbox value="upper">全大写变体</a-checkbox>
                        <a-checkbox value="title">首字母大写</a-checkbox>
                        <a-checkbox value="numbers">追加常用数字（123 / 1234 等）</a-checkbox>
                        <a-checkbox value="leet">Leet 变换</a-checkbox>
                        <a-checkbox value="reverse">倒序</a-checkbox>
                      </a-space>
                    </a-checkbox-group>
                  </a-form-item>

                  <a-form-item field="dict_name" label="字典文件名（可选）">
                    <a-input v-model="comboForm.dict_name" placeholder="留空则自动命名，如：combo_xxx.txt" allow-clear style="max-width: 320px" />
                  </a-form-item>

                  <a-form-item>
                    <a-button
                      type="primary"
                      :loading="comboGenerating"
                      @click="handleComboGenerate"
                    >
                      <template #icon><icon-thunderbolt /></template>
                      生成 Combo 字典
                    </a-button>
                  </a-form-item>
                </a-form>
              </a-col>

              <a-col :span="9">
                <div class="gen-result-box" v-if="comboResult">
                  <div class="gen-result-header">
                    <icon-check-circle class="result-icon success" />
                    <span>生成成功</span>
                  </div>
                  <a-descriptions :column="1" bordered size="small">
                    <a-descriptions-item label="文件名">{{ comboResult.name }}</a-descriptions-item>
                    <a-descriptions-item label="行数">{{ comboResult.lines_cnt.toLocaleString() }}</a-descriptions-item>
                    <a-descriptions-item label="文件大小">{{ formatSize(comboResult.size) }}</a-descriptions-item>
                  </a-descriptions>
                  <div style="margin-top: 12px">
                    <a-button type="outline" size="small" @click="activeTab = '1'; fetchData()">
                      <template #icon><icon-list /></template>
                      查看字典列表
                    </a-button>
                  </div>
                </div>

                <div class="gen-tips-box">
                  <div class="gen-tips-title">
                    <icon-bulb /> 使用提示
                  </div>
                  <ul class="gen-tips-list">
                    <li>列用字母 A/B/C… 标识，每列输入一组基础词</li>
                    <li><b>列顺序组合</b>决定拼接方式：AB = 先A后B，BA = 先B后A</li>
                    <li>可同时添加多个顺序，例如 AB 和 BA，最终合并去重</li>
                    <li>例：A列(admin) × B列(123,456) + 顺序 AB,BA = admin123, admin456, 123admin, 456admin</li>
                    <li>生成的字典会保存到字典管理列表</li>
                  </ul>
                </div>
              </a-col>
            </a-row>
          </div>
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- 浏览字典弹窗 -->
    <a-modal v-model:visible="viewVisible" :title="`查看字典 - ${currentDictName}`" :footer="false" width="620px">
      <a-spin :loading="viewLoading" style="width: 100%">
        <a-textarea v-model="currentViewContent" readonly :auto-size="{ minRows: 15, maxRows: 22 }" style="font-family: monospace; font-size: 12px" />
      </a-spin>
    </a-modal>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { Message, Modal } from '@arco-design/web-vue'
import {
  getDictList,
  syncDicts,
  viewDict,
  downloadDict,
  deleteDict,
  generateSocialDict,
  generateComboDict,
} from '@/api/dict'
import { getToken } from '@/utils/auth'

const uploadUrl = `${import.meta.env.VITE_API_BASE_URL || ''}/api/dict/upload`
const uploadHeaders = { Authorization: `Bearer ${getToken()}` }

const activeTab = ref('1')
const loading = ref(false)
const dictData = ref<any[]>([])

const viewVisible = ref(false)
const viewLoading = ref(false)
const currentDictName = ref('')
const currentViewContent = ref('')

// Social form
const socialGenerating = ref(false)
const socialResult = ref<any>(null)
const socialForm = reactive({
  name: '',
  nickname: '',
  birthday: '',
  phone: '',
  email: '',
  company: '',
  address: '',
  system_tag: '',
  pet_name: '',
  extra: '',
  rules: ['date'] as string[],
  dict_name: '',
})

// Combo form
const comboGenerating = ref(false)
const comboResult = ref<any>(null)
const customOrderInput = ref('')
const comboForm = reactive({
  bases: ['', ''] as string[],
  joins: [''] as string[],
  orders: [] as number[][], // 每个元素是列索引数组，如 [0,1] 表示 AB
  rules: [] as string[],
  dict_name: '',
})

// 将列索引转换为字母标签 (0→A, 1→B, 2→C…)
const colLetter = (idx: number) => String.fromCharCode(65 + idx)

// 将 order 数组转换为展示标签，如 [0,1] → "AB"
const orderLabel = (order: number[]) => order.map((i) => colLetter(i)).join('')

// 根据当前列数生成预设列顺序快捷按钮
const orderPresets = computed(() => {
  const n = comboForm.bases.filter((b) => b.trim()).length || comboForm.bases.length
  const presets: { label: string; order: number[] }[] = []
  if (n >= 2) {
    presets.push({ label: 'AB', order: [0, 1] })
    presets.push({ label: 'BA', order: [1, 0] })
  }
  if (n >= 3) {
    presets.push({ label: 'ABC', order: [0, 1, 2] })
    presets.push({ label: 'ACB', order: [0, 2, 1] })
    presets.push({ label: 'BAC', order: [1, 0, 2] })
    presets.push({ label: 'BCA', order: [1, 2, 0] })
    presets.push({ label: 'CAB', order: [2, 0, 1] })
    presets.push({ label: 'CBA', order: [2, 1, 0] })
  }
  if (n >= 4) {
    // 只提供常用组合
    presets.push({ label: 'ABCD', order: [0, 1, 2, 3] })
    presets.push({ label: 'DCBA', order: [3, 2, 1, 0] })
  }
  return presets
})

// 判断某个 order 是否已在列表中
const isOrderActive = (order: number[]) =>
  comboForm.orders.some((o) => o.length === order.length && o.every((v, i) => v === order[i]))

// 切换快捷按钮选中状态
const toggleOrderPreset = (order: number[]) => {
  const idx = comboForm.orders.findIndex(
    (o) => o.length === order.length && o.every((v, i) => v === order[i])
  )
  if (idx >= 0) {
    comboForm.orders.splice(idx, 1)
  } else {
    comboForm.orders.push([...order])
  }
}

// 解析用户输入的字母字符串为索引数组 ("BA" → [1,0])
const parseOrderStr = (s: string): number[] | null => {
  const upper = s.toUpperCase().trim()
  if (!upper) return null
  const order: number[] = []
  const chars = upper.split('')
  const valid = chars.every((ch) => {
    const idx = ch.charCodeAt(0) - 65
    if (idx < 0 || idx > 25) return false
    order.push(idx)
    return true
  })
  return valid ? order : null
}

const addCustomOrder = () => {
  const order = parseOrderStr(customOrderInput.value)
  if (!order || order.length === 0) {
    Message.warning('请输入有效的列字母组合，如 BA 或 ACB')
    return
  }
  const maxIdx = comboForm.bases.length - 1
  if (order.some((i) => i > maxIdx)) {
    Message.warning(`列索引超出范围，当前共 ${comboForm.bases.length} 列（${colLetter(0)}~${colLetter(maxIdx)}）`)
    return
  }
  if (!isOrderActive(order)) {
    comboForm.orders.push(order)
  }
  customOrderInput.value = ''
}

const removeOrder = (idx: number) => {
  comboForm.orders.splice(idx, 1)
}

const formatSize = (bytes: number) => {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
}

const typeLabel = (t: string) => {
  const m: Record<string, string> = { preset: '预设', custom: '自定义', generated: '生成' }
  return m[t] || t
}

const typeColor = (t: string) => {
  const m: Record<string, string> = { preset: 'blue', custom: 'green', generated: 'purple' }
  return m[t] || 'gray'
}

const fetchData = async () => {
  loading.value = true
  try {
    const res = await getDictList()
    dictData.value = res.data || []
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '获取字典列表失败')
  } finally {
    loading.value = false
  }
}

const onTabChange = (key: string | number) => {
  if (key === '1') fetchData()
}

const handleView = async (record: any) => {
  currentDictName.value = record.name
  viewVisible.value = true
  viewLoading.value = true
  currentViewContent.value = ''
  try {
    const res = await viewDict(record.id)
    currentViewContent.value = res.data || '（内容为空）'
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '加载字典失败')
    currentViewContent.value = '加载失败'
  } finally {
    viewLoading.value = false
  }
}

const handleDownload = async (record: any) => {
  Message.info(`正在准备下载 ${record.name}...`)
  try {
    const res = await downloadDict(record.id)
    const blob = new Blob([res.data], { type: 'application/octet-stream' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.style.display = 'none'
    link.href = url
    link.setAttribute('download', record.name)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
  } catch {
    Message.error('下载失败')
  }
}

const handleDelete = (record: any) => {
  Modal.warning({
    title: '确认删除',
    content: `确定要删除字典 "${record.name}" 吗？`,
    hideCancel: false,
    onOk: async () => {
      try {
        await deleteDict(record.id)
        Message.success('删除成功')
        fetchData()
      } catch (err: any) {
        Message.error(err.response?.data?.msg || '删除失败')
      }
    },
  })
}

const handleUploadSuccess = () => {
  Message.success('导入文件完成')
  syncDicts().then(() => fetchData())
}

const handleUploadError = () => {
  Message.error('文件导入失败')
}

const handleSocialGenerate = async () => {
  const fields = [
    socialForm.name, socialForm.nickname, socialForm.birthday,
    socialForm.phone, socialForm.email, socialForm.company,
    socialForm.address, socialForm.system_tag, socialForm.pet_name, socialForm.extra,
  ]
  if (fields.every((f) => !f.trim())) {
    Message.warning('请至少填写一个信息字段')
    return
  }
  socialGenerating.value = true
  socialResult.value = null
  try {
    const res = await generateSocialDict({
      name: socialForm.name,
      nickname: socialForm.nickname,
      birthday: socialForm.birthday,
      phone: socialForm.phone,
      email: socialForm.email,
      company: socialForm.company,
      address: socialForm.address,
      system_tag: socialForm.system_tag,
      pet_name: socialForm.pet_name,
      extra: socialForm.extra,
      rules: socialForm.rules,
      dict_name: socialForm.dict_name,
    })
    socialResult.value = res.data
    Message.success(`字典生成成功，共 ${res.data?.lines_cnt} 条`)
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '生成失败')
  } finally {
    socialGenerating.value = false
  }
}

const addComboColumn = () => {
  comboForm.bases.push('')
}

const removeComboColumn = (idx: number) => {
  comboForm.bases.splice(idx, 1)
}

const handleComboGenerate = async () => {
  const nonEmpty = comboForm.bases.filter((b) => b.trim())
  if (nonEmpty.length === 0) {
    Message.warning('请至少填写一列基础词')
    return
  }
  if (comboForm.joins.length === 0) {
    Message.warning('请至少选择一个连接符')
    return
  }
  comboGenerating.value = true
  comboResult.value = null
  try {
    const res = await generateComboDict({
      bases: comboForm.bases,
      joins: comboForm.joins,
      orders: comboForm.orders.length > 0 ? comboForm.orders : undefined,
      rules: comboForm.rules,
      dict_name: comboForm.dict_name,
    })
    comboResult.value = res.data
    Message.success(`Combo 字典生成成功，共 ${res.data?.lines_cnt} 条`)
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '生成失败')
  } finally {
    comboGenerating.value = false
  }
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped lang="less">
.container {
  padding: 20px;
}

.tab-content {
  padding-top: 20px;
}

.gen-panel {
  padding-top: 12px;
}

.gen-header {
  margin-bottom: 20px;
}

.gen-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 16px;
  font-weight: 600;
  color: var(--color-text-1);
  margin-bottom: 4px;
}

.gen-icon {
  font-size: 18px;
  color: var(--color-primary-6);
}

.gen-desc {
  color: var(--color-text-3);
  font-size: 13px;
  margin: 0;
}

.gen-result-box {
  background: var(--color-fill-2);
  border: 1px solid var(--color-border-2);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 16px;
  animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(-6px); }
  to { opacity: 1; transform: translateY(0); }
}

.gen-result-header {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 500;
  color: var(--color-text-1);
  margin-bottom: 12px;
}

.result-icon.success {
  color: rgb(var(--success-6));
  font-size: 18px;
}

.gen-tips-box {
  background: var(--color-fill-1);
  border: 1px solid var(--color-border-1);
  border-radius: 8px;
  padding: 14px 16px;
}

.gen-tips-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--color-text-2);
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  gap: 4px;
}

.gen-tips-list {
  padding-left: 18px;
  margin: 0;
  color: var(--color-text-3);
  font-size: 12px;
  line-height: 1.9;
}

/* Combo columns */
.combo-columns-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.combo-columns-label {
  font-size: 13px;
  color: var(--color-text-2);
  font-weight: 500;
}

.combo-columns-wrap {
  display: flex;
  gap: 12px;
  overflow-x: auto;
  padding-bottom: 4px;
  margin-bottom: 8px;
}

.combo-column-card {
  flex: 1;
  min-width: 150px;
  background: var(--color-fill-1);
  border: 1px solid var(--color-border-2);
  border-radius: 8px;
  padding: 10px;
  transition: box-shadow 0.2s;

  &:hover {
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  }
}

.combo-col-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}

.combo-col-label {
  font-size: 12px;
  color: var(--color-text-3);
  font-weight: 500;
}

.combo-col-letter {
  font-size: 16px;
  font-weight: 700;
  color: var(--color-primary-6);
  letter-spacing: 1px;
}

/* 列顺序区域 */
.order-section {
  margin-bottom: 4px;
}

.order-section-header {
  margin-bottom: 8px;
}

.order-section-label {
  font-size: 13px;
  color: var(--color-text-2);
  font-weight: 500;
}

.order-presets {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  margin-bottom: 8px;
}

.order-preset-label {
  font-size: 12px;
  color: var(--color-text-3);
  white-space: nowrap;
  margin-right: 2px;
}

.order-custom {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  flex-wrap: wrap;
}

.order-tags-wrap {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}

.order-empty-hint {
  font-size: 12px;
  color: var(--color-text-4);
  font-style: italic;
  margin-top: 4px;
}
</style>
