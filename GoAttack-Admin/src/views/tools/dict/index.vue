<template>
  <div class="container">
    <Breadcrumb :items="['menu.tools', 'menu.tools.dict']" />
    <a-card class="general-card" :title="$t('menu.tools.dict')">
      <a-tabs default-active-key="1">
        <a-tab-pane key="1" title="字典管理">
          <div class="tab-content">
            <a-space style="margin-bottom: 16px">
              <a-button type="primary" @click="fetchData">刷新列表</a-button>
            </a-space>
            <a-table :data="defaultDictData" :loading="loading" row-key="id">
              <template #columns>
                <a-table-column title="字典名称" data-index="name" />
                <a-table-column title="分类" data-index="category" />
                <a-table-column title="大小" data-index="size">
                  <template #cell="{ record }">{{ formatSize(record.size) }}</template>
                </a-table-column>
                <a-table-column title="行数" data-index="lines_cnt" />
                <a-table-column title="操作">
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
        <a-tab-pane key="2" title="导入字典">
          <div class="tab-content">
            <a-upload
              draggable
              :action="uploadUrl"
              :headers="uploadHeaders"
              tip="点击或拖拽文件到此处上传"
              style="margin-bottom: 20px"
              @success="handleUploadSuccess"
              @error="handleUploadError"
            />
            <div class="upload-list">
              <a-alert>支持 .txt, .dic 格式，导入成功后请在“字典管理”刷新查看</a-alert>
            </div>
          </div>
        </a-tab-pane>
        <a-tab-pane key="3" title="字典生成">
          <div class="tab-content">
            <a-form :model="socialForm" layout="vertical" style="max-width: 600px">
              <a-form-item field="name" label="目标名称/拼音">
                <a-input v-model="socialForm.name" placeholder="请输入姓名或常用ID" />
              </a-form-item>
              <a-form-item field="birthday" label="出生日期">
                <a-date-picker v-model="socialForm.birthday" style="width: 100%" />
              </a-form-item>
              <a-form-item field="phone" label="手机号/关键数字">
                <a-input v-model="socialForm.phone" placeholder="请输入手机号或其他数字" />
              </a-form-item>
              <a-form-item field="rules" label="生成规则">
                <a-checkbox-group v-model="socialForm.rules">
                  <a-checkbox value="date">组合日期</a-checkbox>
                  <a-checkbox value="pinyin">变换拼音大小写</a-checkbox>
                  <a-checkbox value="special">包含特殊字符</a-checkbox>
                </a-checkbox-group>
              </a-form-item>
              <a-form-item>
                <a-button type="primary">生成字典</a-button>
              </a-form-item>
            </a-form>
          </div>
        </a-tab-pane>
      </a-tabs>
    </a-card>
    <!-- 浏览字典弹窗 -->
    <a-modal v-model:visible="viewVisible" :title="`查看字典 - ${currentDictName}`" :footer="false" width="600px">
      <a-spin :loading="viewLoading" style="width: 100%">
        <a-textarea v-model="currentViewContent" readonly :auto-size="{ minRows: 15, maxRows: 20 }" style="font-family: monospace" />
      </a-spin>
    </a-modal>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted } from 'vue'
import { Message, Modal } from '@arco-design/web-vue'
import { getDictList, syncDicts, viewDict, downloadDict, deleteDict } from '@/api/dict'
import { getToken } from '@/utils/auth'

const uploadUrl = `${import.meta.env.VITE_API_BASE_URL || ''}/api/dict/upload`
const uploadHeaders = { Authorization: `Bearer ${getToken()}` }

const loading = ref(false)
const defaultDictData = ref<any[]>([])

const viewVisible = ref(false)
const viewLoading = ref(false)
const currentDictName = ref('')
const currentViewContent = ref('')

const socialForm = reactive({
  name: '',
  birthday: '',
  phone: '',
  rules: ['pinyin'],
})

const formatSize = (bytes: number) => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
}

const fetchData = async () => {
  loading.value = true
  try {
    const res = await getDictList()
    defaultDictData.value = res.data || []
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '获取字典列表失败')
  } finally {
    loading.value = false
  }
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
  } catch (err) {
    Message.error('下载失败')
  }
}

const handleDelete = (record: any) => {
  Modal.warning({
    title: '确认删除',
    content: `确定要删除字典 ${record.name} 吗？如果物理文件是在 service/dict 预设中，删除后可能被再次扫描同步恢复。`,
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
  // Automatically sync
  syncDicts().then(() => fetchData())
}

const handleUploadError = () => {
  Message.error('文件导入失败')
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
</style>
