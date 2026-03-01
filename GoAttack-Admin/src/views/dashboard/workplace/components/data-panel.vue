<template>
  <a-grid :cols="24" :row-gap="16" class="panel">
    <a-grid-item class="panel-col" :span="{ xs: 12, sm: 12, md: 12, lg: 12, xl: 12, xxl: 6 }">
      <a-space>
        <a-avatar :size="54" class="col-avatar">
          <icon-storage style="font-size: 24px" />
        </a-avatar>
        <a-statistic :title="$t('workplace.assets')" :value="stats.assets" :value-from="0" animation show-group-separator>
          <template #suffix>
            <span class="unit">{{ $t('workplace.pecs') }}</span>
          </template>
        </a-statistic>
      </a-space>
    </a-grid-item>
    <a-grid-item class="panel-col" :span="{ xs: 12, sm: 12, md: 12, lg: 12, xl: 12, xxl: 6 }">
      <a-space>
        <a-avatar :size="54" class="col-avatar">
          <icon-find-replace style="font-size: 24px" />
        </a-avatar>
        <a-statistic :title="$t('workplace.fingerprint')" :value="stats.fingerprints" :value-from="0" animation show-group-separator>
          <template #suffix>
            <span class="unit">{{ $t('workplace.pecs') }}</span>
          </template>
        </a-statistic>
      </a-space>
    </a-grid-item>
    <a-grid-item class="panel-col" :span="{ xs: 12, sm: 12, md: 12, lg: 12, xl: 12, xxl: 6 }">
      <a-space>
        <a-avatar :size="54" class="col-avatar">
          <icon-bug style="font-size: 24px" />
        </a-avatar>
        <a-statistic :title="$t('workplace.vulnerabilities')" :value="stats.vulnerabilities" :value-from="0" animation show-group-separator>
          <template #suffix>
            <span class="unit">{{ $t('workplace.pecs') }}</span>
          </template>
        </a-statistic>
      </a-space>
    </a-grid-item>
    <a-grid-item class="panel-col" :span="{ xs: 12, sm: 12, md: 12, lg: 12, xl: 12, xxl: 6 }">
      <a-space>
        <a-avatar :size="54" class="col-avatar">
          <icon-check-circle style="font-size: 24px" />
        </a-avatar>
        <a-statistic :title="$t('workplace.tasks')" :value="stats.tasks" :value-from="0" animation show-group-separator>
          <template #suffix>
            <span class="unit">{{ $t('workplace.pecs') }}</span>
          </template>
        </a-statistic>
      </a-space>
    </a-grid-item>
    <a-grid-item :span="24">
      <a-divider class="panel-border" />
    </a-grid-item>
  </a-grid>
</template>

<script lang="ts" setup>
import { reactive, onMounted } from 'vue'
import { getDashboardOverview } from '@/api/dashboard'

const stats = reactive({
  assets: 0,
  vulnerabilities: 0,
  tasks: 0,
  fingerprints: 0,
})

async function fetchOverview() {
  try {
    const { data } = await getDashboardOverview()
    if (data) {
      stats.assets = data.assets ?? 0
      stats.vulnerabilities = data.vulnerabilities ?? 0
      stats.tasks = data.tasks ?? 0
      stats.fingerprints = data.fingerprints ?? 0
    }
  } catch (e) {
    console.error('[DataPanel] fetchOverview failed', e)
  }
}

onMounted(fetchOverview)
</script>

<style lang="less" scoped>
.arco-grid.panel {
  margin-bottom: 0;
  padding: 16px 20px 0 20px;
}
.panel-col {
  padding-left: 43px;
  border-right: 1px solid rgb(var(--gray-2));
}
.col-avatar {
  margin-right: 12px;
  background-color: var(--color-fill-2);
}
.up-icon {
  color: rgb(var(--red-6));
}
.unit {
  margin-left: 8px;
  color: rgb(var(--gray-8));
  font-size: 12px;
}
:deep(.panel-border) {
  margin: 4px 0 0 0;
}
</style>
