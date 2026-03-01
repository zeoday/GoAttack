<template>
  <div class="login-form-wrapper">
    <div class="login-form-title">{{ $t('login.form.title') }}</div>
    <div class="login-form-error-msg">{{ errorMessage }}</div>
    <a-form ref="loginForm" :model="userInfo" class="login-form" layout="vertical" @submit="handleSubmit">
      <a-form-item
        field="username"
        :rules="[{ required: true, message: $t('login.form.userName.errMsg') }]"
        :validate-trigger="['change', 'blur']"
        hide-label
      >
        <a-input v-model="userInfo.username" :placeholder="$t('login.form.userName.placeholder')">
          <template #prefix>
            <icon-user />
          </template>
        </a-input>
      </a-form-item>
      <a-form-item
        field="password"
        :rules="[{ required: true, message: $t('login.form.password.errMsg') }]"
        :validate-trigger="['change', 'blur']"
        hide-label
      >
        <a-input-password v-model="userInfo.password" :placeholder="$t('login.form.password.placeholder')" allow-clear>
          <template #prefix>
            <icon-lock />
          </template>
        </a-input-password>
      </a-form-item>
      <a-space :size="16" direction="vertical">
        <div class="login-form-password-actions">
          <a-checkbox checked="rememberPassword" :model-value="loginConfig.rememberPassword" @change="setRememberPassword as any">
            {{ $t('login.form.rememberPassword') }}
          </a-checkbox>
          <a-link @click="handleForgetPassword">{{ $t('login.form.forgetPassword') }}</a-link>
        </div>
        <a-button type="primary" html-type="submit" long :loading="loading">
          {{ $t('login.form.login') }}
        </a-button>
      </a-space>
    </a-form>
    <a-modal v-model:visible="showForgetModal" title="提示" :footer="false">请联系管理员</a-modal>
  </div>
</template>

<script lang="ts" setup>
import type { LoginData } from '@/api/user'
import useLoading from '@/hooks/loading'
import { useUserStore } from '@/store'
import { Message } from '@arco-design/web-vue'
import { ValidatedError } from '@arco-design/web-vue/es/form/interface'
import { useStorage } from '@vueuse/core'
import { reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'

const router = useRouter()
const { t } = useI18n()
const errorMessage = ref('')
const showForgetModal = ref(false)
const { loading, setLoading } = useLoading()
const userStore = useUserStore()

const loginConfig = useStorage('login-config', {
  rememberPassword: true,
  username: 'admin',
  password: 'Qaz@123#', 
})
const userInfo = reactive({
  username: loginConfig.value.username,
  password: loginConfig.value.password,
})

const handleSubmit = async ({ errors, values }: { errors: Record<string, ValidatedError> | undefined; values: Record<string, any> }) => {
  if (loading.value) return
  if (!errors) {
    setLoading(true)
    try {
      await userStore.login(values as LoginData)
      const { redirect, ...othersQuery } = router.currentRoute.value.query
      router.push({
        name: (redirect as string) || 'Workplace',
        query: {
          ...othersQuery,
        },
      })
      Message.success(t('login.form.login.success'))
      const { rememberPassword } = loginConfig.value
      const { username, password } = values
      // 实际生产环境需要进行加密存储。
      // The actual production environment requires encrypted storage.
      loginConfig.value.username = rememberPassword ? username : ''
      loginConfig.value.password = rememberPassword ? password : ''
    } catch (err) {
      errorMessage.value = (err as Error).message
    } finally {
      setLoading(false)
    }
  }
}
const setRememberPassword = (value: boolean) => {
  loginConfig.value.rememberPassword = value
}
const handleForgetPassword = () => {
  showForgetModal.value = true
}
</script>

<style lang="less" scoped>
.login-form {
  &-wrapper {
    width: 320px;
  }

  &-title {
    color: var(--color-text-1);
    font-weight: 500;
    font-size: 24px;
    line-height: 32px;
  }

  &-sub-title {
    color: var(--color-text-3);
    font-size: 16px;
    line-height: 24px;
  }

  &-error-msg {
    height: 32px;
    color: rgb(var(--red-6));
    line-height: 32px;
  }

  &-password-actions {
    display: flex;
    justify-content: space-between;
  }

  &-register-btn {
    color: var(--color-text-3) !important;
  }
}

:deep(.arco-btn) {
  border-radius: 24px !important;
}
:deep(.arco-input),
:deep(.arco-input-wrapper),
:deep(.arco-input-password) {
  border-radius: 18px !important;
  background-color: var(--color-fill-2) !important;
  border: 1px solid var(--color-border) !important;
}

:deep(.arco-input-wrapper:hover),
:deep(.arco-input-password:hover) {
  background-color: var(--color-fill-1) !important;
  border-color: var(--color-primary-light-3) !important;
}

:deep(.arco-input-wrapper.arco-input-focus),
:deep(.arco-input-password.arco-input-focus) {
  background-color: var(--color-bg-2) !important;
  border-color: var(--color-primary) !important;
}
</style>
