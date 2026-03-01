<template>
  <div class="login-bg">
    <div class="container">
      <div class="logo">
        <div class="logo-text">Go Attack</div>
      </div>
      <LoginBanner />
      <div class="content">
        <div class="content-inner">
          <LoginForm />
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue'
import LoginBanner from './components/banner.vue'
import LoginForm from './components/login-form.vue'

export default defineComponent({
  components: {
    LoginBanner,
    LoginForm,
  },
  setup() {
    const showQr = ref(false)
    return { showQr }
  },
})
</script>

<style lang="less" scoped>
.login-bg {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100vw;
  min-height: 100vh;
  background: var(--login-bg-gradient);
  transition: background 0.8s ease;
}

.container {
  display: flex;
  position: relative;
  overflow: hidden;
  margin: 40px 0;
  width: 960px;
  max-width: 96vw;
  min-height: 520px;
  background: var(--color-bg-2);
  border: 1px solid var(--color-border-1);
  border-radius: 24px;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
  backdrop-filter: blur(8px);
  transition: transform 0.3s ease;

  &:hover {
    transform: translateY(-5px);
  }

  @media (max-width: 900px) {
    flex-direction: column;
    width: 98vw;
    min-height: unset;
  }

  .banner {
    display: flex;
    position: relative;
    align-items: center;
    justify-content: center;
    width: 440px;
    background: linear-gradient(135deg, #1d2129 0%, #00308f 100%);

    &::after {
      position: absolute;
      top: 0;
      right: 0;
      bottom: 0;
      left: 0;
      background: url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI1MCIgaGVpZ2h0PSI1MCI+PGNpcmNsZSBjeD0iMSIgY3k9IjEiIHI9IjEiIGZpbGw9InJnYmEoMjU1LDI1NSwyNTUsMC4wNSkiLz48L3N2Zz4=');
      opacity: 0.3;
      content: '';
    }

    @media (max-width: 900px) {
      width: 100%;
      min-height: 240px;
    }
  }

  .content {
    display: flex;
    flex: 1;
    position: relative;
    align-items: center;
    justify-content: center;
    padding: 48px;
    background: var(--color-bg-2);

    @media (max-width: 900px) {
      padding: 32px 24px;
    }
  }
}

.logo {
  display: flex;
  position: absolute;
  top: 40px;
  left: 40px;
  z-index: 10;
  align-items: center;
  padding: 8px 24px 8px 16px;
  background: var(--color-bg-2);
  border: 1px solid var(--color-border);
  border-radius: 30px;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
  backdrop-filter: blur(4px);

  &-text {
    margin-left: 12px;
    color: #00308f;
    font-size: 24px;
    font-weight: 800;
    letter-spacing: 2px;
    text-transform: uppercase;

    :global(body[arco-theme='dark']) & {
      color: var(--color-primary-light-3);
    }
  }

  @media (max-width: 900px) {
    display: none;
  }
}

.scan-login-btn {
  display: flex;
  position: absolute;
  top: 32px;
  right: 40px;
  z-index: 10;
  align-items: center;
  gap: 8px;
  padding: 8px 18px;
  color: var(--color-text-1);
  background: var(--color-fill-2);
  border-radius: 20px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;

  &:hover {
    background: var(--color-fill-3);
    transform: scale(1.02);
  }
}

.qr-modal-content {
  padding: 12px 0 0 0;
}
</style>
