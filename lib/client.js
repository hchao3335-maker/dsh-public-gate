/**
 * Public-gate settings section for the dsh web client.
 *
 * Registered into the `settings.section` slot, so it shows up as its own page in
 * the Settings panel. Everything it needs comes from the gate's own
 * `/__gate/admin/*` endpoints: the page is served through the gate, so those
 * requests are same-origin and carry the gate session cookie.
 */
window.__ModuleLoader__.load({
  id: 'dsh-public-gate',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const react = require('react')

    const API = '/__gate/admin'
    const SECTION_ID = 'public-gate'
    const NS = 'public-gate'

    const styles = {
      root: { display: 'flex', flexDirection: 'column', gap: 18, padding: '4px 2px 24px' },
      card: {
        border: '1px solid rgba(127,127,127,.28)',
        borderRadius: 10,
        padding: '14px 16px',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
      },
      h: { fontSize: 13, fontWeight: 600, margin: 0, opacity: 0.9 },
      sub: { fontSize: 12, opacity: 0.62, margin: 0, lineHeight: 1.5 },
      row: { display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' },
      label: { fontSize: 12, opacity: 0.66, minWidth: 96 },
      value: { fontSize: 13, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' },
      input: {
        flex: 1,
        minWidth: 220,
        padding: '7px 10px',
        fontSize: 13,
        color: 'inherit',
        background: 'rgba(127,127,127,.08)',
        border: '1px solid rgba(127,127,127,.3)',
        borderRadius: 7,
        outline: 'none',
      },
      button: {
        padding: '7px 14px',
        fontSize: 13,
        fontWeight: 500,
        color: '#fff',
        background: 'linear-gradient(135deg,#4f7cff,#6a5cff)',
        border: 0,
        borderRadius: 7,
        cursor: 'pointer',
      },
      buttonGhost: {
        padding: '7px 14px',
        fontSize: 13,
        color: 'inherit',
        background: 'rgba(127,127,127,.1)',
        border: '1px solid rgba(127,127,127,.3)',
        borderRadius: 7,
        cursor: 'pointer',
      },
      ok: { fontSize: 12, color: '#31a56b' },
      err: { fontSize: 12, color: '#e2565f', whiteSpace: 'pre-wrap' },
      list: { margin: 0, paddingLeft: 18, fontSize: 12, opacity: 0.78, lineHeight: 1.7 },
    }

    async function call(method, path, body) {
      const headers = { accept: 'application/json' }
      if (body !== undefined) {
        headers['content-type'] = 'application/json'
        headers['x-dsh-gate'] = 'settings'
      }
      const response = await fetch(`${API}${path}`, {
        method,
        credentials: 'same-origin',
        cache: 'no-store',
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      const text = await response.text()
      let parsed
      try {
        parsed = text.length > 0 ? JSON.parse(text) : undefined
      } catch {
        parsed = undefined
      }
      if (!response.ok) {
        throw new Error((parsed && parsed.error) || `${response.status} ${response.statusText}`)
      }
      return parsed
    }

    function Row(props) {
      return react.createElement(
        'div',
        { style: styles.row },
        react.createElement('span', { style: styles.label }, props.label),
        props.children ?? react.createElement('span', { style: styles.value }, String(props.value ?? '—')),
      )
    }

    function GateSection() {
      const [data, setData] = react.useState(undefined)
      const [error, setError] = react.useState(undefined)
      const [notice, setNotice] = react.useState(undefined)
      const [busy, setBusy] = react.useState(false)
      const [form, setForm] = react.useState(undefined)

      const load = react.useCallback(async () => {
        try {
          const next = await call('GET', '/status')
          setData(next)
          setForm({
            emailTo: (next.email.to || []).join(', '),
            sessionDays: Math.round((next.session.absoluteHours / 24) * 100) / 100,
            codeTtlMinutes: next.email.codeTtlMinutes,
            resendSeconds: next.email.minIntervalSeconds,
          })
          setError(undefined)
        } catch (failure) {
          setError(String((failure && failure.message) || failure))
        }
      }, [])

      react.useEffect(() => {
        void load()
      }, [load])

      const save = async () => {
        setBusy(true)
        setNotice(undefined)
        setError(undefined)
        try {
          await call('POST', '/settings', {
            emailTo: form.emailTo,
            sessionDays: Number(form.sessionDays),
            codeTtlMinutes: Number(form.codeTtlMinutes),
            resendSeconds: Number(form.resendSeconds),
          })
          setNotice('已保存，立即生效。')
          await load()
        } catch (failure) {
          setError(String((failure && failure.message) || failure))
        } finally {
          setBusy(false)
        }
      }

      const test = async () => {
        setBusy(true)
        setNotice(undefined)
        setError(undefined)
        try {
          const result = await call('POST', '/test-email', {})
          setNotice(`测试邮件已由 SMTP 接受：${result.accepted.join(', ')}`)
        } catch (failure) {
          setError(String((failure && failure.message) || failure))
        } finally {
          setBusy(false)
        }
      }

      const logout = async () => {
        try {
          await fetch('/__gate/logout', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'x-dsh-gate': 'settings' },
          })
        } catch {
          /* the redirect handles the rest */
        }
        globalThis.location.assign('/')
      }

      if (error !== undefined && data === undefined) {
        return react.createElement(
          'div',
          { style: styles.root },
          react.createElement('h3', { style: styles.h }, '公网访问'),
          react.createElement('p', { style: styles.err }, `无法读取网关状态：${error}`),
        )
      }

      if (data === undefined || form === undefined) {
        return react.createElement(
          'div',
          { style: styles.root },
          react.createElement('h3', { style: styles.h }, '公网访问'),
          react.createElement('p', { style: styles.sub }, '正在读取网关状态…'),
        )
      }

      return react.createElement(
        'div',
        { style: styles.root },
        react.createElement(
          'div',
          { style: styles.card },
          react.createElement('h3', { style: styles.h }, '公网访问网关'),
          react.createElement(
            'p',
            { style: styles.sub },
            '本页配置的是把 dsh 暴露到公网的那层反向代理（dsh 本身始终只监听 127.0.0.1）。改动即时生效并写入 config.json。',
          ),
          react.createElement(Row, { label: '监听地址', value: `https://${data.listen.host}:${data.listen.port}` }),
          react.createElement(Row, { label: '证书', value: data.listen.tls }),
          react.createElement(Row, { label: '二次因子', value: data.secondFactor === 'email' ? '邮箱验证码' : data.secondFactor === 'totp' ? 'TOTP' : '仅口令' }),
          react.createElement(Row, { label: '登录方式', value: data.email.mode === 'password+code' ? '口令 + 邮箱验证码' : '仅邮箱验证码' }),
          react.createElement(Row, { label: 'SMTP', value: `${data.email.smtpHost}:${data.email.smtpPort}${data.email.smtpSecure ? ' (TLS)' : ' (STARTTLS)'}` }),
          react.createElement(Row, { label: '配置文件', value: data.configFile }),
        ),
        react.createElement(
          'div',
          { style: styles.card },
          react.createElement('h3', { style: styles.h }, '登录设置'),
          react.createElement(
            'div',
            { style: styles.row },
            react.createElement('span', { style: styles.label }, '验证码收件箱'),
            react.createElement('input', {
              style: styles.input,
              value: form.emailTo,
              onChange: (event) => setForm({ ...form, emailTo: event.target.value }),
              spellCheck: false,
            }),
          ),
          react.createElement(
            'p',
            { style: styles.sub },
            '多个地址用英文逗号分隔。请使用你完全掌控、且已开启二次验证的邮箱 —— 它能登录这台服务器。',
          ),
          react.createElement(
            'div',
            { style: styles.row },
            react.createElement('span', { style: styles.label }, '登录有效期'),
            react.createElement('input', {
              style: styles.input,
              type: 'number',
              min: '0.1',
              step: '0.5',
              value: form.sessionDays,
              onChange: (event) => setForm({ ...form, sessionDays: event.target.value }),
            }),
            react.createElement('span', { style: styles.sub }, '天'),
          ),
          react.createElement(
            'div',
            { style: styles.row },
            react.createElement('span', { style: styles.label }, '验证码有效期'),
            react.createElement('input', {
              style: styles.input,
              type: 'number',
              min: '1',
              max: '60',
              value: form.codeTtlMinutes,
              onChange: (event) => setForm({ ...form, codeTtlMinutes: event.target.value }),
            }),
            react.createElement('span', { style: styles.sub }, '分钟'),
          ),
          react.createElement(
            'div',
            { style: styles.row },
            react.createElement('span', { style: styles.label }, '重发间隔'),
            react.createElement('input', {
              style: styles.input,
              type: 'number',
              min: '0',
              max: '600',
              value: form.resendSeconds,
              onChange: (event) => setForm({ ...form, resendSeconds: event.target.value }),
            }),
            react.createElement('span', { style: styles.sub }, '秒（同一 IP）'),
          ),
          react.createElement(
            'div',
            { style: styles.row },
            react.createElement(
              'button',
              { style: styles.button, disabled: busy, onClick: () => void save() },
              busy ? '保存中…' : '保存',
            ),
            react.createElement(
              'button',
              { style: styles.buttonGhost, disabled: busy, onClick: () => void test() },
              '发送测试邮件',
            ),
            react.createElement(
              'button',
              { style: styles.buttonGhost, disabled: busy, onClick: () => void logout() },
              '退出登录',
            ),
          ),
          notice !== undefined ? react.createElement('p', { style: styles.ok }, notice) : null,
          error !== undefined ? react.createElement('p', { style: styles.err }, error) : null,
        ),
        react.createElement(
          'div',
          { style: styles.card },
          react.createElement('h3', { style: styles.h }, '最近事件'),
          react.createElement(
            'ul',
            { style: styles.list },
            (data.recent || []).length === 0
              ? react.createElement('li', { style: styles.sub }, '暂无记录')
              : data.recent.map((entry, index) =>
                  react.createElement(
                    'li',
                    { key: `${entry.ts}-${index}` },
                    `${new Date(entry.ts).toLocaleString()}  ${entry.event}` +
                      (entry.ip ? `  ${entry.ip}` : '') +
                      (entry.reason ? `  ${entry.reason}` : ''),
                  ),
                ),
          ),
        ),
      )
    }

    const inject = ['slots']

    function apply(ctx) {
      ctx.effect(
        () =>
          ctx.slots.inject('settings.section', () =>
            ctx.slots.register(
              {
                name: 'settings.section',
                id: SECTION_ID,
                order: 40,
                label: () => '公网访问',
                locale: NS,
              },
              GateSection,
            ),
          ),
        'public-gate: settings section',
      )
    }

    exports.Name = SECTION_ID
    exports.apply = apply
    exports.inject = inject
    return module.exports
  },
})
