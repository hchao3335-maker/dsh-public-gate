/**
 * HTML for the gate's own pages.
 *
 * Deliberately script-free (the login page runs under `script-src 'none'`, so an
 * injected payload has no execution surface) and deliberately plain: a neutral
 * card, one accent colour, no gradients or glass effects. Both colour schemes
 * follow `prefers-color-scheme`.
 */

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #f5f5f6;
  --card: #ffffff;
  --fg: #18191b;
  --muted: #6b6f76;
  --line: #e1e2e5;
  --field: #ffffff;
  --accent: #2563eb;
  --focus: rgba(37, 99, 235, 0.18);
  --danger: #b42318;
  --danger-bg: #fef3f2;
  --danger-line: #f2c6c1;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e0f11;
    --card: #161719;
    --fg: #e9eaec;
    --muted: #9aa0a8;
    --line: #2a2c30;
    --field: #111214;
    --accent: #7aa2ff;
    --focus: rgba(122, 162, 255, 0.22);
    --danger: #ff9b90;
    --danger-bg: #26120f;
    --danger-line: #4a211b;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
  background: var(--bg);
  color: var(--fg);
  font: 400 14px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto,
    "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  -webkit-font-smoothing: antialiased;
}
.card {
  width: 100%;
  max-width: 372px;
  padding: 26px 26px 20px;
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 12px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 7px;
  margin-bottom: 22px;
  font-size: 13px;
  color: var(--muted);
}
.brand svg { width: 17px; height: 17px; color: var(--accent); flex: none; }
h1 { margin: 0 0 6px; font-size: 20px; font-weight: 600; line-height: 1.3; letter-spacing: -0.01em; }
.kicker { margin: 0 0 8px; font-size: 12px; color: var(--muted); }
.lead { margin: 0 0 20px; font-size: 13px; color: var(--muted); }
.lead strong { color: var(--fg); font-weight: 500; }
.msg {
  margin: 0 0 16px;
  padding: 9px 11px;
  border: 1px solid;
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.5;
}
.msg.err { color: var(--danger); background: var(--danger-bg); border-color: var(--danger-line); }
.msg.info { margin: 0 0 14px; padding: 0; color: var(--muted); background: transparent; border: 0; }
.field { margin: 0 0 12px; }
label { display: block; margin: 0 0 5px; font-size: 12px; color: var(--muted); }
input {
  width: 100%;
  height: 38px;
  padding: 0 11px;
  font: inherit;
  color: var(--fg);
  background: var(--field);
  border: 1px solid var(--line);
  border-radius: 8px;
  outline: none;
  transition: border-color .12s, box-shadow .12s;
}
input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--focus); }
input[name="code"], input[name="totp"] { letter-spacing: .3em; font-variant-numeric: tabular-nums; }
button {
  width: 100%;
  height: 38px;
  margin-top: 4px;
  font: inherit;
  font-weight: 500;
  color: var(--card);
  background: var(--fg);
  border: 0;
  border-radius: 8px;
  cursor: pointer;
}
button:hover { opacity: .9; }
button:active { opacity: .82; }
button.ghost { margin-top: 10px; color: var(--fg); background: transparent; border: 1px solid var(--line); }
button.ghost:hover { border-color: var(--muted); opacity: 1; }
.hint { margin: 10px 0 0; font-size: 12px; color: var(--muted); }
.foot { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--line); font-size: 11px; color: var(--muted); }
`

const MARK = `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 20v-9a6 6 0 0 1 12 0v9" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="11" r="1.7" fill="currentColor"/><path d="M12 12.8V16.2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`

const FOOT = '<div class="foot">仅限授权用户访问，所有登录尝试都会记录。</div>'

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function page({ title, body }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main class="card">
<div class="brand">${MARK}<span>DeepSeek Harness</span></div>
${body}
</main>
</body>
</html>`
}

/**
 * Login entry page.
 *
 * `mode: 'password+code'` renders the username/password form; `mode: 'code-only'`
 * renders the send button AND the code field on the same page, so a blocked or
 * failed send never leaves the visitor without somewhere to type a code.
 */
export function loginPage({
  loginPath,
  sendPath,
  emailPath,
  csrf,
  error,
  info,
  username = '',
  next,
  mode = 'password+code',
  maskedEmail = '',
}) {
  const nextField = typeof next === 'string' ? `<input type="hidden" name="next" value="${escapeHtml(next)}">` : ''
  const messages = `${error !== undefined ? `<div class="msg err">${escapeHtml(error)}</div>` : ''}${
    info !== undefined ? `<div class="msg info">${escapeHtml(info)}</div>` : ''
  }`

  if (mode === 'code-only') {
    return page({
      title: '登录 · DeepSeek Harness',
      body: `
<h1>登录</h1>
<p class="lead">验证码会发送到 <strong>${escapeHtml(maskedEmail)}</strong>。先获取验证码，再填入下方。</p>
${messages}
<form method="POST" action="${escapeHtml(sendPath)}">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <button type="submit" class="ghost">获取验证码</button>
</form>
<form method="POST" action="${escapeHtml(emailPath)}" style="margin-top:14px">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <div class="field">
    <label for="c">验证码</label>
    <input id="c" name="code" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="10"
           autocomplete="one-time-code" required>
  </div>
  <button type="submit">继续</button>
</form>
${FOOT}`,
    })
  }

  return page({
    title: '登录 · DeepSeek Harness',
    body: `
<h1>登录</h1>
<p class="lead">输入账户密码以继续。</p>
${messages}
<form method="POST" action="${escapeHtml(loginPath)}" autocomplete="on">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <div class="field">
    <label for="u">用户名</label>
    <input id="u" name="username" type="text" value="${escapeHtml(username)}" autocomplete="username" required autofocus maxlength="128" spellcheck="false">
  </div>
  <div class="field">
    <label for="p">密码</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required maxlength="512">
  </div>
  <button type="submit">继续</button>
</form>
${FOOT}`,
  })
}

/** Code entry step for the email factor. */
export function emailCodePage({ emailPath, sendPath, csrf, maskedEmail, error, info, next }) {
  const nextField = typeof next === 'string' ? `<input type="hidden" name="next" value="${escapeHtml(next)}">` : ''
  return page({
    title: '输入验证码 · DeepSeek Harness',
    body: `
<p class="kicker">第 2 步，共 2 步</p>
<h1>输入验证码</h1>
<p class="lead">验证码已发送到 <strong>${escapeHtml(maskedEmail)}</strong>，10 分钟内有效，只能使用一次。</p>
${error !== undefined ? `<div class="msg err">${escapeHtml(error)}</div>` : ''}
${info !== undefined ? `<div class="msg info">${escapeHtml(info)}</div>` : ''}
<form method="POST" action="${escapeHtml(emailPath)}">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <div class="field">
    <label for="c">6 位数字</label>
    <input id="c" name="code" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="10"
           autocomplete="one-time-code" required autofocus>
  </div>
  <button type="submit">验证并进入</button>
</form>
<form method="POST" action="${escapeHtml(sendPath)}" style="margin-top:10px">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <button type="submit" class="ghost">重新发送</button>
</form>
${FOOT}`,
  })
}

export function totpPage({ totpPath, csrf, error, info }) {
  return page({
    title: '两步验证 · DeepSeek Harness',
    body: `
<p class="kicker">第 2 步，共 2 步</p>
<h1>两步验证</h1>
<p class="lead">输入认证器 App 中当前的 6 位动态码。</p>
${error !== undefined ? `<div class="msg err">${escapeHtml(error)}</div>` : ''}
${info !== undefined ? `<div class="msg info">${escapeHtml(info)}</div>` : ''}
<form method="POST" action="${escapeHtml(totpPath)}">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  <div class="field">
    <label for="t">动态码</label>
    <input id="t" name="totp" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="10"
           autocomplete="one-time-code" required autofocus>
  </div>
  <button type="submit">验证并进入</button>
</form>
${FOOT}`,
  })
}

export function messagePage({ title, heading, message, status, action }) {
  const actionHtml = action === undefined ? '' : `<div class="msg info">${escapeHtml(action)}</div>`
  return page({
    title: `${title} · DeepSeek Harness`,
    body: `
<p class="kicker">HTTP ${escapeHtml(String(status ?? '错误'))}</p>
<h1>${escapeHtml(heading)}</h1>
<p class="lead">${escapeHtml(message)}</p>
${actionHtml}
${FOOT}`,
  })
}
