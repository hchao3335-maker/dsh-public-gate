/**
 * HTML for the gate's own pages. Deliberately script-free: the login page runs
 * under `script-src 'none'`, so an injected payload has no execution surface.
 */

const STYLE = `
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: grid; place-items: center;
  font-family: ui-sans-serif, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
  background: radial-gradient(1200px 600px at 50% -10%, #16203a 0%, #0a0d14 55%, #06080c 100%);
  color: #e6e9ef; padding: 24px;
}
.card {
  width: 100%; max-width: 380px; padding: 32px 28px 26px;
  background: rgba(20, 24, 34, .82); border: 1px solid rgba(255,255,255,.08);
  border-radius: 16px; box-shadow: 0 24px 64px rgba(0,0,0,.55); backdrop-filter: blur(8px);
}
.brand { display: flex; align-items: center; gap: 10px; margin-bottom: 22px; }
.mark {
  width: 34px; height: 34px; border-radius: 10px; flex: none;
  background: linear-gradient(135deg, #4f7cff, #7a5cff);
  display: grid; place-items: center; font-weight: 700; font-size: 15px; color: #fff;
}
.brand h1 { font-size: 15px; font-weight: 600; margin: 0; letter-spacing: .2px; }
.brand p { margin: 2px 0 0; font-size: 12px; color: #8b94a7; }
h2 { font-size: 19px; margin: 0 0 6px; font-weight: 600; }
.sub { margin: 0 0 20px; font-size: 13px; color: #8b94a7; line-height: 1.5; }
.field { margin-bottom: 14px; }
label { display: block; font-size: 12px; color: #9aa4b8; margin-bottom: 6px; }
input {
  width: 100%; padding: 11px 13px; font-size: 14px; color: #eef1f7;
  background: #0c1018; border: 1px solid rgba(255,255,255,.10); border-radius: 9px;
  outline: none; transition: border-color .15s, box-shadow .15s;
}
input:focus { border-color: #4f7cff; box-shadow: 0 0 0 3px rgba(79,124,255,.18); }
input[name="totp"] { letter-spacing: .5em; text-align: center; font-variant-numeric: tabular-nums; }
button {
  width: 100%; margin-top: 6px; padding: 11px; font-size: 14px; font-weight: 600;
  color: #fff; background: linear-gradient(135deg, #4f7cff, #6a5cff);
  border: 0; border-radius: 9px; cursor: pointer; transition: filter .15s;
}
button:hover { filter: brightness(1.08); }
button:disabled { filter: grayscale(.5) brightness(.8); cursor: default; }
button.secondary { background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.12); color: #c9d1e0; }
button.secondary:hover { filter: brightness(1.25); }
.msg { margin-bottom: 16px; padding: 10px 12px; border-radius: 9px; font-size: 13px; line-height: 1.45; }
.msg.err { background: rgba(220, 70, 90, .12); border: 1px solid rgba(220, 70, 90, .35); color: #ff9aa8; }
.msg.info { background: rgba(79,124,255,.10); border: 1px solid rgba(79,124,255,.32); color: #a9c0ff; }
.foot { margin-top: 18px; font-size: 11px; color: #5f6879; text-align: center; line-height: 1.6; }
.step { font-size: 11px; color: #6d768a; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 14px; }
`

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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main class="card">
  <div class="brand">
    <div class="mark">DS</div>
    <div>
      <h1>DeepSeek Harness</h1>
      <p>Public gate</p>
    </div>
  </div>
  ${body}
</main>
</body>
</html>`
}

const FOOT = '<div class="foot">Protected endpoint · all access is logged</div>'

/**
 * @param loginPath - action target.
 * @param csrf - one-time CSRF token.
 * @param error - optional error message.
 * @param info - optional informational message.
 * @param username - prefilled username.
 */
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
<h2>登录</h2>
<p class="sub">验证码会发送到 <strong>${escapeHtml(maskedEmail)}</strong>。先点「发送验证码」，再把收到的 6 位数字填进下面的框里。</p>
${messages}
<form method="POST" action="${escapeHtml(sendPath)}">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <button type="submit" class="secondary">发送验证码</button>
</form>
<form method="POST" action="${escapeHtml(emailPath)}" style="margin-top:16px">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <div class="field">
    <label for="c">验证码</label>
    <input id="c" name="code" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="10"
           autocomplete="one-time-code" required>
  </div>
  <button type="submit">验证并进入</button>
</form>
${FOOT}`,
    })
  }

  return page({
    title: '登录 · DeepSeek Harness',
    body: `
<h2>登录</h2>
<p class="sub">此页面之后是一台可执行代码的主机。请使用授权账户登录。</p>
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
    title: '邮箱验证码 · DeepSeek Harness',
    body: `
<div class="step">第 2 步 / 共 2 步</div>
<h2>邮箱验证码</h2>
<p class="sub">验证码已发送到 <strong>${escapeHtml(maskedEmail)}</strong>，10 分钟内有效。</p>
${error !== undefined ? `<div class="msg err">${escapeHtml(error)}</div>` : ''}
${info !== undefined ? `<div class="msg info">${escapeHtml(info)}</div>` : ''}
<form method="POST" action="${escapeHtml(emailPath)}">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <div class="field">
    <label for="c">验证码</label>
    <input id="c" name="code" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="10"
           autocomplete="one-time-code" required autofocus>
  </div>
  <button type="submit">验证并进入</button>
</form>
<form method="POST" action="${escapeHtml(sendPath)}" style="margin-top:10px">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  ${nextField}
  <button type="submit" class="secondary">没收到？重新发送</button>
</form>
${FOOT}`,
  })
}

export function totpPage({ totpPath, csrf, error, info }) {
  return page({
    title: '两步验证 · DeepSeek Harness',
    body: `
<div class="step">第 2 步 / 共 2 步</div>
<h2>两步验证</h2>
<p class="sub">输入认证器 App 中显示的 6 位动态验证码。</p>
${error !== undefined ? `<div class="msg err">${escapeHtml(error)}</div>` : ''}
${info !== undefined ? `<div class="msg info">${escapeHtml(info)}</div>` : ''}
<form method="POST" action="${escapeHtml(totpPath)}">
  <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
  <div class="field">
    <label for="t">验证码</label>
    <input id="t" name="totp" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="10"
           autocomplete="one-time-code" required autofocus>
  </div>
  <button type="submit">验证并进入</button>
</form>
${FOOT}`,
  })
}

export function messagePage({ title, heading, message, status, action }) {
  const actionHtml =
    action === undefined
      ? ''
      : `<div class="msg info">${escapeHtml(action)}</div>`
  return page({
    title: `${title} · DeepSeek Harness`,
    body: `
<div class="step">${escapeHtml(String(status ?? '提示'))}</div>
<h2>${escapeHtml(heading)}</h2>
<p class="sub">${escapeHtml(message)}</p>
${actionHtml}
${FOOT}`,
  })
}
