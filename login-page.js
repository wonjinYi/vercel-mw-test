function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

export function loginPage(destination, error = '') {
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>로그인</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; min-height: 100svh; display: grid; place-items: center; padding: 24px; background: #f4f6fa; color: #172235; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Malgun Gothic", sans-serif; }
    main { width: 100%; max-width: 400px; padding: 36px 32px; background: #fff; border: 1px solid #e1e6ee; border-radius: 16px; box-shadow: 0 12px 36px #1722350a; }
    .eyebrow { margin: 0 0 12px; color: #53637c; font-size: 11px; font-weight: 700; letter-spacing: .16em; }
    h1 { margin: 0; font-size: 28px; letter-spacing: -.04em; }
    .intro { margin: 12px 0 28px; color: #647087; font-size: 14px; line-height: 1.7; }
    label { display: block; margin: 20px 0 8px; font-size: 13px; font-weight: 600; }
    input { width: 100%; min-height: 46px; padding: 12px; border: 1px solid #cdd5e1; border-radius: 8px; background: #fff; color: #172235; font: inherit; font-size: 16px; }
    input:focus-visible { outline: 3px solid #b5cdfb; outline-offset: 2px; border-color: #315fb4; }
    button { width: 100%; min-height: 48px; margin-top: 28px; padding: 12px 16px; border: 0; border-radius: 8px; background: #244d91; color: #fff; font: inherit; font-weight: 600; cursor: pointer; }
    button:hover { background: #193b74; }
    button:focus-visible { outline: 3px solid #90b3f0; outline-offset: 3px; }
    .error { margin: 20px 0 0; padding: 12px; border: 1px solid #f0cccc; border-radius: 8px; background: #fff5f5; color: #982d2d; font-size: 13px; line-height: 1.6; }
    @media (max-width: 420px) { main { padding: 28px 24px; } }
  </style>
</head>
<body>
  <main aria-labelledby="login-title">
    <p class="eyebrow">PRIVATE ACCESS</p>
    <h1 id="login-title">로그인</h1>
    <p class="intro">계속하려면 사용자이름과 비밀번호를 입력해 주세요.</p>
    <form action="/_auth/login" method="post" accept-charset="UTF-8">
      <input type="hidden" name="next" value="${escapeHtml(destination)}">
      <label for="username">사용자이름</label>
      <input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required>
      <label for="password">비밀번호</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}
      <button type="submit">로그인</button>
    </form>
  </main>
</body>
</html>`;
}
