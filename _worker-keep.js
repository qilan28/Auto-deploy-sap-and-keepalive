/**
 * SAP Cloud 全能保活助手 (密码鉴权增强版)
 * 功能：密码登录 | 多账号管理 | 双重状态检测 | 异常自动重启 | 交互式面板
 */

// ================= 1. 用户配置区域 =================

// 【重要】设置后台登录密码 (留空则不开启验证，强烈建议设置！)
let ADMIN_PASSWORD = "你的登录密码"; 

let ACCOUNTS = [
  {
    name: "账号A-美国",
    email: "email_A@example.com",
    password: "password_A",
    apiUrl: "https://api.cf.us10-001.hana.ondemand.com", 
    apps: [
      { name: "应用A1", url: "https://app-a1.cfapps.us10-001.hana.ondemand.com" },
    ]
  },
  {
    name: "账号B-新加坡",
    email: "email_B@example.com",
    password: "password_B",
    apiUrl: "https://api.cf.ap21.hana.ondemand.com",
    apps: [
      { name: "应用B1", url: "https://app-b1.cfapps.ap21.hana.ondemand.com" }
    ]
  }
];

// Telegram 通知配置
let CHAT_ID = ""; 
let BOT_TOKEN = ""; 


// ================= 2. 核心工具函数 =================

const json = (o, c = 200) => new Response(JSON.stringify(o), { status: c, headers: { "content-type": "application/json;charset=UTF-8" } });

const STATE_MAP = {
  "STARTED": "运行中",
  "STOPPED": "已停止",
  "CRASHED": "已崩溃",
  "DOWN":    "离线",
  "UNKNOWN": "未知"
};

async function getAuthToken(account) {
  try {
    const uaaUrl = account.apiUrl.replace("api.cf", "uaa.cf");
    const authHeader = "Basic " + btoa("cf:");
    const body = new URLSearchParams({
      "grant_type": "password",
      "username": account.email,
      "password": account.password,
      "response_type": "token"
    });
    const res = await fetch(`${uaaUrl}/oauth/token`, {
      method: "POST",
      headers: { "Authorization": authHeader, "Content-Type": "application/x-www-form-urlencoded" },
      body: body
    });
    
    if (!res.ok) throw new Error(`登录失败: HTTP ${res.status}`);
    const data = await res.json();
    return data.access_token;
  } catch (e) {
    throw e;
  }
}

async function getAppInfo(token, apiUrl, appName) {
  const cleanName = appName.trim();
  const searchUrl = `${apiUrl}/v3/apps?names=${encodeURIComponent(cleanName)}`;
  const searchRes = await fetch(searchUrl, { headers: { "Authorization": `Bearer ${token}` } });
  if (!searchRes.ok) throw new Error(`查询API失败: ${searchRes.status}`);
  const appData = await searchRes.json();
  if (!appData.resources || appData.resources.length === 0) throw new Error(`未找到应用: ${cleanName}`);
  return { guid: appData.resources[0].guid, state: appData.resources[0].state };
}

async function sendNotify(msg) {
  if (!CHAT_ID || !BOT_TOKEN) return;
  try {
    await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: CHAT_ID, text: msg, parse_mode: "Markdown" })
    });
  } catch (e) { console.error("TG通知失败:", e); }
}

// ================= 3. Worker 主逻辑 =================

export default {
  async fetch(request, env, ctx) {
    // 环境变量覆盖
    if (env.ACCOUNTS) ACCOUNTS = JSON.parse(env.ACCOUNTS);
    CHAT_ID = env.CHAT_ID || CHAT_ID;
    BOT_TOKEN = env.BOT_TOKEN || BOT_TOKEN;
    const pwd = env.ADMIN_PASSWORD || ADMIN_PASSWORD;

    const url = new URL(request.url);

    // --- 鉴权逻辑 START ---
    if (pwd) {
      const cookie = request.headers.get('Cookie') || "";
      // 简单鉴权：检查 Cookie 是否包含正确的密码 hash (这里简化为直接比对密码，配合 HttpOnly 足够安全)
      if (!cookie.includes(`SAP_SESSION=${pwd}`)) {
        
        // 处理登录 POST 请求
        if (request.method === 'POST' && url.pathname === '/login') {
          const formData = await request.formData();
          if (formData.get('password') === pwd) {
            return new Response('登录成功，跳转中...', {
              status: 302,
              headers: {
                'Location': '/',
                // 设置 Cookie，30天过期，HttpOnly 防止 XSS
                'Set-Cookie': `SAP_SESSION=${pwd}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax`
              }
            });
          } else {
             return new Response(loginHtml("密码错误"), { headers: { 'content-type': 'text/html;charset=utf-8' }});
          }
        }
        
        // 未登录且不是 POST /login，一律显示登录页
        return new Response(loginHtml(), { headers: { 'content-type': 'text/html;charset=utf-8' }});
      }
    }
    // --- 鉴权逻辑 END ---

    // 路由: 退出登录
    if (url.pathname === '/logout') {
      return new Response('已退出', {
        status: 302,
        headers: {
          'Location': '/',
          'Set-Cookie': `SAP_SESSION=deleted; Path=/; Max-Age=0; HttpOnly`
        }
      });
    }

    // API: 获取容器状态
    if (url.pathname === "/api/status") {
      const accIdx = url.searchParams.get("acc");
      const appName = url.searchParams.get("app");
      try {
        if (!ACCOUNTS[accIdx]) throw new Error("账号不存在");
        const account = ACCOUNTS[accIdx];
        const token = await getAuthToken(account);
        const appInfo = await getAppInfo(token, account.apiUrl, appName);
        return json({ ok: true, state: STATE_MAP[appInfo.state] || appInfo.state });
      } catch (e) {
        return json({ ok: false, state: "获取失败", error: e.message });
      }
    }

    // API: 检测 URL
    if (url.pathname === "/api/check_url") {
      const targetUrl = url.searchParams.get("url");
      try {
        const start = Date.now();
        const res = await fetch(targetUrl, {
          method: 'GET',
          headers: { 'User-Agent': 'SAP-Monitor/1.0' },
          signal: AbortSignal.timeout(5000) 
        });
        const ms = Date.now() - start;
        return json({ ok: true, code: res.status, ms: ms });
      } catch (e) {
        return json({ ok: false, error: '连接超时' });
      }
    }

    // API: 执行操作
    if (url.pathname === "/api/action") {
      const accIdx = url.searchParams.get("acc");
      const appName = url.searchParams.get("app");
      const action = url.searchParams.get("action");
      try {
        const account = ACCOUNTS[accIdx];
        const token = await getAuthToken(account);
        const appInfo = await getAppInfo(token, account.apiUrl, appName);
        const endpoint = action === "restart" ? `/actions/restart` : `/actions/${action}`;
        const actionRes = await fetch(`${account.apiUrl}/v3/apps/${appInfo.guid}${endpoint}`, {
          method: "POST",
          headers: { "Authorization": `Bearer ${token}` }
        });
        if (!actionRes.ok) throw new Error(await actionRes.text());
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: e.message });
      }
    }

    // 首页
    if (url.pathname === "/") {
      return new Response(generateHtml(ACCOUNTS), { headers: { "content-type": "text/html;charset=UTF-8" } });
    }

    return new Response("404 Not Found", { status: 404 });
  },

  // 定时保活 (Cron Trigger 不受 Cookie 鉴权影响，可正常运行)
  async scheduled(event, env, ctx) {
    if (env.ACCOUNTS) ACCOUNTS = JSON.parse(env.ACCOUNTS);
    CHAT_ID = env.CHAT_ID || CHAT_ID;
    BOT_TOKEN = env.BOT_TOKEN || BOT_TOKEN;

    const tasks = [];
    for (const acc of ACCOUNTS) {
      tasks.push(async () => {
        let token = null;
        try { token = await getAuthToken(acc); } catch (e) { return; }

        for (const app of acc.apps) {
          try {
            const appInfo = await getAppInfo(token, acc.apiUrl, app.name);
            const containerState = appInfo.state;

            let urlStatus = 0;
            let urlError = null;
            try {
              const res = await fetch(app.url, { headers: { 'User-Agent': 'SAP-KeepAlive/1.0' }, signal: AbortSignal.timeout(10000) });
              urlStatus = res.status;
            } catch (e) { urlError = e.message; }

            let needRestart = false;
            let failReason = "";

            if (containerState !== 'STARTED') {
              needRestart = true; failReason = `容器状态异常 (${containerState})`;
            } else if (urlError || urlStatus !== 200) {
              needRestart = true; failReason = urlError ? `URL连接失败` : `状态码 ${urlStatus}`;
            }

            if (needRestart) {
              console.log(`[Cron] 重启: ${app.name}`);
              await fetch(`${acc.apiUrl}/v3/apps/${appInfo.guid}/actions/restart`, {
                method: "POST", headers: { "Authorization": `Bearer ${token}` }
              });
              await sendNotify(`🔄 *SAP保活重启*\n应用: ${app.name}\n原因: ${failReason}`);
            }
          } catch (e) { console.error(e); }
        }
      });
    }
    await Promise.all(tasks.map(fn => fn()));
  }
};

// ================= 4. HTML 模板 (含登录页) =================

function loginHtml(error = "") {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SAP 管理系统 - 登录</title>
  <style>
    body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; margin: 0; }
    .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 350px; text-align: center; }
    input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
    button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; }
    button:hover { background: #0056b3; }
    .error { color: red; font-size: 14px; margin-bottom: 10px; }
    h2 { margin-top: 0; color: #333; }
  </style></head><body>
  <div class="card">
    <h2>🔐 系统登录</h2>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form action="/login" method="POST">
      <input type="password" name="password" placeholder="请输入管理员密码" required autofocus>
      <button type="submit">登录</button>
    </form>
  </div></body></html>`;
}

function generateHtml(accounts) {
  let rows = "";
  accounts.forEach((acc, aIdx) => {
    acc.apps.forEach((app, pIdx) => {
      const encodedUrl = encodeURIComponent(app.url);
      rows += `
      <tr>
        <td class="col-acc"><strong>${acc.name}</strong></td>
        <td>
            <div class="app-name">${app.name}</div>
            <a href="${app.url}" target="_blank" class="app-link">打开链接</a>
        </td>
        <td><span class="state-tag loading" id="sap-state-${aIdx}-${pIdx}">查询中...</span></td>
        <td><span class="url-tag loading" id="url-state-${aIdx}-${pIdx}" data-url="${encodedUrl}">检测中...</span></td>
        <td>
          <div class="btn-group">
            <button class="btn-start" onclick="doAction(${aIdx}, '${app.name}', 'start')">启动</button>
            <button class="btn-restart" onclick="doAction(${aIdx}, '${app.name}', 'restart')">重启</button>
            <button class="btn-stop" onclick="doAction(${aIdx}, '${app.name}', 'stop')">停止</button>
          </div>
        </td>
      </tr>`;
    });
  });

  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SAP 节点监控台</title>
  <style>
    body { font-family: -apple-system, sans-serif; background: #f3f4f6; padding: 20px; color: #1f2937; }
    .container { max-width: 1100px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); position: relative; }
    h2 { text-align: center; margin-bottom: 24px; color: #111827; }
    .logout-btn { position: absolute; top: 24px; right: 24px; text-decoration: none; color: #ef4444; font-size: 14px; border: 1px solid #ef4444; padding: 4px 10px; border-radius: 4px; }
    .logout-btn:hover { background: #fee2e2; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th { background: #f9fafb; color: #6b7280; font-weight: 600; font-size: 0.85rem; padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb; }
    td { padding: 16px 12px; border-bottom: 1px solid #e5e7eb; vertical-align: middle; }
    .state-tag, .url-tag { padding: 4px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; display: inline-block; white-space: nowrap; }
    .state-运行中 { background: #dcfce7; color: #166534; } .state-已停止 { background: #f3f4f6; color: #4b5563; } .state-已崩溃 { background: #fee2e2; color: #991b1b; }
    .url-ok { background: #dbeafe; color: #1e40af; } .url-error { background: #fee2e2; color: #991b1b; } .loading { background: #f3f4f6; color: #9ca3af; }
    .app-name { font-weight: 500; font-size: 0.95rem; }
    .app-link { font-size: 0.75rem; color: #3b82f6; text-decoration: none; margin-top: 4px; display: inline-block; }
    .btn-group { display: flex; gap: 6px; }
    button { border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 0.75rem; font-weight: 500; color: white; transition: all 0.2s; }
    .btn-start { background: #10b981; } .btn-restart { background: #3b82f6; } .btn-stop { background: #ef4444; }
    button:hover { opacity: 0.9; transform: translateY(-1px); } button:disabled { opacity: 0.5; }
    @media (max-width: 768px) { .col-acc { display: none; } .btn-group { flex-direction: column; } .logout-btn { position: static; display: block; width: fit-content; margin: 0 auto 20px auto; } }
  </style>
</head><body>
  <div class="container">
    <a href="/logout" class="logout-btn">退出登录</a>
    <h2>SAP 节点监控台</h2>
    <table><thead><tr><th class="col-acc">所属账号</th><th>应用信息</th><th>容器状态 (API)</th><th>连通性 (URL)</th><th>操作</th></tr></thead>
    <tbody>${rows}</tbody></table>
  </div>
  <script>
    async function refreshSapStates() {
      const tags = document.querySelectorAll('.state-tag');
      for (const tag of tags) {
        const idParts = tag.id.split('-');
        const accIdx = idParts[2];
        const appName = document.querySelector(\`#sap-state-\${idParts[2]}-\${idParts[3]}\`).parentElement.previousElementSibling.querySelector('.app-name').innerText;
        try {
          const res = await fetch('/api/status?acc=' + accIdx + '&app=' + encodeURIComponent(appName));
          const data = await res.json();
          tag.innerText = data.state; tag.className = 'state-tag state-' + data.state;
        } catch (e) { tag.innerText = '错误'; }
      }
    }
    async function refreshUrlStates() {
      const tags = document.querySelectorAll('.url-tag');
      const promises = Array.from(tags).map(async (tag) => {
        const url = decodeURIComponent(tag.dataset.url);
        try {
          const res = await fetch('/api/check_url?url=' + encodeURIComponent(url));
          const data = await res.json();
          if (data.ok) { tag.innerText = 'HTTP ' + data.code + ' (' + data.ms + 'ms)'; tag.className = 'url-tag url-ok'; } 
          else { tag.innerText = data.error || ('HTTP ' + data.code); tag.className = 'url-tag url-error'; }
        } catch (e) { tag.innerText = '检测失败'; tag.className = 'url-tag url-error'; }
      });
      await Promise.all(promises);
    }
    async function doAction(acc, app, action) {
      const actionNames = { 'start': '启动', 'stop': '停止', 'restart': '重启' };
      if(!confirm('确认要【' + actionNames[action] + '】应用 ' + app + ' 吗？')) return;
      const btn = event.target; btn.innerText = '...'; btn.disabled = true;
      try {
        const res = await fetch('/api/action?acc=' + acc + '&app=' + encodeURIComponent(app) + '&action=' + action);
        const data = await res.json();
        if(data.ok) { alert('指令已发送'); setTimeout(() => { refreshSapStates(); refreshUrlStates(); btn.innerText = actionNames[action]; btn.disabled = false; }, 3000); }
        else { alert('失败: ' + data.error); btn.innerText = actionNames[action]; btn.disabled = false; }
      } catch (e) { alert('网络错误或鉴权过期'); location.reload(); }
    }
    window.onload = function() { refreshSapStates(); refreshUrlStates(); };
  </script>
</body></html>`;
}
