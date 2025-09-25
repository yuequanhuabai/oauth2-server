# OAuth2 PKCE 实现方案 - 授权码模式增强

## 目标与背景

现有项目演示了纯手工的授权码模式，客户端通过 `client_secret` 与授权码换取访问令牌。为了增强公共客户端（浏览器、SPA、原生 APP）的安全性，需要引入 **PKCE（Proof Key for Code Exchange）**：

- 消除授权码在回调过程中被截获后直接换取令牌的风险。
- 允许无需保密 `client_secret` 的客户端安全地使用授权码模式。
- 保留当前的整体架构，仅扩展必要的字段与校验逻辑。

下文给出如何在 `oauth2-server` 与 `oauth2-client` 上落地 PKCE，并提供一个仅使用原生 JavaScript 的最小示例页面。

## PKCE 流程回顾

PKCE 在标准授权码模式基础上新增三项内容：

1. **生成 code_verifier**：客户端在本地生成长度 43-128 的高熵字符串，仅保存在本地。
2. **派生 code_challenge**：客户端使用 `S256`(SHA-256) 或 `plain` 算法对 `code_verifier` 处理后作为 `code_challenge`，随授权请求一同发送。
3. **校验**：授权服务器在令牌端点收到 `code_verifier` 后，按 `code_challenge_method` 重新计算 `code_challenge` 并与授权阶段缓存的值对比，匹配后才发放访问令牌。

## 服务端改造（oauth2-server）

### 1. 数据模型扩展

在 `AuthCode` 中新增字段保存 PKCE 信息，并引入一个枚举指示算法：

```java
public class AuthCode {
    private String code;
    private String clientId;
    private String username;
    private long expireTime;
    private String codeChallenge;
    private CodeChallengeMethod codeChallengeMethod;
    // 构造器、getter/setter 省略
}

public enum CodeChallengeMethod {
    S256, PLAIN;
}
```

授权码写入与读取的位置均需要相应补充 `codeChallenge` 与 `codeChallengeMethod`。

### 2. 授权端点 (`GET /oauth/authorize`)

- 新增必填参数 `code_challenge`，可选 `code_challenge_method`（默认为 `S256`）。
- 允许仅支持 `S256`，对不支持的 method 返回错误页，避免降级到不安全算法。
- 将 `code_challenge` 与 `method` 透传到登录页，作为隐藏表单字段，保证 POST 提交时仍可获取。

```java
if (!"S256".equalsIgnoreCase(codeChallengeMethod)) {
    model.addAttribute("error", "unsupported_code_challenge_method");
    return "error";
}
model.addAttribute("code_challenge", codeChallenge);
model.addAttribute("code_challenge_method", codeChallengeMethod.toUpperCase());
```

### 3. 授权处理 (`POST /oauth/authorize`)

- 登录验证通过后，生成授权码时写入 `codeChallenge` 与 `codeChallengeMethod`。
- 若缺失 `code_challenge`，直接返回错误，强制客户端按 PKCE 流程接入。

```java
AuthCode authCode = new AuthCode(code, client_id, username,
    System.currentTimeMillis() + 600_000,
    codeChallenge,
    CodeChallengeMethod.valueOf(codeChallengeMethod));
```

### 4. 令牌端点 (`POST /oauth/token`)

- 新增必填参数 `code_verifier`。
- 读取授权码记录中的 `codeChallenge` 与 `method`，调用工具类校验：

```java
String codeVerifier = request.getParameter("code_verifier");
if (!PkceVerifier.matches(codeVerifier, authCode.getCodeChallenge(), authCode.getCodeChallengeMethod())) {
    response.put("error", "invalid_grant");
    return response;
}
```

- 通过校验后，与原逻辑一致生成访问令牌，并删除授权码。

### 5. PKCE 校验工具

新增 `PkceVerifier`，封装 `S256` 和 `plain` 的对比逻辑：

```java
public final class PkceVerifier {
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    public static boolean matches(String codeVerifier, String expectedChallenge, CodeChallengeMethod method) {
        if (codeVerifier == null || codeVerifier.length() < 43 || codeVerifier.length() > 128) {
            return false;
        }
        String actual;
        if (method == CodeChallengeMethod.S256) {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            actual = BASE64_URL.encodeToString(digest);
        } else {
            actual = codeVerifier;
        }
        return expectedChallenge.equals(actual);
    }
    private PkceVerifier() {}
}
```

> 推荐仅允许 `S256`，如确有需要保留 `plain`，也要限制 `code_verifier` 的字符集与长度。

### 6. 模板更新 (`templates/login.html`)

在隐藏字段里加上 `code_challenge` 与 `code_challenge_method`，以便授权表单提交时带回服务端：

```html
<input type="hidden" name="code_challenge" th:value="${code_challenge}" />
<input type="hidden" name="code_challenge_method" th:value="${code_challenge_method}" />
```

若 `state` 未传入，可默认空字符串，避免模板渲染报错。

## 客户端改造与最小原生 JS 示例

目标：使用最少的 HTML/JS，即刻发起 PKCE 授权、处理回调并从服务器获取用户信息。以下示例可放入 `oauth2-client/src/main/resources/templates` 中替换原页面（或作为静态文件挂载），示范生成 `code_verifier`、`code_challenge` 和回调处理流程。

### 1. 首页 `home.html`

```html
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>PKCE Demo</title></head>
<body>
<h1>OAuth2 PKCE Demo</h1>
<button id="login-btn">Login with PKCE</button>
<script>
const config = {
  clientId: 'client123',
  authorizeUri: 'http://localhost:8080/oauth/authorize',
  redirectUri: 'http://localhost:8081/callback',
  scope: 'read'
};

async function startPkce() {
  const codeVerifier = generateVerifier();
  sessionStorage.setItem('pkce_code_verifier', codeVerifier);
  const codeChallenge = await generateChallenge(codeVerifier);
  const authorizeUrl = new URL(config.authorizeUri);
  authorizeUrl.searchParams.set('client_id', config.clientId);
  authorizeUrl.searchParams.set('redirect_uri', config.redirectUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', config.scope);
  authorizeUrl.searchParams.set('state', crypto.randomUUID());
  authorizeUrl.searchParams.set('code_challenge', codeChallenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');
  window.location = authorizeUrl.toString();
}

function generateVerifier(length = 64) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const random = new Uint8Array(length);
  crypto.getRandomValues(random);
  return Array.from(random, b => chars[b % chars.length]).join('');
}

async function generateChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(digest);
  let str = '';
  bytes.forEach(b => str += String.fromCharCode(b));
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

document.getElementById('login-btn').onclick = startPkce;
</script>
</body>
</html>
```

> 页面只包含核心逻辑：生成 verifier、challenge 并跳转。无额外样式或第三方库。

### 2. 回调页 `callback.html`

```html
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>PKCE Callback</title></head>
<body>
<p>Authorizing...</p>
<script>
(async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  if (!code) {
    document.body.textContent = '授权失败：缺少 code';
    return;
  }
  const verifier = sessionStorage.getItem('pkce_code_verifier');
  if (!verifier) {
    document.body.textContent = '授权失败：code_verifier 丢失';
    return;
  }
  try {
    const tokenResp = await fetch('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, state, code_verifier: verifier })
    }).then(r => r.json());
    if (tokenResp.error) throw new Error(tokenResp.error);
    const userInfo = await fetch('/userinfo', {
      headers: { 'Authorization': 'Bearer ' + tokenResp.access_token }
    }).then(r => r.json());
    sessionStorage.removeItem('pkce_code_verifier');
    document.body.innerHTML = '<h1>欢迎, ' + userInfo.name + '</h1>';
  } catch (err) {
    document.body.textContent = '授权失败：' + err.message;
  }
})();
</script>
</body>
</html>
```

> 为保持示例简洁，这里假设客户端自身暴露 `/token` 和 `/userinfo` 代理接口，将请求转发到授权服务器的 `/oauth/token` 与 `/oauth/userinfo`。若需直接调用授权服务器，请使用其完整地址并处理 CORS。

### 3. 客户端后端 (`OAuth2ClientController` / `OAuth2Service`)

- `OAuth2ClientController` 在 `/login` 逻辑中不再生成 state/challenge，而由前端负责。可保留服务器端 state 验证作为兜底。
- `/callback` 仅负责读取授权码（或改为静态页面处理，如上示例）。如仍由后端发起令牌交换，需要将 `code_verifier` 从前端传回（可使用 `sessionStorage` + cookie 传递或直接改用纯前端交换）。
- `OAuth2Service.getAccessToken` 新增 `code_verifier` 参数：

```java
params.add("code_verifier", codeVerifier);
```

## 运行与验证

1. 更新 `oauth2-server`：
   - 扩展数据模型、控制器、校验工具类。
   - 模板加入 PKCE 隐藏字段。
2. 更新 `oauth2-client`：
   - 使用上述最小前端页面或等价逻辑生成 `code_challenge`。
   - 令牌交换时携带 `code_verifier`。
3. 启动两端应用，访问客户端首页，点击按钮完成授权，确认授权服务器的日志存在 `code_challenge` / `code_verifier` 校验记录。
4. 测试异常路径：
   - 拦截 `code_verifier` 置空，应返回 `invalid_grant`。
   - 修改 `code_verifier`，校验失败。

## 兼容性与安全提示

- 浏览器端使用 `crypto.subtle` 需要 HTTPS 或 `localhost`。部署到外网时务必使用 HTTPS。
- 若仍需兼容旧的非 PKCE 客户端，可在服务端保留旧逻辑，但建议通过客户端注册表配置是否接受无 PKCE 请求，并为公共客户端强制开启。
- `code_verifier` 建议使用 `sessionStorage`，避免跨 tab 泄漏；若需跨端共享，需加密持久化存储。
- 在日志或错误信息中避免输出完整 `code_verifier` 与 `access_token`。
