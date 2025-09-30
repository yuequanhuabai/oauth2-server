# SPA + 原生 OAuth2（前后端分离）方案

> 拆代码逻辑（放在最前，便于照着拆）：

## 拆解思路（按 OAuth2 步骤定位前后端边界）

拆分的核心不是“把页面搬走”，而是沿着 OAuth2 授权码（含 PKCE）的步骤，按“是否需要保密（client_secret）”和“运行环境（浏览器还是服务器）”来划分职责。这样可以在不改协议语义的前提下，稳妥抽离前端。

[1) 授权码获取（Authorization Request → User Login → Authorization Code）]()

- 浏览器/前端职责：
  - 生成 `state`（防 CSRF）；
  - 生成 `code_verifier` 并计算 `code_challenge(S256)`；
  - 组装授权 URL：`/oauth/authorize?client_id&redirect_uri&response_type=code&state&code_challenge&code_challenge_method=S256`；
  - 跳转到授权服务器（AS）。
- 授权服务器职责：
  - 渲染登录页、校验用户口令（用户口令只能提交给 AS）；
  - 验证 `client_id/redirect_uri` 合法性；
  - 生成并重定向返回授权码 `code`（原样回传 `state`）。
- 客户端后端职责：
  - 可不参与此步；如果要“回调中转”，仅在接收 `code` 后 302 到前端服务器/页面。

2) 令牌交换（Token Exchange）

- 必须在服务器端完成（涉及 `client_secret`，绝不可放浏览器）：
  - 请求：`grant_type=authorization_code&code&code_verifier&client_id&client_secret`（表单）。
  - 由客户端后端（Java 或 Node）代表浏览器调用授权服务器 `/oauth/token`。
  - 成功后得到 `access_token`（可选 `expires_in`、`token_type`）。

3) 使用令牌访问资源（Resource Access）

- 两种做法：
  - 浏览器 → 客户端后端 `/userinfo`（推荐）：后端转发到 AS 的 `/oauth/userinfo`；好处是无需在 AS 开 CORS，也可隐藏资源端点细节；
  - 浏览器 → 授权服务器 `/oauth/userinfo`：需要为该端点配置 CORS，前端以 `Authorization: Bearer <token>` 直连。

4) PKCE 的归属

- 生成 `code_verifier/challenge` 的地方与“谁发起授权”一致：
  - SPA 方案：由浏览器生成，保存在 `sessionStorage`；
  - Node 方案：在 Node 会话中保存，浏览器只负责重定向；
- 校验逻辑只在授权服务器（AS），本项目已在 `oauth2-server` 中实现（`PkceVerifier`）。

5) 从耦合代码中“对号入座”拆除

- 找出客户端模板/脚本职责：
  - `home.html`：生成 PKCE、拼授权 URL、跳转 → 迁移到“前端入口”（SPA 脚本或 Node `/login` 重定向）；
  - `callback.html`：从 URL 取 `code`，取回 `code_verifier`，调用 `/token`、再调 `/userinfo` → 迁移到“前端回调处理”（SPA 脚本或 Node `/cb` 服务端处理）；
  - `user.html`：仅展示结果 → 可以删掉，由前端打印 JSON 或纯文本返回即可。
- 客户端后端保留哪些：
  - `/token`：服务端交换令牌（持有 `client_secret`）；
  - `/userinfo`：服务端代理拉取资源；
  - `/callback`：若要保持授权服务器注册回调不变，可做“回调中转”。
- 授权服务器（AS）不动：
  - `/oauth/authorize`、登录页、`/oauth/token`、`/oauth/userinfo` 的逻辑保持现状。

6) 拆解的落地清单（一步步做）

- 定边界：令牌交换在服务端；登录只在 AS；浏览器只负责跳转与状态保存（或 Node 代管状态）。
- 清页面：删除客户端模板与控制器中“返回视图”的方法，只保留 JSON API。
- 接口对齐：保留 `/token` 和 `/userinfo`；`/callback` 若不变更 AS 注册回调地址，则做 302 中转到前端服务器；
- 前端入口：
  - SPA 版：极简脚本生成 PKCE 与授权 URL；
  - Node 版：`/login` 生成 PKCE，`/cb` 完成交换与取数，返回 JSON（零/极少 HTML/JS）。
- CORS：仅当前端浏览器直接访问后端 API 时需要放开；服务器到服务器（Node→Java/AS）无需 CORS。

带着以上“骨架+边界”，就可以机械地把耦合代码中属于“页面/脚本”的部分迁走，把属于“持有密钥/代理资源”的部分留在后端。


本文基于当前仓库的 `oauth2-server` 与 `oauth2-client` 代码进行分析，并给出将前端代码外置为远程 SPA（HTML/CSS/JS），后端保持原生 OAuth2（不引入 Spring Security）的前后端分离实施方案。目标是最小代码量、最清晰的学习路径：理解 SPA 与 Java 后端如何配合实现 OAuth2 授权码（含 PKCE）流程。

## 1. 现状概览

- 授权服务器：`oauth2-server`（端口 8080）
  - 端点：`/oauth/authorize`（PKCE 必填）、`/oauth/token`（需要 `client_secret`，同时校验 `code_verifier`）、`/oauth/userinfo`。
  - 模板：`src/main/resources/templates/login.html`（登录页）。
  - 内存存储：`DataStore` 预置客户端：`client123/secret456`，回调：`http://localhost:8081/callback`。
  - 已实现 PKCE：`PkceVerifier` + `CodeChallengeMethod`。

- 客户端：`oauth2-client`（端口 8081）
  - 模板：`home.html`（生成 PKCE 并跳转授权）、`callback.html`（从回调页发起 `/token` 交换并拉取 `/userinfo`）、`user.html`（页面化展示）。
  - 控制器：
    - `GET /` → 返回 `home` 模板。
    - `GET /callback` → 返回 `callback` 模板（由前端脚本发起令牌交换）。
    - `POST /token` → 服务器端携带 `client_secret` 调授权服务器的 `/oauth/token`（含 `code_verifier`）。
    - `GET /userinfo` → 代理调用授权服务器 `/oauth/userinfo`（可从 Authorization 头或会话获取 token）。

当前实现属于“前后端耦合的 PKCE 演示”：前端页面由 `oauth2-client` 的模板提供，授权服务器登录页由 `oauth2-server` 模板提供。

## 2. 目标形态（前后端分离）

- 保持后端“原生 OAuth2”实现，不引入 Spring Security；授权服务器逻辑不变（继续校验 `client_secret` + PKCE）。
- 将客户端的页面（home/callback/user 展示）迁移为“远程静态 SPA”（可任意托管，如静态服务器、GitHub Pages 等）。
- `oauth2-client` 仅保留极简 API（令牌交换、用户信息代理、回调转发），不再返回模板页面。
- SPA 负责：生成 `code_verifier`/`code_challenge`（S256）、拼装授权 URL、接收回调参数、调用 `oauth2-client` 的 JSON API 完成交换与取数并渲染。

关键约束：由于授权服务器当前在 `DataStore` 中绑定了回调 `http://localhost:8081/callback`，且 `/oauth/token` 需要 `client_secret`，所以“令牌交换”必须由后端（`oauth2-client`）完成。

## 3. 目标架构与请求流（方案一：远程静态 SPA）

1) SPA（远程静态页）生成 `code_verifier` 与 `code_challenge(S256)`，构造授权 URL 并跳转至授权服务器 `/oauth/authorize`。

2) 用户在授权服务器登录页（`oauth2-server` 的 `login.html`）登录授权，随后授权服务器重定向至已注册的回调：`http://localhost:8081/callback?code=...&state=...`。

3) `oauth2-client` 的 `/callback` 不再渲染模板页面，而是 302 重定向到远程 SPA 的回调页面（例如 `https://spa.example.com/callback.html?code=...&state=...`），透传查询参数。

4) 远程 SPA 的 `callback.html` 从 URL 读取 `code`/`state`，再从 `sessionStorage` 取出 `code_verifier`，通过 CORS 调用 `http://localhost:8081/token` 执行令牌交换（后端携带 `client_id` + `client_secret` + `code_verifier` 调 `oauth2-server`）。

5) 成功后，SPA 可：
   - 直接以 `Authorization: Bearer <token>` 调用 `http://localhost:8081/userinfo`（由客户端后端代理到授权服务器），避免额外开放授权服务器 CORS；或
   - 直接跨域调用授权服务器 `http://localhost:8080/oauth/userinfo`（需在授权服务器上为该端点开放 CORS）。

推荐第一种（经 `oauth2-client` 代理），最小变更且更可控。

---

## 3+. 目标架构与请求流（方案二：Node 前端服务器，零/极少前端资源）

本方案满足“前端也用服务器部署（如 Node）且尽量不写 HTML/CSS/JS”的要求。通过服务端重定向与服务端取数完成整个流程，浏览器仅负责跳转。

- 2A（保留 `oauth2-client`，后端保持不变指授权服务器不改）：
  1) Node 服务器提供 `GET /login`：生成 `state` 与 `code_verifier`，计算 `code_challenge(S256)`，将二者存入服务端会话，构造授权 URL（`redirect_uri` 仍为 `http://localhost:8081/callback`），302 跳转至授权服务器。
  2) 授权服务器登录后按原注册回调回到 Java 客户端的 `/callback`。
  3) 将 Java 的 `/callback` 改为“回调中转”：把 `code/state` 原样 302 到 Node 的 `/cb`（Node 最终呈现结果）。
  4) Node `/cb` 校验 `state`，从会话取 `code_verifier`，服务端调用 `http://localhost:8081/token` 完成令牌交换，再服务端调用 `http://localhost:8081/userinfo` 拉取用户信息。最后向浏览器返回纯文本/JSON。（无需任何前端 JS）

- 2B（Node 直接作为机密客户端，替代 `oauth2-client`）：
  1) 将授权服务器中客户端的 `redirect_uri` 改为 Node 的 `/cb`（或支持多回调）。
  2) Node 在 `/login` 生成并保存 `state`/`code_verifier`，重定向到 `/oauth/authorize`。
  3) Node 在 `/cb` 使用 `client_id/client_secret + code_verifier` 直接调用授权服务器 `/oauth/token`，再拉取 `/oauth/userinfo`，返回纯文本/JSON。

2A 无需改授权服务器，且保留“Java 后端参与”的学习重心；2B 代码路径最短，但需要修改授权服务器里注册的回调地址并把 `client_secret` 移到 Node。

## 4. 具体改造方案

### 4.1 oauth2-server（保持不变，可选 CORS）

- 无需改动控制器与模板。
- 可选：若 SPA 选择直连 `oauth2-server` 的 `/oauth/userinfo`，可添加 CORS 允许 SPA 源（只对该端点放开）。

### 4.2 oauth2-client（精简为 API + 回调中转）

1) 移除模板与 Thymeleaf 依赖（只保留 Web/WebFlux）：

- 删除 `src/main/resources/templates` 下的 `home.html`、`callback.html`、`user.html`。
- `pom.xml` 去除 `spring-boot-starter-thymeleaf` 依赖（如果存在）。

2) 控制器改造要点：

- 删除 `GET /` 与返回视图的方法。
- 将 `GET /callback` 改为“回调中转”：读取查询参数后 302 重定向到远程回调页。

示例：

```java
// 将回调中转到 Node 前端服务器（方案 2A）
@GetMapping("/callback")
public ResponseEntity<Void> callbackRelay(@RequestParam String code,
                                          @RequestParam(required = false) String state) {
    String nodeCallback = "http://localhost:3000/cb"; // Node 前端服务器
    URI redirect = URI.create(nodeCallback + "?code=" + code + (state == null ? "" : "&state=" + state));
    return ResponseEntity.status(302).location(redirect).build();
}
```

- 保留 `POST /token` 与 `GET /userinfo` 两个 JSON API，不返回视图。
  - `/token` 入参：`{ code, code_verifier }`；服务端用 `client_id/client_secret` + `code_verifier` 调授权服务器 `/oauth/token`。
  - `/userinfo` 入参：优先从 `Authorization: Bearer` 读取 token，也可回退 session（与现有实现保持兼容）。

3) 为远程前端服务器开放 CORS（如需从浏览器直接访问 `oauth2-client` 的 API 时）：

```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/token")
                .allowedOrigins("https://spa.example.com")
                .allowedMethods("POST")
                .allowedHeaders("Content-Type")
                .allowCredentials(false);

        registry.addMapping("/userinfo")
                .allowedOrigins("https://spa.example.com")
                .allowedMethods("GET")
                .allowedHeaders("Authorization")
                .allowCredentials(false);
    }
}
```

说明：若 Node 以“服务器到服务器”方式访问 `oauth2-client`，则无需 CORS；只有浏览器直接访问时才需要。

4) 配置保持不变（关键是 `oauth2.redirect.uri=http://localhost:8081/callback` 与 `DataStore` 中一致），无需改授权服务器注册。

### 4.3 前端最简替代：Node 服务器（无/极少 HTML/JS）

以下以 Node 18+（内置 `fetch`）和 `express`、`express-session` 为例，给出两种实现：

1) 方案 2A（保留 `oauth2-client`，Node 只做前端门面）

```js
// server-2A.js
import express from 'express';
import session from 'express-session';
import crypto from 'crypto';

const app = express();
app.use(session({ secret: 'dev', resave: false, saveUninitialized: true }));

const cfg = {
  clientId: 'client123',
  authorizeUri: 'http://localhost:8080/oauth/authorize',
  redirectUri: 'http://localhost:8081/callback', // 授权服务器已注册
  javaToken: 'http://localhost:8081/token',
  javaUserinfo: 'http://localhost:8081/userinfo'
};

app.get('/', (req, res) => res.type('text').send('Use /login to start OAuth2'));

app.get('/login', async (req, res) => {
  const verifier = base64Url(crypto.randomBytes(48));
  const challenge = base64Url(crypto.createHash('sha256').update(verifier).digest());
  const state = crypto.randomUUID();
  req.session.verifier = verifier; req.session.state = state;
  const u = new URL(cfg.authorizeUri);
  u.searchParams.set('client_id', cfg.clientId);
  u.searchParams.set('redirect_uri', cfg.redirectUri);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  res.redirect(u.toString());
});

// Java 客户端将 /callback 中转到此 /cb?code=...&state=...
app.get('/cb', async (req, res) => {
  const { code, state } = req.query; const { verifier, state: s } = req.session;
  if (!code || !verifier || state !== s) return res.status(400).send('Invalid state or verifier');
  const token = await fetch(cfg.javaToken, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, code_verifier: verifier })
  }).then(r => r.json());
  if (token.error) return res.status(400).json(token);
  const user = await fetch(cfg.javaUserinfo, { headers: { Authorization: 'Bearer ' + token.access_token } }).then(r => r.json());
  res.json({ token, user });
});

function base64Url(buf){ return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

app.listen(3000, () => console.log('Node front on :3000'));
```

配套：把 `oauth2-client` 的 `/callback` 改为 302 到 `http://localhost:3000/cb?code=...&state=...`（见 4.2 示例）。

2) 方案 2B（Node 直接作为机密客户端，替代 `oauth2-client`）

```js
// server-2B.js
import express from 'express';
import session from 'express-session';
import crypto from 'crypto';

const app = express();
app.use(session({ secret: 'dev', resave: false, saveUninitialized: true }));

const cfg = {
  clientId: 'client123', clientSecret: 'secret456',
  authorizeUri: 'http://localhost:8080/oauth/authorize',
  tokenUri: 'http://localhost:8080/oauth/token',
  userinfoUri: 'http://localhost:8080/oauth/userinfo',
  redirectUri: 'http://localhost:3000/cb' // 需在授权服务器注册
};

app.get('/login', (req, res) => {
  const verifier = base64Url(crypto.randomBytes(48));
  const challenge = base64Url(crypto.createHash('sha256').update(verifier).digest());
  const state = crypto.randomUUID();
  req.session.verifier = verifier; req.session.state = state;
  const u = new URL(cfg.authorizeUri);
  u.searchParams.set('client_id', cfg.clientId);
  u.searchParams.set('redirect_uri', cfg.redirectUri);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  res.redirect(u.toString());
});

app.get('/cb', async (req, res) => {
  const { code, state } = req.query; const { verifier, state: s } = req.session;
  if (!code || !verifier || state !== s) return res.status(400).send('Invalid state or verifier');
  const form = new URLSearchParams();
  form.set('grant_type', 'authorization_code');
  form.set('code', code); form.set('code_verifier', verifier);
  form.set('client_id', cfg.clientId); form.set('client_secret', cfg.clientSecret);
  const token = await fetch(cfg.tokenUri, { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: form }).then(r => r.json());
  if (token.error) return res.status(400).json(token);
  const user = await fetch(cfg.userinfoUri, { headers: { Authorization: 'Bearer ' + token.access_token } }).then(r => r.json());
  res.json({ token, user });
});

function base64Url(buf){ return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

app.listen(3000, () => console.log('Node client on :3000'));
```

上述两种实现都无需编写前端页面与脚本，浏览器仅用于完成重定向。返回给用户的是纯 JSON，也可以改为 `text/plain`。

## 5. 迁移步骤（最小改动版）

1) 在 `oauth2-client` 中：
   - 删除模板文件，移除 Thymeleaf 依赖。
   - 修改控制器：删除返回视图的方法，新增“回调中转”。
   - 保留并确认：`POST /token` 与 `GET /userinfo` 返回 JSON；增加 CORS 允许远程 SPA 源访问。

2) 若采用方案 2A：
   - 在 Node 服务器部署 `server-2A.js`。
   - 将 `oauth2-client` 的 `/callback` 改成回调中转到 `http://localhost:3000/cb`。
   - 保持 `oauth2-server` 与 `oauth2-client` 的配置不变。

3) 若采用方案 2B：
   - 在 Node 服务器部署 `server-2B.js`。
   - 在授权服务器注册/更新客户端的 `redirect_uri` 为 `http://localhost:3000/cb`（或增加该地址）。
   - 可移除/停用 `oauth2-client` 模块（非必需）。

3) 启动两个后端：
   - `oauth2-server`：`mvn spring-boot:run`（默认 8080）。
   - `oauth2-client`：`mvn spring-boot:run`（默认 8081）。

4) 在浏览器打开远程 `https://spa.example.com/index.html`，点击登录，完成整条授权码（PKCE）流程，回到 SPA 的 `callback.html` 显示用户信息。

## 6. 备选与对比

- 方案一（远程静态 SPA）：便于理解浏览器端 PKCE 细节；需要少量前端 JS。
- 方案二（Node 前端服务器）：完全无前端资源，流程更清晰；
  - 2A：后端不改授权服务器且保留 Java 客户端的学习场景；仅把 `/callback` 改为中转。
  - 2B：路径最短但需在授权服务器注册新的回调，且把 `client_secret` 放在 Node。

## 7. 安全与实践建议

- PKCE：SPA 端生成 `code_verifier` 并仅保存在 `sessionStorage`；用后即清除，避免持久化。
- Token 管理：示例直接把 `access_token` 暴露给前端用于演示，实际可通过后端代理 `/userinfo` 避免跨域与泄露范围过大。
- CORS 最小化：仅对 `/token`、`/userinfo` 放开到指定 SPA 源，限制方法与头。
- CSRF/状态：校验 `state`，避免回放；授权码一次性使用，服务端已实现。
- HTTPS：远程 SPA 与后端接口均建议走 HTTPS，避免中间人攻击。

## 8. 成果与后续

完成后：

- 授权服务器保持原样（原生 OAuth2 + PKCE + `client_secret`）。
- 客户端后端精简为纯 API（令牌交换与用户信息代理），无模板；前端完全外置为 SPA。
- 代码更少、更清晰，聚焦学习“SPA 与 Java 后端协作完成 OAuth2 授权码（PKCE）”的核心原理。

如需，我可以按本方案进一步提交示例改造补丁（移除模板、增加 CORS、回调中转示例）。
