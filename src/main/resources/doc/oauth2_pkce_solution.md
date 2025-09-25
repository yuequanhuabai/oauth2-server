# OAuth2 授权码 + PKCE 改造方案

## 宏观框架逻辑

1. **保持原有授权码主流程**：沿用现有授权端点、令牌端点与用户信息端点，只在必要处插入 PKCE 参数校验，使未携带 PKCE 参数的请求明确失败，而不是影响既有逻辑。
2. **引入客户端证明链路**：客户端在发起授权请求时生成 `code_verifier`，派生 `code_challenge` 随浏览器跳转提交；授权服务器将挑战值与方法与授权码关联存储。
3. **令牌交换强化校验**：客户端在换取令牌时回传原始 `code_verifier`，授权服务器基于保存的挑战信息计算比对，验证通过后才下发访问令牌，并删除授权码，抵御授权码窃取。
4. **最小依赖改动**：继续使用核心 Spring Web 及 WebClient 依赖，只在现有模型和 Controller 层新增字段与校验逻辑，避免引入额外安全框架。
5. **全链路可观测与回退**：记录关键失败场景（缺参、校验失败、已过期等），并通过文档/日志说明如何诊断，确保 PKCE 加固后仍易于调试与维护。

## 具体操作步骤

### 1. 共享准备
- 在 `oauth2-server` 与 `oauth2-client` 中创建用于 Base64URL 编码的工具（若已有可复用），确保按 RFC 7636 要求去掉填充、使用 URL 安全字符集。
- 更新 `src/main/resources/doc/oauth2_solution.md` 与 `command.md` 等文档，记录引入 PKCE 的背景、参数说明、失败响应示例与测试步骤。

### 2. 授权服务器改造（`oauth2-server`）
1. **数据模型扩展**
   - 在 `AuthCode` 类中新增 `codeChallenge` 与 `codeChallengeMethod` 字段及访问器。
   - 在 `DataStore` 中创建/更新存储授权码的 `Map` 时，支持保存上述字段。
2. **登录模板透传**
   - 在 `templates/login.html` 中为隐藏字段增加 `code_challenge`、`code_challenge_method`，并在渲染模型中设置默认空值（便于显示错误或重填）。
3. **授权端点增强 (`OAuth2Controller#authorize` GET/POST)**
   - GET：读取 `code_challenge` 与 `code_challenge_method` 参数，校验 `code_challenge_method` 仅允许 `S256`（可选兼容 `plain`）。参数缺失或非法时返回错误页面。
   - POST：生成授权码前将挑战信息写入 `AuthCode` 对象；若没有挑战信息，应拒绝授权以确保所有客户端走 PKCE。
4. **令牌端点校验 (`OAuth2Controller#token`)**
   - 新增 `code_verifier` 请求参数，缺失时返回 `invalid_request`。
   - 根据授权码保存的 `codeChallengeMethod`：
     - `S256`：对 `code_verifier` 做 SHA-256，再 Base64URL 编码，与存储的 `codeChallenge` 对比。
     - `plain`：直接比较字符串。
   - 校验失败时返回 `invalid_grant` 并删除授权码。
   - 校验成功后按原逻辑生成访问令牌并删除授权码（保持一次性使用）。
5. **错误反馈与日志**
   - 在关键失败分支记录日志（授权码缺失、校验失败、过期），助于运维定位问题。

### 3. 客户端改造（`oauth2-client`）
1. **生成并存储 `code_verifier`**
   - 在 `OAuth2ClientController#login` 中生成长度至少 43 字节、使用字母数字加特殊字符（`-._~`）的高熵字符串，保存到用户 Session。
2. **构建授权请求**
   - 计算 `code_challenge = Base64URL(SHA256(code_verifier))`。
   - 在重定向 URL 中追加 `code_challenge`、`code_challenge_method=S256`。
3. **令牌交换**
   - `OAuth2Service#getAccessToken` 在表单参数中加入 `code_verifier`。
   - 若后端返回 `invalid_grant` 或 `invalid_request`，在客户端记录日志并向用户展示友好错误信息。
4. **降级策略（可选）**
   - 若需兼容不支持 PKCE 的授权服务器，可在配置中开关 `code_challenge_method`；本项目默认强制开启以示范最佳实践。

### 4. 配置与文档
- 在客户端 `application.properties` 中增加关于 PKCE 的注释说明（无需新增配置项）。
- `oauth2_pkce_solution.md`、`oauth2_solution.md` 与 README 中更新 PKCE 概述、请求示例、错误码说明。
- 若有 API 文档（如 `command.md`），同步标注新增参数与返回结构。

### 5. 测试与验证
1. **正向回归**：
   - 按运行指南启动服务，走完整版 OAuth2 + PKCE 流程，确认令牌成功获取并展示用户信息。
2. **安全场景验证**：
   - 修改回调请求中的 `code_verifier`，确认令牌端点返回 `invalid_grant`。
   - 重放已使用授权码或过期授权码，验证失败响应与日志。
3. **兼容检查**：
   - 若启用 `plain` 方法，确保服务端能正确处理并返回令牌；默认应保持 `S256`。
4. **自动化（可选）**：
   - 为 `OAuth2Controller` 与 `OAuth2Service` 编写单元测试覆盖成功/失败分支，确保校验逻辑稳定。

