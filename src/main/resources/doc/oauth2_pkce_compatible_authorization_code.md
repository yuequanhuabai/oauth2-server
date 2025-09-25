# OAuth2 授权码 + PKCE 兼容方案

## 目标
- **保持现有授权码客户端可用**：未立即接入 PKCE 的客户端不受影响，继续按原协议运行。
- **逐步引入 PKCE 防护**：为新客户端提供 PKCE 支持，并允许对接成功后再逐步收紧策略。
- **可配置的演进路径**：通过配置或白名单控制强制 PKCE 的范围，支持灰度、回滚和监控。

## 宏观设计
1. **协议向后兼容**：
   - 当请求携带 `code_challenge` 时按照 PKCE 流程处理；
   - 未携带 PKCE 参数时，回落到原始授权码逻辑（相当于“legacy 模式”）。
2. **可控的强制策略**：
   - 使用应用配置、环境变量或客户端注册信息标记哪些客户端必须使用 PKCE；
   - 支持运行时调整策略（如配置中心或热更新），降低上线风险。
3. **增强的检测与告警**：
   - 日志中区分 PKCE / legacy 调用，便于统计迁移进度；
   - 若某客户端在限定时间内仍未迁移，可结合监控发出预警。
4. **清晰的迁移阶段**：
   - 阶段1：PKCE 可选（默认兼容）；
   - 阶段2：对关键客户端或新注册客户端强制 PKCE；
   - 阶段3：当全部客户端完成改造后，关闭 legacy 模式。

## 授权服务器改造要点

### 1. 配置开关与客户端标识
- 在 `application.yml` 或独立配置类中增加开关，例如：
  ```yaml
  security:
    pkce:
      enabled-by-default: false   # 默认为兼容模式
      required-clients:           # 可选，强制 PKCE 的客户端列表
        - client_pkce_only
  ```
- `DataStore` 或客户端实体中增加字段 `pkceRequired`，标记该客户端是否强制走 PKCE。

### 2. 授权端点（GET `/oauth/authorize`）
- 校验逻辑：
  1. 获取客户端配置判断是否强制 PKCE；
  2. 如果强制且缺少 `code_challenge` / `code_challenge_method`，直接返回错误；
  3. 如果未强制而缺参，则标记为 legacy 请求，允许继续；
  4. 若带参则验证 `code_challenge_method` 合法性（支持 `S256`，可选 `plain`），并把参数写入 `Model` 返回给登录页。

### 3. 授权端点（POST `/oauth/authorize`）
- 根据 GET 阶段判定的模式：
  - PKCE 模式：`AuthCode` 保存 `codeChallenge` 与 `codeChallengeMethod`；
  - Legacy 模式：`AuthCode` 中记录 `codeChallenge=null`，后续令牌端点据此跳过校验。
- 建议在授权码对象中添加布尔字段 `pkceEnabled`，方便后续判断。

### 4. 令牌端点（POST `/oauth/token`）
- 扩展参数解析：增加可选的 `code_verifier`。
- 校验流程：
  1. 读取授权码对象：
     - 若 `pkceEnabled=true`，校验 `code_verifier` 是否存在并匹配；
     - 若 `pkceEnabled=false`，允许没有 `code_verifier`，维持旧逻辑。
  2. 对强制 PKCE 的客户端，如果 `code_verifier` 缺失则返回 `invalid_request`。
  3. 仍保留授权码时效校验、一致性校验，以及使用后删除授权码。

## 客户端改造建议

### 1. 客户端分类
- **老客户端（Legacy）**：暂不改动，继续按原逻辑请求。
- **新客户端或升级客户端**：
  - 修改登录流程生成 `code_verifier` 并保存；
  - 授权请求带上 `code_challenge` / `code_challenge_method`；
  - 令牌交换时提交 `code_verifier`。

### 2. 配置管理
- 在客户端配置文件中添加注释或开关，提醒是否启用 PKCE；
- 对外发布接入文档，要求新接入的客户端默认开启 PKCE。

## 迁移与发布策略

1. **阶段性灰度**：
   - 先在测试环境开启 `enabled-by-default=false`，验通过后发布；
   - 在生产环境启用兼容模式，观测日志确认未带 PKCE 的客户端列表。
2. **通知与改造**：
   - 告知客户端团队升级时间表；
   - 对新注册客户端启用 `pkceRequired=true`。
3. **监控与告警**：
   - 统计授权码请求中 PKCE/legacy 占比，设置阈值；
   - 针对强制 PKCE 的客户端添加异常报警。
4. **最终收紧**：
   - 当所有客户端迁移完成后，将 `enabled-by-default` 置为 `true`，并清空 legacy 逻辑；
   - 回收配置、清理兼容代码，简化维护。

## 测试要点
1. **回归**：
   - Legacy 客户端：不传 PKCE 参数，授权码流程应成功。
   - PKCE 客户端：按 RFC 7636 全流程验证，令牌交换需带 `code_verifier`。
2. **强制策略**：
   - 将某客户端标记为强制 PKCE，模拟缺参请求，期望返回 `invalid_request`。
3. **错误场景**：
   - 提交错误的 `code_verifier`，验证返回 `invalid_grant`。
   - 重放授权码，验证一次性使用仍有效。
4. **监控验证**：
   - 检查日志/指标是否能区分 PKCE 与 legacy 请求，确认统计数据正确。

## 文档与培训
- 更新 `oauth2_solution.md`、`command.md` 等文件，说明兼容策略与配置项含义。
- 为客户端提供接入手册：如何生成 `code_verifier`、如何调试、常见错误及解决办法。
- 在团队内部培训上线步骤和故障排查流程，确保多人掌握改造要点。

