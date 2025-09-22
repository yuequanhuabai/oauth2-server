# OAuth2 原生实现方案 - 深入理解OAuth2机制

## 概述

这是一个完全手工实现的OAuth2授权码模式演示项目，**不使用Spring Security OAuth2**，而是从零开始实现OAuth2的核心机制。通过这个项目，你将深入理解OAuth2的每一个步骤和参数含义。

### OAuth2授权码流程的核心步骤

OAuth2授权码模式包含以下关键步骤，每个步骤都有明确的作用：

1. **授权请求 (Authorization Request)**
   - **作用**: 客户端将用户重定向到授权服务器，请求授权
   - **关键参数**: `client_id`(客户端标识)、`redirect_uri`(回调地址)、`state`(防CSRF攻击)

2. **用户授权 (User Authorization)**
   - **作用**: 用户在授权服务器登录并同意授权给客户端
   - **安全机制**: 用户凭证只提交给授权服务器，客户端无法获取

3. **授权码返回 (Authorization Code Grant)**
   - **作用**: 授权服务器生成临时授权码，重定向回客户端
   - **安全特性**: 授权码短期有效(通常10分钟)，且只能使用一次

4. **令牌交换 (Token Exchange)**
   - **作用**: 客户端用授权码+客户端凭证换取访问令牌
   - **安全机制**: 需要客户端密钥验证，确保令牌不被恶意获取

5. **资源访问 (Resource Access)**
   - **作用**: 客户端使用访问令牌访问受保护的用户资源
   - **优势**: 令牌可以限制访问范围和有效期

## 项目结构
```
oauth2/
├── oauth2-server/     # 授权服务器 (纯手工实现OAuth2协议)
└── oauth2-client/     # 客户端应用 (手动处理OAuth2流程)
```

## 1. OAuth2-Server (授权服务器) - 原生实现

### 1.1 添加依赖 (pom.xml)

**依赖说明**: 授权服务器只需要最基础的依赖，不引入Spring Security相关组件

```xml
<dependencies>
    <!-- Spring Boot Web: 提供REST API和HTTP服务能力 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <!-- 作用:
             1. 内置Tomcat服务器，处理HTTP请求
             2. Spring MVC框架，支持@Controller、@RequestMapping等注解
             3. JSON序列化，自动将Java对象转换为JSON响应
        -->
    </dependency>

    <!-- Thymeleaf模板引擎: 渲染动态HTML页面 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
        <!-- 作用:
             1. 渲染登录页面(login.html)，支持动态数据绑定
             2. 模板语法支持，如 th:value="${client_id}"
             3. 自动配置视图解析器，Controller返回字符串自动映射到模板
        -->
    </dependency>
</dependencies>
```

**为什么不使用Spring Security?**
- 我们要手动实现OAuth2协议的每个细节
- 深入理解授权码生成、令牌交换等核心机制
- 避免框架"黑盒"，掌握OAuth2的本质原理

### 1.2 配置文件 (application.yml)
```yaml
server:
  port: 8080
spring:
  application:
    name: oauth2-server
```

### 1.3 数据存储 (内存模拟)
```java
@Component
public class DataStore {
    // 客户端信息
    private final Map<String, ClientInfo> clients = new HashMap<>();
    // 用户信息
    private final Map<String, User> users = new HashMap<>();
    // 授权码
    private final Map<String, AuthCode> authCodes = new HashMap<>();
    // 访问令牌
    private final Map<String, AccessToken> accessTokens = new HashMap<>();

    @PostConstruct
    public void init() {
        // 初始化客户端
        clients.put("client123", new ClientInfo("client123", "secret456",
            "http://localhost:8081/callback"));

        // 初始化用户
        users.put("admin", new User("admin", "123456", "管理员"));
    }

    // getter方法...
}
```

### 1.4 数据模型
```java
// ClientInfo.java
public class ClientInfo {
    private String clientId;
    private String clientSecret;
    private String redirectUri;
    // 构造器和getter/setter
}

// User.java
public class User {
    private String username;
    private String password;
    private String displayName;
    // 构造器和getter/setter
}

// AuthCode.java
public class AuthCode {
    private String code;
    private String clientId;
    private String username;
    private long expireTime;
    // 构造器和getter/setter
}

// AccessToken.java
public class AccessToken {
    private String token;
    private String clientId;
    private String username;
    private long expireTime;
    // 构造器和getter/setter
}
```

### 1.5 OAuth2Controller - 核心实现

**控制器说明**: 这是OAuth2授权服务器的核心，实现了OAuth2协议的4个关键端点

```java
@Controller
public class OAuth2Controller {

    @Autowired
    private DataStore dataStore;

    // =============== 步骤1: 授权端点 - 显示登录页面 ===============
    @GetMapping("/oauth/authorize")
    public String authorize(@RequestParam String client_id,         // 客户端ID
                          @RequestParam String redirect_uri,       // 重定向URI
                          @RequestParam String response_type,      // 响应类型(固定为code)
                          @RequestParam(required = false) String state,  // 状态参数(防CSRF)
                          Model model) {

        // 【安全检查1】验证客户端是否存在且redirect_uri是否匹配
        ClientInfo client = dataStore.getClients().get(client_id);
        if (client == null || !client.getRedirectUri().equals(redirect_uri)) {
            return "error";  // 返回错误页面
        }

        // 【数据传递】将参数传递给登录页面模板
        model.addAttribute("client_id", client_id);
        model.addAttribute("redirect_uri", redirect_uri);
        model.addAttribute("state", state);

        return "login";  // 渲染登录页面(src/main/resources/templates/login.html)
    }

    // =============== 步骤2: 处理用户登录和授权 ===============
    @PostMapping("/oauth/authorize")
    public String handleAuthorize(@RequestParam String client_id,
                                @RequestParam String redirect_uri,
                                @RequestParam(required = false) String state,
                                @RequestParam String username,    // 用户输入的用户名
                                @RequestParam String password) {  // 用户输入的密码

        // 【安全检查2】验证用户凭证
        User user = dataStore.getUsers().get(username);
        if (user == null || !user.getPassword().equals(password)) {
            // 登录失败，重定向回登录页面并显示错误
            return "redirect:/oauth/authorize?client_id=" + client_id +
                   "&redirect_uri=" + redirect_uri + "&response_type=code&error=invalid_user";
        }

        // 【核心逻辑1】生成授权码 - OAuth2的关键机制
        String code = UUID.randomUUID().toString();  // 生成随机授权码
        AuthCode authCode = new AuthCode(code, client_id, username,
                                        System.currentTimeMillis() + 600000); // 10分钟过期
        dataStore.getAuthCodes().put(code, authCode);

        // 【协议实现】构建重定向URL，将授权码返回给客户端
        String redirectUrl = redirect_uri + "?code=" + code;
        if (state != null) {
            redirectUrl += "&state=" + state;  // 原样返回state参数
        }

        return "redirect:" + redirectUrl;  // 重定向回客户端
    }

    // =============== 步骤3: 令牌端点 - 用授权码换取访问令牌 ===============
    @PostMapping("/oauth/token")
    @ResponseBody
    public Map<String, Object> token(@RequestParam String grant_type,     // 授权类型
                                   @RequestParam String code,             // 授权码
                                   @RequestParam String client_id,        // 客户端ID
                                   @RequestParam String client_secret) {  // 客户端密钥

        Map<String, Object> response = new HashMap<>();

        // 【安全检查3】验证客户端凭证 - 防止恶意客户端获取令牌
        ClientInfo client = dataStore.getClients().get(client_id);
        if (client == null || !client.getClientSecret().equals(client_secret)) {
            response.put("error", "invalid_client");
            return response;
        }

        // 【安全检查4】验证授权码的有效性和时效性
        AuthCode authCode = dataStore.getAuthCodes().get(code);
        if (authCode == null || authCode.getExpireTime() < System.currentTimeMillis()) {
            response.put("error", "invalid_grant");
            return response;
        }

        // 【核心逻辑2】生成访问令牌 - OAuth2的最终目标
        String accessToken = UUID.randomUUID().toString();
        AccessToken token = new AccessToken(accessToken, client_id, authCode.getUsername(),
                                          System.currentTimeMillis() + 3600000); // 1小时过期
        dataStore.getAccessTokens().put(accessToken, token);

        // 【安全机制】删除已使用的授权码 - 确保授权码只能使用一次
        dataStore.getAuthCodes().remove(code);

        // 【协议响应】返回标准的OAuth2令牌响应
        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);

        return response;
    }

    // =============== 步骤4: 用户信息端点 - 使用访问令牌获取用户信息 ===============
    @GetMapping("/oauth/userinfo")
    @ResponseBody
    public Map<String, Object> userinfo(@RequestHeader("Authorization") String authorization) {

        Map<String, Object> response = new HashMap<>();

        // 【协议解析】解析Bearer令牌格式
        if (!authorization.startsWith("Bearer ")) {
            response.put("error", "invalid_token");
            return response;
        }

        String tokenValue = authorization.substring(7);  // 提取令牌值
        AccessToken token = dataStore.getAccessTokens().get(tokenValue);

        // 【安全检查5】验证访问令牌的有效性和时效性
        if (token == null || token.getExpireTime() < System.currentTimeMillis()) {
            response.put("error", "invalid_token");
            return response;
        }

        // 【业务逻辑】返回用户信息 - 这是受保护的资源
        User user = dataStore.getUsers().get(token.getUsername());
        response.put("sub", user.getUsername());        // 用户标识(OpenID Connect标准)
        response.put("name", user.getDisplayName());    // 显示名称
        response.put("username", user.getUsername());   // 用户名

        return response;
    }
}
```

**关键设计说明**:
1. **授权码机制**: 避免直接暴露访问令牌，增加安全层级
2. **双重验证**: 客户端凭证验证 + 授权码验证，确保安全性
3. **时效控制**: 授权码10分钟、访问令牌1小时，平衡安全与可用性
4. **一次性使用**: 授权码使用后立即删除，防止重放攻击

### 1.6 登录页面 (src/main/resources/templates/login.html)
```html
<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 授权服务器</title>
    <meta charset="UTF-8">
</head>
<body>
    <h2>用户登录</h2>
    <form method="post" action="/oauth/authorize">
        <input type="hidden" name="client_id" th:value="${client_id}"/>
        <input type="hidden" name="redirect_uri" th:value="${redirect_uri}"/>
        <input type="hidden" name="state" th:value="${state}"/>

        <p>
            用户名: <input type="text" name="username" placeholder="admin"/>
        </p>
        <p>
            密码: <input type="password" name="password" placeholder="123456"/>
        </p>
        <p>
            <button type="submit">登录并授权</button>
        </p>
    </form>
</body>
</html>
```

## 2. OAuth2-Client (客户端) - 原生实现

### 2.1 添加依赖 (pom.xml)

**依赖说明**: 客户端需要HTTP请求能力来与授权服务器通信

```xml
<dependencies>
    <!-- Spring Boot Web: 提供Web服务和控制器功能 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <!-- 作用: 与授权服务器相同，提供Web层支持 -->
    </dependency>

    <!-- Thymeleaf模板引擎: 渲染客户端页面 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
        <!-- 作用:
             1. 渲染首页(home.html)和用户信息页面(user.html)
             2. 显示OAuth2登录入口和用户数据
        -->
    </dependency>

    <!-- WebFlux: 响应式HTTP客户端 -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-webflux</artifactId>
        <!-- 作用:
             1. 提供WebClient，用于发送HTTP请求
             2. 调用授权服务器的/oauth/token端点（令牌交换）
             3. 调用授权服务器的/oauth/userinfo端点（获取用户信息）
             4. 支持同步阻塞调用(.block())，简化代码逻辑
        -->
    </dependency>
</dependencies>
```

**为什么使用WebFlux而不是RestTemplate?**
- WebClient是Spring推荐的现代HTTP客户端
- 支持响应式编程，但也可以同步使用(.block())
- 更好的错误处理和配置选项

### 2.2 配置文件 (application.properties)

**配置说明**: 客户端需要配置OAuth2相关的端点URL和客户端凭证

```properties
# 服务器配置
server.port=8081
spring.application.name=oauth2-client

# OAuth2 核心配置参数详解
oauth2.client.id=client123
# 作用: 客户端标识符，必须与授权服务器中注册的client_id一致
# 安全性: 公开参数，用于标识客户端身份

oauth2.client.secret=secret456
# 作用: 客户端密钥，用于在令牌交换时验证客户端身份
# 安全性: 机密参数，只能在后端使用，不能暴露给前端

oauth2.authorization.uri=http://localhost:8080/oauth/authorize
# 作用: 授权端点URL，用户将被重定向到此URL进行登录和授权
# 对应: OAuth2协议的Authorization Endpoint

oauth2.token.uri=http://localhost:8080/oauth/token
# 作用: 令牌端点URL，客户端用授权码换取访问令牌的API地址
# 对应: OAuth2协议的Token Endpoint

oauth2.userinfo.uri=http://localhost:8080/oauth/userinfo
# 作用: 用户信息端点URL，使用访问令牌获取用户基本信息
# 对应: OpenID Connect的UserInfo Endpoint

oauth2.redirect.uri=http://localhost:8081/callback
# 作用: 重定向URI，授权服务器完成授权后将用户重定向回此地址
# 安全性: 必须与授权服务器注册的redirect_uri完全一致
```

### 2.3 OAuth2ClientController
```java
@Controller
public class OAuth2ClientController {

    @Value("${oauth2.client.id}")
    private String clientId;

    @Value("${oauth2.authorization.uri}")
    private String authorizationUri;

    @Value("${oauth2.redirect.uri}")
    private String redirectUri;

    @Autowired
    private OAuth2Service oauth2Service;

    // 首页
    @GetMapping("/")
    public String home() {
        return "home";
    }

    // 1. 发起OAuth2授权请求
    @GetMapping("/login")
    public String login(HttpSession session) {
        // 生成state防止CSRF攻击
        String state = UUID.randomUUID().toString();
        session.setAttribute("oauth2_state", state);

        // 构建授权URL
        String authUrl = authorizationUri +
            "?client_id=" + clientId +
            "&redirect_uri=" + redirectUri +
            "&response_type=code" +
            "&state=" + state;

        return "redirect:" + authUrl;
    }

    // 2. 处理授权回调
    @GetMapping("/callback")
    public String callback(@RequestParam String code,
                         @RequestParam String state,
                         HttpSession session,
                         Model model) {

        // 验证state
        String sessionState = (String) session.getAttribute("oauth2_state");
        if (!state.equals(sessionState)) {
            model.addAttribute("error", "状态验证失败");
            return "error";
        }

        try {
            // 用授权码换取访问令牌
            String accessToken = oauth2Service.getAccessToken(code);
            session.setAttribute("access_token", accessToken);

            // 获取用户信息
            Map<String, Object> userInfo = oauth2Service.getUserInfo(accessToken);
            session.setAttribute("user_info", userInfo);

            return "redirect:/user";
        } catch (Exception e) {
            model.addAttribute("error", "获取令牌失败: " + e.getMessage());
            return "error";
        }
    }

    // 3. 显示用户信息
    @GetMapping("/user")
    public String user(HttpSession session, Model model) {
        Map<String, Object> userInfo = (Map<String, Object>) session.getAttribute("user_info");
        if (userInfo == null) {
            return "redirect:/";
        }

        model.addAttribute("userInfo", userInfo);
        return "user";
    }
}
```

### 2.4 OAuth2Service
```java
@Service
public class OAuth2Service {

    @Value("${oauth2.client.id}")
    private String clientId;

    @Value("${oauth2.client.secret}")
    private String clientSecret;

    @Value("${oauth2.token.uri}")
    private String tokenUri;

    @Value("${oauth2.userinfo.uri}")
    private String userInfoUri;

    private final WebClient webClient = WebClient.create();

    public String getAccessToken(String code) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);

        Map response = webClient.post()
            .uri(tokenUri)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .bodyValue(params)
            .retrieve()
            .bodyToMono(Map.class)
            .block();

        if (response.containsKey("error")) {
            throw new RuntimeException("获取访问令牌失败: " + response.get("error"));
        }

        return (String) response.get("access_token");
    }

    public Map<String, Object> getUserInfo(String accessToken) {
        return webClient.get()
            .uri(userInfoUri)
            .header("Authorization", "Bearer " + accessToken)
            .retrieve()
            .bodyToMono(Map.class)
            .block();
    }
}
```

### 2.5 页面模板

**home.html**
```html
<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 客户端</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>OAuth2 客户端演示</h1>
    <p><a href="/login">点击这里使用OAuth2登录</a></p>
</body>
</html>
```

**user.html**
```html
<!DOCTYPE html>
<html>
<head>
    <title>用户信息</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>用户信息</h1>
    <p>用户名: <span th:text="${userInfo.username}"></span></p>
    <p>显示名: <span th:text="${userInfo.name}"></span></p>
    <p>用户ID: <span th:text="${userInfo.sub}"></span></p>
    <p><a href="/">返回首页</a></p>
</body>
</html>
```

## 3. 运行步骤

1. **启动授权服务器**
   ```bash
   cd oauth2-server
   mvn spring-boot:run
   ```

2. **启动客户端**
   ```bash
   cd oauth2-client
   mvn spring-boot:run
   ```

3. **测试流程**
   - 访问 http://localhost:8081
   - 点击"点击这里使用OAuth2登录"
   - 跳转到授权服务器 http://localhost:8080
   - 输入用户名：admin，密码：123456
   - 点击"登录并授权"
   - 自动跳转回客户端显示用户信息

## 4. OAuth2关键参数详解

### 4.1 授权请求参数
```
GET /oauth/authorize?
    client_id=client123              # 客户端标识
    &redirect_uri=http://...callback # 重定向URI
    &response_type=code              # 响应类型(授权码模式固定为code)
    &state=xyz123                    # 状态值(防CSRF攻击)
    &scope=read,write               # 权限范围(可选)
```

**参数说明**:
- `client_id`: 客户端在授权服务器注册时获得的唯一标识
- `redirect_uri`: 授权完成后重定向的回调地址，必须预先注册
- `response_type`: 固定值"code"，表示使用授权码模式
- `state`: 客户端生成的随机值，用于防止CSRF攻击
- `scope`: 请求的权限范围，如"read"、"write"等

### 4.2 令牌交换参数
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code        # 授权类型
&code=abcdef123456                  # 授权码
&client_id=client123                # 客户端ID
&client_secret=secret456            # 客户端密钥
&redirect_uri=http://...callback    # 重定向URI(验证用)
```

**参数说明**:
- `grant_type`: 固定值"authorization_code"，表示授权码换令牌
- `code`: 从授权服务器获得的授权码，短期有效且只能使用一次
- `client_id` + `client_secret`: 客户端凭证，验证客户端身份
- `redirect_uri`: 必须与授权请求中的redirect_uri一致

### 4.3 访问令牌使用
```
GET /oauth/userinfo
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**参数说明**:
- `Authorization`: HTTP头，格式为"Bearer {access_token}"
- `Bearer`: 令牌类型，表示承载者令牌
- `access_token`: 访问令牌，用于访问受保护资源

## 5. 安全机制说明

### 5.1 为什么使用授权码而不是直接返回令牌?
1. **前端安全**: 授权码通过URL参数传递，即使被截获也无法直接使用
2. **后端验证**: 令牌交换在后端进行，需要客户端密钥，增加安全层级
3. **短期有效**: 授权码通常10分钟内过期，降低被滥用风险

### 5.2 state参数的CSRF防护机制
1. **生成**: 客户端生成随机state值，存储在session中
2. **传递**: state随授权请求发送给授权服务器
3. **回传**: 授权服务器原样返回state值
4. **验证**: 客户端验证返回的state与session中的是否一致

### 5.3 令牌的安全特性
1. **有限生命周期**: access_token通常1-2小时过期
2. **权限范围**: 可以限制令牌的访问权限(scope)
3. **撤销机制**: 授权服务器可以随时撤销令牌

## 6. OAuth2核心流程总结

这个原生实现清晰展示了OAuth2的核心步骤：

1. **授权请求**: 客户端构建授权URL，包含client_id、redirect_uri、state等参数
2. **用户授权**: 用户在授权服务器登录并确认授权
3. **授权码返回**: 授权服务器生成授权码，重定向回客户端
4. **令牌交换**: 客户端用授权码+客户端凭证换取访问令牌
5. **资源访问**: 客户端使用访问令牌访问受保护的资源

**学习价值**: 通过这个手工实现，你可以清楚地看到每一步的具体逻辑和数据流转，为后续学习Spring Security OAuth2打下坚实基础！