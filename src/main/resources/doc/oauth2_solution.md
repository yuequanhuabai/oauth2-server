# OAuth2 授权码模式解决方案

## 概述

这是一个精简的OAuth2授权码流程实现方案，包含一个授权服务器和一个客户端应用。基于你提供的时序图，实现完整的第三方授权登录功能。

## 架构图

```
用户浏览器 ←→ 客户端应用(端口8081) ←→ 授权服务器(端口8080)
```

## 技术栈选择

### 方案一：Node.js版本（轻量级）
- **后端**: Node.js + Express
- **模板引擎**: EJS (用于登录/授权页面)
- **存储**: 内存存储(简化版，生产环境建议使用数据库)
- **加密**: crypto模块

### 方案二：Java Spring Boot版本（企业级）
- **后端**: Java 17 + Spring Boot 3.x
- **Web**: Spring Web MVC
- **模板引擎**: Thymeleaf
- **存储**: Spring Data JPA + H2数据库
- **安全**: Spring Security + JWT

---

# 方案一：Node.js版本实现

## 授权服务器实现

### 1. 项目结构

```
oauth2-server/
├── package.json
├── server.js
├── views/
│   ├── login.ejs
│   └── authorize.ejs
└── public/
    └── style.css
```

### 2. package.json

```json
{
  "name": "oauth2-server",
  "version": "1.0.0",
  "main": "server.js",
  "dependencies": {
    "express": "^4.18.2",
    "ejs": "^3.1.9",
    "body-parser": "^1.20.2",
    "express-session": "^1.17.3"
  },
  "scripts": {
    "start": "node server.js"
  }
}
```

### 3. server.js

```javascript
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const session = require('express-session');

const app = express();
const PORT = 3000;

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(session({
  secret: 'oauth2-server-secret',
  resave: false,
  saveUninitialized: false
}));

// 内存存储
const users = {
  'admin': 'password123',
  'user1': 'mypassword'
};

const clients = {
  'client123': {
    secret: 'secret456',
    redirectUris: ['http://localhost:3001/callback']
  }
};

const authCodes = new Map(); // 存储授权码
const accessTokens = new Map(); // 存储访问令牌

// 生成随机字符串
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// 1. 授权端点 - GET /authorize
app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, state, scope } = req.query;

  // 验证必需参数
  if (!client_id || !redirect_uri || response_type !== 'code') {
    return res.status(400).json({ error: 'invalid_request' });
  }

  // 验证客户端
  const client = clients[client_id];
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_client' });
  }

  // 如果用户未登录，重定向到登录页面
  if (!req.session.userId) {
    req.session.authRequest = { client_id, redirect_uri, state, scope };
    return res.redirect('/login');
  }

  // 显示授权页面
  res.render('authorize', {
    client_id,
    redirect_uri,
    state,
    scope: scope || 'profile',
    user: req.session.userId
  });
});

// 2. 登录页面 - GET /login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// 3. 处理登录 - POST /login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (users[username] && users[username] === password) {
    req.session.userId = username;

    // 如果有待处理的授权请求，重定向回授权页面
    if (req.session.authRequest) {
      const { client_id, redirect_uri, state, scope } = req.session.authRequest;
      delete req.session.authRequest;
      return res.redirect(`/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&state=${state}&scope=${scope || ''}`);
    }

    res.json({ success: true, message: '登录成功' });
  } else {
    res.render('login', { error: '用户名或密码错误' });
  }
});

// 4. 处理授权 - POST /authorize
app.post('/authorize', (req, res) => {
  const { client_id, redirect_uri, state, action } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  if (action === 'deny') {
    return res.redirect(`${redirect_uri}?error=access_denied&state=${state}`);
  }

  // 生成授权码
  const code = generateRandomString(16);
  authCodes.set(code, {
    client_id,
    redirect_uri,
    userId: req.session.userId,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10分钟过期
  });

  // 重定向回客户端
  res.redirect(`${redirect_uri}?code=${code}&state=${state}`);
});

// 5. 令牌端点 - POST /token
app.post('/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

  // 验证请求
  if (grant_type !== 'authorization_code' || !code || !client_id || !client_secret) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  // 验证客户端
  const client = clients[client_id];
  if (!client || client.secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  // 验证授权码
  const authCodeData = authCodes.get(code);
  if (!authCodeData || authCodeData.expiresAt < Date.now()) {
    authCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (authCodeData.client_id !== client_id || authCodeData.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  // 删除已使用的授权码
  authCodes.delete(code);

  // 生成访问令牌
  const access_token = generateRandomString(32);
  accessTokens.set(access_token, {
    userId: authCodeData.userId,
    client_id,
    expiresAt: Date.now() + 3600 * 1000 // 1小时过期
  });

  res.json({
    access_token,
    token_type: 'Bearer',
    expires_in: 3600
  });
});

// 6. 用户信息端点 - GET /userinfo
app.get('/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const token = authHeader.substring(7);
  const tokenData = accessTokens.get(token);

  if (!tokenData || tokenData.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return res.status(401).json({ error: 'invalid_token' });
  }

  // 返回用户信息
  res.json({
    sub: tokenData.userId,
    name: tokenData.userId,
    email: `${tokenData.userId}@example.com`,
    profile: `https://example.com/users/${tokenData.userId}`
  });
});

// 7. 登出端点
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`OAuth2 授权服务器运行在 http://localhost:${PORT}`);
});
```

### 4. views/login.ejs

```html
<!DOCTYPE html>
<html>
<head>
    <title>用户登录</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <h2>用户登录</h2>
        <% if (error) { %>
            <div class="error"><%= error %></div>
        <% } %>
        <form method="POST" action="/login">
            <div class="form-group">
                <label>用户名:</label>
                <input type="text" name="username" required>
                <small>测试账号: admin 或 user1</small>
            </div>
            <div class="form-group">
                <label>密码:</label>
                <input type="password" name="password" required>
                <small>admin密码: password123, user1密码: mypassword</small>
            </div>
            <button type="submit">登录</button>
        </form>
    </div>
</body>
</html>
```

### 5. views/authorize.ejs

```html
<!DOCTYPE html>
<html>
<head>
    <title>授权确认</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <h2>授权确认</h2>
        <p>用户 <strong><%= user %></strong>，应用 <strong><%= client_id %></strong> 请求访问您的以下信息：</p>
        <ul>
            <li>基本用户信息 (姓名、邮箱)</li>
            <li>用户资料 (<%= scope %>)</li>
        </ul>
        <form method="POST" action="/authorize">
            <input type="hidden" name="client_id" value="<%= client_id %>">
            <input type="hidden" name="redirect_uri" value="<%= redirect_uri %>">
            <input type="hidden" name="state" value="<%= state %>">
            <div class="button-group">
                <button type="submit" name="action" value="allow" class="allow">同意授权</button>
                <button type="submit" name="action" value="deny" class="deny">拒绝</button>
            </div>
        </form>
    </div>
</body>
</html>
```

### 6. public/style.css

```css
body {
    font-family: Arial, sans-serif;
    background-color: #f5f5f5;
    margin: 0;
    padding: 20px;
}

.container {
    max-width: 400px;
    margin: 50px auto;
    background: white;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

h2 {
    text-align: center;
    color: #333;
    margin-bottom: 30px;
}

.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    margin-bottom: 5px;
    color: #555;
}

input[type="text"], input[type="password"] {
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 4px;
    box-sizing: border-box;
}

small {
    color: #888;
    font-size: 12px;
}

button {
    width: 100%;
    padding: 12px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 16px;
}

button[type="submit"] {
    background-color: #007bff;
    color: white;
}

.button-group {
    display: flex;
    gap: 10px;
}

.button-group button {
    width: 50%;
}

.allow {
    background-color: #28a745;
    color: white;
}

.deny {
    background-color: #dc3545;
    color: white;
}

.error {
    background-color: #f8d7da;
    color: #721c24;
    padding: 10px;
    border-radius: 4px;
    margin-bottom: 20px;
}

ul {
    margin: 20px 0;
    padding-left: 20px;
}

li {
    margin-bottom: 5px;
}
```

---

## 客户端应用实现

### 1. 项目结构

```
oauth2-client/
├── package.json
├── client.js
├── views/
│   ├── index.ejs
│   └── profile.ejs
└── public/
    └── style.css
```

### 2. package.json

```json
{
  "name": "oauth2-client",
  "version": "1.0.0",
  "main": "client.js",
  "dependencies": {
    "express": "^4.18.2",
    "ejs": "^3.1.9",
    "axios": "^1.4.0",
    "express-session": "^1.17.3"
  },
  "scripts": {
    "start": "node client.js"
  }
}
```

### 3. client.js

```javascript
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const session = require('express-session');

const app = express();
const PORT = 3001;

// OAuth2配置
const OAUTH_CONFIG = {
  authServer: 'http://localhost:3000',
  clientId: 'client123',
  clientSecret: 'secret456',
  redirectUri: 'http://localhost:3001/callback',
  scope: 'profile'
};

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(session({
  secret: 'oauth2-client-secret',
  resave: false,
  saveUninitialized: false
}));

// 生成state参数
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

// 1. 首页
app.get('/', (req, res) => {
  res.render('index', {
    user: req.session.user || null,
    loginUrl: '/login'
  });
});

// 2. 发起OAuth2登录
app.get('/login', (req, res) => {
  const state = generateState();
  req.session.oauthState = state;

  const authUrl = new URL('/authorize', OAUTH_CONFIG.authServer);
  authUrl.searchParams.set('client_id', OAUTH_CONFIG.clientId);
  authUrl.searchParams.set('redirect_uri', OAUTH_CONFIG.redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', OAUTH_CONFIG.scope);
  authUrl.searchParams.set('state', state);

  console.log('重定向到授权服务器:', authUrl.toString());
  res.redirect(authUrl.toString());
});

// 3. OAuth2回调处理
app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  console.log('收到回调:', { code, state, error });

  // 检查错误
  if (error) {
    return res.render('index', {
      user: null,
      error: `授权失败: ${error}`,
      loginUrl: '/login'
    });
  }

  // 验证state参数
  if (!state || state !== req.session.oauthState) {
    return res.render('index', {
      user: null,
      error: 'State参数验证失败，可能存在CSRF攻击',
      loginUrl: '/login'
    });
  }

  delete req.session.oauthState;

  try {
    // 用授权码换取访问令牌
    console.log('交换访问令牌...');
    const tokenResponse = await axios.post(`${OAUTH_CONFIG.authServer}/token`, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: OAUTH_CONFIG.redirectUri,
      client_id: OAUTH_CONFIG.clientId,
      client_secret: OAUTH_CONFIG.clientSecret
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const { access_token } = tokenResponse.data;
    console.log('获取到访问令牌');

    // 使用访问令牌获取用户信息
    console.log('获取用户信息...');
    const userResponse = await axios.get(`${OAUTH_CONFIG.authServer}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });

    // 保存用户信息到会话
    req.session.user = userResponse.data;
    req.session.accessToken = access_token;

    console.log('登录成功，用户信息:', userResponse.data);
    res.redirect('/profile');

  } catch (error) {
    console.error('OAuth2流程错误:', error.response?.data || error.message);
    res.render('index', {
      user: null,
      error: `登录失败: ${error.response?.data?.error || error.message}`,
      loginUrl: '/login'
    });
  }
});

// 4. 用户资料页面
app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }

  res.render('profile', {
    user: req.session.user
  });
});

// 5. 登出
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 6. API示例 - 使用访问令牌调用受保护的API
app.get('/api/userinfo', async (req, res) => {
  if (!req.session.accessToken) {
    return res.status(401).json({ error: '需要登录' });
  }

  try {
    const response = await axios.get(`${OAUTH_CONFIG.authServer}/userinfo`, {
      headers: {
        'Authorization': `Bearer ${req.session.accessToken}`
      }
    });

    res.json(response.data);
  } catch (error) {
    res.status(401).json({ error: '访问令牌无效' });
  }
});

app.listen(PORT, () => {
  console.log(`OAuth2 客户端应用运行在 http://localhost:${PORT}`);
  console.log('请在浏览器中访问 http://localhost:3001 开始测试');
});
```

### 4. views/index.ejs

```html
<!DOCTYPE html>
<html>
<head>
    <title>OAuth2 客户端应用</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <h1>OAuth2 演示应用</h1>

        <% if (typeof error !== 'undefined' && error) { %>
            <div class="error"><%= error %></div>
        <% } %>

        <% if (user) { %>
            <div class="user-info">
                <h3>欢迎回来，<%= user.name %>!</h3>
                <p>您已通过OAuth2成功登录</p>
                <div class="button-group">
                    <a href="/profile" class="button">查看个人资料</a>
                    <a href="/logout" class="button secondary">登出</a>
                </div>
            </div>
        <% } else { %>
            <div class="login-section">
                <h3>请登录</h3>
                <p>点击下面的按钮使用OAuth2授权服务器登录</p>
                <a href="<%= loginUrl %>" class="button primary">使用OAuth2登录</a>
            </div>
        <% } %>

        <div class="info-section">
            <h4>OAuth2流程说明</h4>
            <ol>
                <li>点击"使用OAuth2登录"按钮</li>
                <li>跳转到授权服务器进行身份验证</li>
                <li>授权后返回到本应用</li>
                <li>应用获取访问令牌并获取用户信息</li>
                <li>完成登录流程</li>
            </ol>
        </div>
    </div>
</body>
</html>
```

### 5. views/profile.ejs

```html
<!DOCTYPE html>
<html>
<head>
    <title>用户资料 - OAuth2 客户端</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div class="container">
        <h1>用户资料</h1>

        <div class="profile-info">
            <h3>基本信息</h3>
            <table>
                <tr>
                    <td><strong>用户ID:</strong></td>
                    <td><%= user.sub %></td>
                </tr>
                <tr>
                    <td><strong>姓名:</strong></td>
                    <td><%= user.name %></td>
                </tr>
                <tr>
                    <td><strong>邮箱:</strong></td>
                    <td><%= user.email %></td>
                </tr>
                <tr>
                    <td><strong>资料链接:</strong></td>
                    <td><a href="<%= user.profile %>" target="_blank"><%= user.profile %></a></td>
                </tr>
            </table>
        </div>

        <div class="api-test">
            <h3>API测试</h3>
            <button onclick="testAPI()" class="button">测试API调用</button>
            <div id="api-result"></div>
        </div>

        <div class="button-group">
            <a href="/" class="button">返回首页</a>
            <a href="/logout" class="button secondary">登出</a>
        </div>
    </div>

    <script>
        async function testAPI() {
            try {
                const response = await fetch('/api/userinfo');
                const data = await response.json();
                document.getElementById('api-result').innerHTML =
                    '<h4>API响应:</h4><pre>' + JSON.stringify(data, null, 2) + '</pre>';
            } catch (error) {
                document.getElementById('api-result').innerHTML =
                    '<div class="error">API调用失败: ' + error.message + '</div>';
            }
        }
    </script>
</body>
</html>
```

### 6. public/style.css (客户端)

```css
body {
    font-family: Arial, sans-serif;
    background-color: #f8f9fa;
    margin: 0;
    padding: 20px;
    line-height: 1.6;
}

.container {
    max-width: 800px;
    margin: 0 auto;
    background: white;
    padding: 30px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

h1 {
    color: #333;
    text-align: center;
    margin-bottom: 30px;
}

h3, h4 {
    color: #555;
}

.error {
    background-color: #f8d7da;
    color: #721c24;
    padding: 15px;
    border-radius: 4px;
    margin-bottom: 20px;
    border: 1px solid #f5c6cb;
}

.user-info, .login-section, .info-section, .profile-info, .api-test {
    margin-bottom: 30px;
    padding: 20px;
    border: 1px solid #e9ecef;
    border-radius: 4px;
}

.button {
    display: inline-block;
    padding: 12px 24px;
    text-decoration: none;
    border-radius: 4px;
    font-size: 16px;
    text-align: center;
    cursor: pointer;
    border: none;
    margin-right: 10px;
    margin-bottom: 10px;
}

.button.primary {
    background-color: #007bff;
    color: white;
}

.button.secondary {
    background-color: #6c757d;
    color: white;
}

.button:hover {
    opacity: 0.8;
}

.button-group {
    margin-top: 20px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}

table td {
    padding: 10px;
    border-bottom: 1px solid #e9ecef;
}

table td:first-child {
    width: 150px;
}

ol {
    padding-left: 20px;
}

li {
    margin-bottom: 8px;
}

pre {
    background-color: #f8f9fa;
    padding: 15px;
    border-radius: 4px;
    overflow-x: auto;
    border: 1px solid #e9ecef;
}

#api-result {
    margin-top: 15px;
}
```

---

## 部署和运行

### 1. 环境准备

确保你的系统已安装 Node.js (版本 14 或更高)。

### 2. 启动授权服务器

```bash
# 创建授权服务器目录
mkdir oauth2-server
cd oauth2-server

# 创建上述文件结构和代码

# 安装依赖
npm install

# 启动服务器
npm start
```

授权服务器将在 `http://localhost:3000` 运行。

### 3. 启动客户端应用

```bash
# 在另一个终端窗口
# 创建客户端应用目录
mkdir oauth2-client
cd oauth2-client

# 创建上述文件结构和代码

# 安装依赖
npm install

# 启动应用
npm start
```

客户端应用将在 `http://localhost:3001` 运行。

---

## 测试流程

### 1. 完整流程测试

1. **访问客户端**: 打开浏览器访问 `http://localhost:3001`
2. **发起登录**: 点击"使用OAuth2登录"按钮
3. **跳转授权服务器**: 自动跳转到 `http://localhost:3000/authorize`
4. **用户登录**: 使用测试账号登录
   - 用户名: `admin` 密码: `password123`
   - 或 用户名: `user1` 密码: `mypassword`
5. **授权确认**: 在授权页面点击"同意授权"
6. **返回客户端**: 自动跳转回客户端应用并完成登录
7. **查看用户信息**: 点击"查看个人资料"查看获取的用户信息
8. **API测试**: 在资料页面点击"测试API调用"

### 2. 安全性验证

1. **State参数验证**: 尝试手动修改回调URL中的state参数，应该被拒绝
2. **授权码重放**: 尝试重复使用已使用的授权码，应该失败
3. **令牌过期**: 等待令牌过期后尝试访问API，应该返回401错误

### 3. 错误处理测试

1. **拒绝授权**: 在授权页面点击"拒绝"，应该正确处理错误
2. **无效客户端**: 修改client_id测试无效客户端处理
3. **错误的重定向URI**: 测试重定向URI验证

---

## 安全注意事项

### 1. 生产环境改进

1. **数据库存储**: 使用真实数据库替代内存存储
2. **HTTPS**: 所有通信必须使用HTTPS
3. **密码加密**: 用户密码应该进行哈希存储
4. **令牌加密**: 考虑使用JWT令牌
5. **速率限制**: 添加API速率限制
6. **日志记录**: 添加详细的安全日志

### 2. 当前实现的安全特性

1. **State参数**: 防止CSRF攻击
2. **授权码一次性使用**: 防止重放攻击
3. **令牌过期机制**: 限制令牌有效期
4. **客户端验证**: 验证客户端身份和重定向URI
5. **作用域控制**: 限制访问权限范围

---

## 扩展功能

### 1. 可添加的功能

1. **刷新令牌**: 实现令牌刷新机制
2. **多种授权类型**: 支持客户端凭证、密码等授权类型
3. **用户管理**: 添加用户注册、密码重置等功能
4. **客户端管理**: 添加客户端注册、管理界面
5. **作用域管理**: 更细粒度的权限控制

### 2. 集成建议

1. **与现有系统集成**: 可以将此方案集成到现有的用户系统中
2. **第三方登录**: 可以作为统一的身份提供者
3. **微服务架构**: 可以作为认证中心在微服务架构中使用

---

## 学习要点

通过这个实现，你将理解：

1. **OAuth2授权码流程**: 完整的授权码模式实现
2. **安全考虑**: State参数、授权码管理、令牌过期等
3. **前后端交互**: 浏览器重定向、API调用等
4. **会话管理**: 用户会话和OAuth2状态管理
5. **错误处理**: 各种异常情况的处理

这个解决方案提供了OAuth2的核心功能，可以作为学习和理解OAuth2的良好起点。在生产环境中使用时，请务必加强安全性和错误处理。

---

# 方案二：Java Spring Boot版本实现

## 技术优势

相比Node.js版本，Java Spring Boot版本具有以下优势：

1. **企业级成熟度**: Spring Security提供完整的OAuth2支持
2. **类型安全**: Java静态类型检查，减少运行时错误
3. **生态系统**: 丰富的企业级组件和中间件支持
4. **性能**: JVM优化，更好的多线程支持
5. **标准化**: 基于Java EE标准，代码规范性更强

## Java版授权服务器实现

### 1. 项目结构

```
oauth2-auth-server/
├── pom.xml
├── src/main/java/com/example/oauth2/
│   ├── OAuth2AuthServerApplication.java
│   ├── config/
│   │   ├── AuthorizationServerConfig.java
│   │   ├── SecurityConfig.java
│   │   └── WebConfig.java
│   ├── controller/
│   │   ├── AuthController.java
│   │   ├── UserController.java
│   │   └── TokenController.java
│   ├── entity/
│   │   ├── User.java
│   │   ├── Client.java
│   │   ├── AuthCode.java
│   │   └── AccessToken.java
│   ├── repository/
│   │   ├── UserRepository.java
│   │   ├── ClientRepository.java
│   │   ├── AuthCodeRepository.java
│   │   └── AccessTokenRepository.java
│   ├── service/
│   │   ├── UserService.java
│   │   ├── ClientService.java
│   │   ├── AuthCodeService.java
│   │   └── TokenService.java
│   └── dto/
│       ├── LoginRequest.java
│       ├── AuthorizeRequest.java
│       └── TokenRequest.java
└── src/main/resources/
    ├── application.yml
    ├── data.sql
    └── templates/
        ├── login.html
        └── authorize.html
```

### 2. pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>oauth2-auth-server</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/>
    </parent>

    <properties>
        <java.version>17</java.version>
    </properties>

    <dependencies>
        <!-- Spring Boot Web -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <!-- Spring Boot Security -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <!-- Spring Data JPA -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>

        <!-- H2 Database -->
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>

        <!-- Thymeleaf -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <!-- JWT -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.12.3</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.12.3</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.12.3</version>
            <scope>runtime</scope>
        </dependency>

        <!-- Validation -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        <!-- Test -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

### 3. application.yml

```yaml
server:
  port: 8080
  servlet:
    context-path: /

spring:
  application:
    name: oauth2-auth-server

  datasource:
    url: jdbc:h2:mem:oauth2db
    driver-class-name: org.h2.Driver
    username: sa
    password:

  h2:
    console:
      enabled: true
      path: /h2-console

  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: true
    database-platform: org.hibernate.dialect.H2Dialect

  thymeleaf:
    prefix: classpath:/templates/
    suffix: .html
    mode: HTML
    encoding: UTF-8
    cache: false

oauth2:
  jwt:
    secret: mySecretKey123456789012345678901234567890
    expiration: 3600000  # 1 hour in milliseconds
  auth-code:
    expiration: 600000   # 10 minutes in milliseconds

logging:
  level:
    com.example.oauth2: DEBUG
    org.springframework.security: DEBUG
```

### 4. 主启动类

```java
package com.example.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class OAuth2AuthServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(OAuth2AuthServerApplication.class, args);
    }
}
```

### 5. 实体类

#### User.java

```java
package com.example.oauth2.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String email;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
```

#### Client.java

```java
package com.example.oauth2.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.Set;

@Entity
@Table(name = "oauth_clients")
public class Client {
    @Id
    private String clientId;

    @Column(nullable = false)
    private String clientSecret;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_redirect_uris")
    private Set<String> redirectUris;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_scopes")
    private Set<String> scopes;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public Set<String> getRedirectUris() { return redirectUris; }
    public void setRedirectUris(Set<String> redirectUris) { this.redirectUris = redirectUris; }

    public Set<String> getScopes() { return scopes; }
    public void setScopes(Set<String> scopes) { this.scopes = scopes; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
```

#### AuthCode.java

```java
package com.example.oauth2.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "auth_codes")
public class AuthCode {
    @Id
    private String code;

    @Column(nullable = false)
    private String clientId;

    @Column(nullable = false)
    private String redirectUri;

    @Column(nullable = false)
    private String userId;

    private String scope;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getRedirectUri() { return redirectUri; }
    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }

    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
```

#### AccessToken.java

```java
package com.example.oauth2.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "access_tokens")
public class AccessToken {
    @Id
    private String token;

    @Column(nullable = false)
    private String clientId;

    @Column(nullable = false)
    private String userId;

    private String scope;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }

    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
```

### 6. Repository接口

#### UserRepository.java

```java
package com.example.oauth2.repository;

import com.example.oauth2.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
}
```

#### ClientRepository.java

```java
package com.example.oauth2.repository;

import com.example.oauth2.entity.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {
}
```

#### AuthCodeRepository.java

```java
package com.example.oauth2.repository;

import com.example.oauth2.entity.AuthCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;

@Repository
public interface AuthCodeRepository extends JpaRepository<AuthCode, String> {
    void deleteByExpiresAtBefore(LocalDateTime dateTime);
}
```

#### AccessTokenRepository.java

```java
package com.example.oauth2.repository;

import com.example.oauth2.entity.AccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;

@Repository
public interface AccessTokenRepository extends JpaRepository<AccessToken, String> {
    void deleteByExpiresAtBefore(LocalDateTime dateTime);
}
```

### 7. 服务层

#### TokenService.java

```java
package com.example.oauth2.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Service
public class TokenService {

    @Value("${oauth2.jwt.secret}")
    private String jwtSecret;

    @Value("${oauth2.jwt.expiration}")
    private long jwtExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateAccessToken(String userId, String clientId, String scope) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .subject(userId)
                .claim("client_id", clientId)
                .claim("scope", scope)
                .issuedAt(now)
                .expiration(expiry)
                .id(UUID.randomUUID().toString())
                .signWith(getSigningKey())
                .compact();
    }

    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = parseToken(token);
            return claims.getExpiration().after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String generateAuthCode() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
```

#### AuthCodeService.java

```java
package com.example.oauth2.service;

import com.example.oauth2.entity.AuthCode;
import com.example.oauth2.repository.AuthCodeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class AuthCodeService {

    @Autowired
    private AuthCodeRepository authCodeRepository;

    @Autowired
    private TokenService tokenService;

    @Value("${oauth2.auth-code.expiration}")
    private long authCodeExpiration;

    public AuthCode createAuthCode(String clientId, String redirectUri, String userId, String scope) {
        AuthCode authCode = new AuthCode();
        authCode.setCode(tokenService.generateAuthCode());
        authCode.setClientId(clientId);
        authCode.setRedirectUri(redirectUri);
        authCode.setUserId(userId);
        authCode.setScope(scope);
        authCode.setExpiresAt(LocalDateTime.now().plusSeconds(authCodeExpiration / 1000));

        return authCodeRepository.save(authCode);
    }

    public Optional<AuthCode> validateAndConsumeAuthCode(String code, String clientId, String redirectUri) {
        Optional<AuthCode> authCodeOpt = authCodeRepository.findById(code);

        if (authCodeOpt.isPresent()) {
            AuthCode authCode = authCodeOpt.get();

            // Check expiration
            if (authCode.getExpiresAt().isBefore(LocalDateTime.now())) {
                authCodeRepository.delete(authCode);
                return Optional.empty();
            }

            // Check client_id and redirect_uri
            if (!authCode.getClientId().equals(clientId) ||
                !authCode.getRedirectUri().equals(redirectUri)) {
                return Optional.empty();
            }

            // Delete the auth code (one-time use)
            authCodeRepository.delete(authCode);
            return Optional.of(authCode);
        }

        return Optional.empty();
    }

    public void cleanupExpiredAuthCodes() {
        authCodeRepository.deleteByExpiresAtBefore(LocalDateTime.now());
    }
}
```

### 8. 控制器

#### AuthController.java

```java
package com.example.oauth2.controller;

import com.example.oauth2.entity.Client;
import com.example.oauth2.entity.User;
import com.example.oauth2.entity.AuthCode;
import com.example.oauth2.repository.ClientRepository;
import com.example.oauth2.repository.UserRepository;
import com.example.oauth2.service.AuthCodeService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
public class AuthController {

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthCodeService authCodeService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/authorize")
    public String authorize(@RequestParam String client_id,
                           @RequestParam String redirect_uri,
                           @RequestParam String response_type,
                           @RequestParam(required = false) String state,
                           @RequestParam(defaultValue = "profile") String scope,
                           HttpSession session,
                           Model model) {

        // Validate request parameters
        if (!"code".equals(response_type)) {
            return "redirect:" + redirect_uri + "?error=unsupported_response_type" +
                   (state != null ? "&state=" + state : "");
        }

        // Validate client
        Optional<Client> clientOpt = clientRepository.findById(client_id);
        if (clientOpt.isEmpty() || !clientOpt.get().getRedirectUris().contains(redirect_uri)) {
            return "redirect:" + redirect_uri + "?error=invalid_client" +
                   (state != null ? "&state=" + state : "");
        }

        // Check if user is logged in
        String userId = (String) session.getAttribute("userId");
        if (userId == null) {
            // Store authorize request in session
            session.setAttribute("authRequest", new AuthRequest(client_id, redirect_uri, state, scope));
            return "redirect:/login";
        }

        // Show authorization page
        model.addAttribute("client_id", client_id);
        model.addAttribute("redirect_uri", redirect_uri);
        model.addAttribute("state", state);
        model.addAttribute("scope", scope);
        model.addAttribute("username", userId);

        return "authorize";
    }

    @PostMapping("/authorize")
    public String handleAuthorize(@RequestParam String client_id,
                                 @RequestParam String redirect_uri,
                                 @RequestParam(required = false) String state,
                                 @RequestParam(defaultValue = "profile") String scope,
                                 @RequestParam String action,
                                 HttpSession session) {

        String userId = (String) session.getAttribute("userId");
        if (userId == null) {
            return "redirect:/login";
        }

        if ("deny".equals(action)) {
            return "redirect:" + redirect_uri + "?error=access_denied" +
                   (state != null ? "&state=" + state : "");
        }

        // Generate authorization code
        AuthCode authCode = authCodeService.createAuthCode(client_id, redirect_uri, userId, scope);

        return "redirect:" + redirect_uri + "?code=" + authCode.getCode() +
               (state != null ? "&state=" + state : "");
    }

    @GetMapping("/login")
    public String login(Model model) {
        return "login";
    }

    @PostMapping("/login")
    public String handleLogin(@RequestParam String username,
                             @RequestParam String password,
                             HttpSession session,
                             Model model) {

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isPresent() && passwordEncoder.matches(password, userOpt.get().getPassword())) {
            session.setAttribute("userId", username);

            // Check if there's a pending auth request
            AuthRequest authRequest = (AuthRequest) session.getAttribute("authRequest");
            if (authRequest != null) {
                session.removeAttribute("authRequest");
                return "redirect:/authorize?client_id=" + authRequest.getClientId() +
                       "&redirect_uri=" + authRequest.getRedirectUri() +
                       "&response_type=code" +
                       (authRequest.getState() != null ? "&state=" + authRequest.getState() : "") +
                       "&scope=" + authRequest.getScope();
            }

            return "redirect:/";
        } else {
            model.addAttribute("error", "用户名或密码错误");
            return "login";
        }
    }

    @PostMapping("/logout")
    @ResponseBody
    public String logout(HttpSession session) {
        session.invalidate();
        return "{\"success\": true}";
    }

    // Helper class for storing auth request in session
    public static class AuthRequest {
        private String clientId;
        private String redirectUri;
        private String state;
        private String scope;

        public AuthRequest(String clientId, String redirectUri, String state, String scope) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.state = state;
            this.scope = scope;
        }

        // Getters
        public String getClientId() { return clientId; }
        public String getRedirectUri() { return redirectUri; }
        public String getState() { return state; }
        public String getScope() { return scope; }
    }
}
```

#### TokenController.java

```java
package com.example.oauth2.controller;

import com.example.oauth2.entity.AuthCode;
import com.example.oauth2.entity.Client;
import com.example.oauth2.entity.AccessToken;
import com.example.oauth2.repository.ClientRepository;
import com.example.oauth2.repository.AccessTokenRepository;
import com.example.oauth2.service.AuthCodeService;
import com.example.oauth2.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
public class TokenController {

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    @Autowired
    private AuthCodeService authCodeService;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> token(@RequestParam String grant_type,
                                                    @RequestParam String code,
                                                    @RequestParam String redirect_uri,
                                                    @RequestParam String client_id,
                                                    @RequestParam String client_secret) {

        Map<String, Object> response = new HashMap<>();

        // Validate grant type
        if (!"authorization_code".equals(grant_type)) {
            response.put("error", "unsupported_grant_type");
            return ResponseEntity.badRequest().body(response);
        }

        // Validate client
        Optional<Client> clientOpt = clientRepository.findById(client_id);
        if (clientOpt.isEmpty() || !passwordEncoder.matches(client_secret, clientOpt.get().getClientSecret())) {
            response.put("error", "invalid_client");
            return ResponseEntity.status(401).body(response);
        }

        // Validate and consume authorization code
        Optional<AuthCode> authCodeOpt = authCodeService.validateAndConsumeAuthCode(code, client_id, redirect_uri);
        if (authCodeOpt.isEmpty()) {
            response.put("error", "invalid_grant");
            return ResponseEntity.badRequest().body(response);
        }

        AuthCode authCode = authCodeOpt.get();

        // Generate access token
        String accessToken = tokenService.generateAccessToken(authCode.getUserId(), client_id, authCode.getScope());

        // Store access token in database
        AccessToken tokenEntity = new AccessToken();
        tokenEntity.setToken(accessToken);
        tokenEntity.setClientId(client_id);
        tokenEntity.setUserId(authCode.getUserId());
        tokenEntity.setScope(authCode.getScope());
        tokenEntity.setExpiresAt(LocalDateTime.now().plusSeconds(3600)); // 1 hour
        accessTokenRepository.save(tokenEntity);

        response.put("access_token", accessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);
        if (authCode.getScope() != null) {
            response.put("scope", authCode.getScope());
        }

        return ResponseEntity.ok(response);
    }
}
```

#### UserController.java

```java
package com.example.oauth2.controller;

import com.example.oauth2.entity.User;
import com.example.oauth2.repository.UserRepository;
import com.example.oauth2.service.TokenService;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo(@RequestHeader("Authorization") String authHeader) {

        Map<String, Object> response = new HashMap<>();

        // Validate Authorization header
        if (!authHeader.startsWith("Bearer ")) {
            response.put("error", "invalid_token");
            return ResponseEntity.status(401).body(response);
        }

        String token = authHeader.substring(7);

        // Validate token
        if (!tokenService.isTokenValid(token)) {
            response.put("error", "invalid_token");
            return ResponseEntity.status(401).body(response);
        }

        // Parse token
        Claims claims = tokenService.parseToken(token);
        String userId = claims.getSubject();

        // Get user info
        Optional<User> userOpt = userRepository.findByUsername(userId);
        if (userOpt.isEmpty()) {
            response.put("error", "invalid_token");
            return ResponseEntity.status(401).body(response);
        }

        User user = userOpt.get();
        response.put("sub", user.getUsername());
        response.put("name", user.getUsername());
        response.put("email", user.getEmail());
        response.put("profile", "https://example.com/users/" + user.getUsername());

        return ResponseEntity.ok(response);
    }
}
```

### 9. 配置类

#### SecurityConfig.java

```java
package com.example.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/login", "/token", "/userinfo", "/h2-console/**").permitAll()
                .anyRequest().permitAll()
            )
            .headers(headers -> headers.frameOptions().disable()); // For H2 console

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### 10. 模板文件

#### templates/login.html

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>用户登录</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; background-color: #007bff; color: white; }
        .error { background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
        small { color: #888; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>用户登录</h2>
        <div th:if="${error}" class="error" th:text="${error}"></div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label>用户名:</label>
                <input type="text" name="username" required>
                <small>测试账号: admin 或 user1</small>
            </div>
            <div class="form-group">
                <label>密码:</label>
                <input type="password" name="password" required>
                <small>admin密码: password123, user1密码: mypassword</small>
            </div>
            <button type="submit">登录</button>
        </form>
    </div>
</body>
</html>
```

#### templates/authorize.html

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>授权确认</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { text-align: center; color: #333; margin-bottom: 30px; }
        .button-group { display: flex; gap: 10px; }
        .button-group button { width: 50%; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .allow { background-color: #28a745; color: white; }
        .deny { background-color: #dc3545; color: white; }
        ul { margin: 20px 0; padding-left: 20px; }
        li { margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>授权确认</h2>
        <p>用户 <strong th:text="${username}"></strong>，应用 <strong th:text="${client_id}"></strong> 请求访问您的以下信息：</p>
        <ul>
            <li>基本用户信息 (姓名、邮箱)</li>
            <li>用户资料 (<span th:text="${scope}"></span>)</li>
        </ul>
        <form method="POST" action="/authorize">
            <input type="hidden" name="client_id" th:value="${client_id}">
            <input type="hidden" name="redirect_uri" th:value="${redirect_uri}">
            <input type="hidden" name="state" th:value="${state}">
            <input type="hidden" name="scope" th:value="${scope}">
            <div class="button-group">
                <button type="submit" name="action" value="allow" class="allow">同意授权</button>
                <button type="submit" name="action" value="deny" class="deny">拒绝</button>
            </div>
        </form>
    </div>
</body>
</html>
```

### 11. 数据初始化

#### src/main/resources/data.sql

```sql
-- 插入测试用户 (密码都是BCrypt加密后的)
-- admin/password123, user1/mypassword
INSERT INTO users (username, password, email, created_at) VALUES
('admin', '$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iYqiSfFvMbNQ2pJeG/GFoAaOJ4sO', 'admin@example.com', NOW()),
('user1', '$2a$10$n0z3DEqd9SINRUHcdJ2k.eAu4QZhwXdLN.ub3cG4mDfNlgJq4LMxG', 'user1@example.com', NOW());

-- 插入测试客户端 (client_secret也是BCrypt加密的)
-- client123/secret456
INSERT INTO oauth_clients (client_id, client_secret, created_at) VALUES
('client123', '$2a$10$8oyPWpYVvklU0lJd7x6KQOzm8fYEDjJ5P1w4OQiuV9bgZkG0rTXwu', NOW());

-- 插入客户端重定向URI
INSERT INTO client_redirect_uris (client_client_id, redirect_uris) VALUES
('client123', 'http://localhost:8081/callback');

-- 插入客户端作用域
INSERT INTO client_scopes (client_client_id, scopes) VALUES
('client123', 'profile'),
('client123', 'email');
```

---

## Java版客户端应用实现

### 1. 项目结构

```
oauth2-client/
├── pom.xml
├── src/main/java/com/example/client/
│   ├── OAuth2ClientApplication.java
│   ├── config/
│   │   └── WebConfig.java
│   ├── controller/
│   │   ├── HomeController.java
│   │   ├── AuthController.java
│   │   └── ApiController.java
│   ├── service/
│   │   └── OAuth2Service.java
│   └── dto/
│       ├── TokenResponse.java
│       └── UserInfo.java
└── src/main/resources/
    ├── application.yml
    └── templates/
        ├── index.html
        └── profile.html
```

### 2. 客户端pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>oauth2-client</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
        <relativePath/>
    </parent>

    <properties>
        <java.version>17</java.version>
    </properties>

    <dependencies>
        <!-- Spring Boot Web -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <!-- Thymeleaf -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <!-- WebClient for HTTP calls -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webflux</artifactId>
        </dependency>

        <!-- JSON processing -->
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
        </dependency>

        <!-- Test -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

### 3. 客户端application.yml

```yaml
server:
  port: 8081
  servlet:
    context-path: /

spring:
  application:
    name: oauth2-client

oauth2:
  auth-server: http://localhost:8080
  client-id: client123
  client-secret: secret456
  redirect-uri: http://localhost:8081/callback
  scope: profile

logging:
  level:
    com.example.client: DEBUG
```

### 4. 客户端主要类实现

#### OAuth2Service.java

```java
package com.example.client.service;

import com.example.client.dto.TokenResponse;
import com.example.client.dto.UserInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.SecureRandom;
import java.util.Base64;

@Service
public class OAuth2Service {

    @Value("${oauth2.auth-server}")
    private String authServer;

    @Value("${oauth2.client-id}")
    private String clientId;

    @Value("${oauth2.client-secret}")
    private String clientSecret;

    @Value("${oauth2.redirect-uri}")
    private String redirectUri;

    @Value("${oauth2.scope}")
    private String scope;

    private final WebClient webClient;

    public OAuth2Service() {
        this.webClient = WebClient.builder().build();
    }

    public String generateState() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public String buildAuthorizationUrl(String state) {
        return authServer + "/authorize" +
               "?client_id=" + clientId +
               "&redirect_uri=" + redirectUri +
               "&response_type=code" +
               "&scope=" + scope +
               "&state=" + state;
    }

    public TokenResponse exchangeCodeForToken(String code) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "authorization_code");
        formData.add("code", code);
        formData.add("redirect_uri", redirectUri);
        formData.add("client_id", clientId);
        formData.add("client_secret", clientSecret);

        return webClient.post()
                .uri(authServer + "/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .block();
    }

    public UserInfo getUserInfo(String accessToken) {
        return webClient.get()
                .uri(authServer + "/userinfo")
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .bodyToMono(UserInfo.class)
                .block();
    }
}
```

#### AuthController.java

```java
package com.example.client.controller;

import com.example.client.dto.TokenResponse;
import com.example.client.dto.UserInfo;
import com.example.client.service.OAuth2Service;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private OAuth2Service oauth2Service;

    @GetMapping("/login")
    public String login(HttpSession session) {
        String state = oauth2Service.generateState();
        session.setAttribute("oauth2State", state);

        String authUrl = oauth2Service.buildAuthorizationUrl(state);
        logger.info("重定向到授权服务器: {}", authUrl);

        return "redirect:" + authUrl;
    }

    @GetMapping("/callback")
    public String callback(@RequestParam(required = false) String code,
                          @RequestParam(required = false) String state,
                          @RequestParam(required = false) String error,
                          HttpSession session,
                          Model model) {

        logger.info("收到回调: code={}, state={}, error={}", code, state, error);

        // 检查错误
        if (error != null) {
            model.addAttribute("error", "授权失败: " + error);
            return "index";
        }

        // 验证state参数
        String sessionState = (String) session.getAttribute("oauth2State");
        if (sessionState == null || !sessionState.equals(state)) {
            model.addAttribute("error", "State参数验证失败，可能存在CSRF攻击");
            return "index";
        }

        session.removeAttribute("oauth2State");

        try {
            // 交换访问令牌
            logger.info("交换访问令牌...");
            TokenResponse tokenResponse = oauth2Service.exchangeCodeForToken(code);
            logger.info("获取到访问令牌");

            // 获取用户信息
            logger.info("获取用户信息...");
            UserInfo userInfo = oauth2Service.getUserInfo(tokenResponse.getAccessToken());
            logger.info("登录成功，用户信息: {}", userInfo);

            // 保存到会话
            session.setAttribute("user", userInfo);
            session.setAttribute("accessToken", tokenResponse.getAccessToken());

            return "redirect:/profile";

        } catch (Exception e) {
            logger.error("OAuth2流程错误", e);
            model.addAttribute("error", "登录失败: " + e.getMessage());
            return "index";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }
}
```

### 5. DTO类

#### TokenResponse.java

```java
package com.example.client.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TokenResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType;

    @JsonProperty("expires_in")
    private Integer expiresIn;

    private String scope;

    // Getters and Setters
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }

    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }

    public Integer getExpiresIn() { return expiresIn; }
    public void setExpiresIn(Integer expiresIn) { this.expiresIn = expiresIn; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
}
```

#### UserInfo.java

```java
package com.example.client.dto;

public class UserInfo {
    private String sub;
    private String name;
    private String email;
    private String profile;

    // Getters and Setters
    public String getSub() { return sub; }
    public void setSub(String sub) { this.sub = sub; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getProfile() { return profile; }
    public void setProfile(String profile) { this.profile = profile; }

    @Override
    public String toString() {
        return "UserInfo{" +
               "sub='" + sub + '\'' +
               ", name='" + name + '\'' +
               ", email='" + email + '\'' +
               ", profile='" + profile + '\'' +
               '}';
    }
}
```

---

## 部署和运行

### 1. 构建和运行授权服务器

```bash
# 进入授权服务器目录
cd oauth2-auth-server

# 编译打包
mvn clean package

# 运行
java -jar target/oauth2-auth-server-1.0.0.jar

# 或者直接运行
mvn spring-boot:run
```

授权服务器将在 `http://localhost:8080` 运行。

### 2. 构建和运行客户端应用

```bash
# 进入客户端应用目录
cd oauth2-client

# 编译打包
mvn clean package

# 运行
java -jar target/oauth2-client-1.0.0.jar

# 或者直接运行
mvn spring-boot:run
```

客户端应用将在 `http://localhost:8081` 运行。

### 3. 测试流程

1. 访问 `http://localhost:8081`
2. 点击"使用OAuth2登录"
3. 使用测试账号登录：
   - 用户名: `admin` 密码: `password123`
   - 或者 用户名: `user1` 密码: `mypassword`
4. 授权后查看用户信息

---

## Java版本的优势

1. **类型安全**: 编译时错误检查，减少运行时问题
2. **Spring生态**: 成熟的依赖注入、AOP、事务管理
3. **数据库集成**: JPA/Hibernate自动表创建和关系映射
4. **安全性**: Spring Security提供完整的安全框架
5. **企业级特性**: 监控、日志、配置管理等
6. **性能**: JVM优化和多线程支持
7. **维护性**: 强类型系统和IDE支持提高代码质量

## 与Node.js版本对比

| 特性 | Node.js版本 | Java Spring Boot版本 |
|------|-------------|----------------------|
| 学习曲线 | 较平缓 | 稍陡峭 |
| 开发速度 | 快速原型 | 中等 |
| 类型安全 | 运行时检查 | 编译时检查 |
| 生态系统 | npm包丰富 | Spring生态成熟 |
| 企业应用 | 适合小型项目 | 适合大型企业应用 |
| 性能 | 单线程异步 | 多线程优化 |
| 部署 | 简单 | 标准化 |

选择哪个版本取决于你的具体需求、团队技能和项目规模。