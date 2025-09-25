package com.t.a.oauth2server.controller;

import com.t.a.oauth2server.conf.DataStore;
import com.t.a.oauth2server.enums.CodeChallengeMethod;
import com.t.a.oauth2server.pojo.AccessToken;
import com.t.a.oauth2server.pojo.AuthCode;
import com.t.a.oauth2server.pojo.ClientInfo;
import com.t.a.oauth2server.pojo.User;
import com.t.a.oauth2server.util.PkceVerifier;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

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
                            @RequestParam(required = false, name = "code_challenge") String codeChallenge,
                            @RequestParam(required = false, name = "code_challenge_method") String codeChallengeMethod,
                            Model model) {

        // 【安全检查1】验证客户端是否存在且redirect_uri是否匹配
        ClientInfo client = dataStore.getClients().get(client_id);
        if (client == null || !client.getRedirectUri().equals(redirect_uri)) {
            return "error";  // 返回错误页面
        }

        if (codeChallenge == null || codeChallenge.isBlank()) {
            model.addAttribute("error", "invalid_request");
            return "error";
        }

        String normalizedMethod = codeChallengeMethod == null
                ? CodeChallengeMethod.S256.name()
                : codeChallengeMethod.toUpperCase(Locale.ROOT);

        if (!CodeChallengeMethod.S256.name().equals(normalizedMethod)) {
            model.addAttribute("error", "unsupported_code_challenge_method");
            return "error";
        }
        model.addAttribute("code_challenge", codeChallenge);
        model.addAttribute("code_challenge_method", normalizedMethod);

        // 【数据传递】将参数传递给登录页面模板
        model.addAttribute("client_id", client_id);
        model.addAttribute("redirect_uri", redirect_uri);
        model.addAttribute("state", state == null ? "" : state);

        return "login";  // 渲染登录页面(src/main/resources/templates/login.html)
    }

    // =============== 步骤2: 处理用户登录和授权 ===============
    @PostMapping("/oauth/authorize")
    public String handleAuthorize(@RequestParam String client_id,
                                  @RequestParam String redirect_uri,
                                  @RequestParam(required = false) String state,
                                  @RequestParam String username,    // 用户输入的用户名
                                  @RequestParam String password,
                                  @RequestParam(required = false, name = "code_challenge") String codeChallenge,
                                  @RequestParam(required = false, name = "code_challenge_method") String codeChallengeMethod
                                  ) {  // 用户输入的密码

        // 【安全检查2】验证用户凭证
        User user = dataStore.getUsers().get(username);
        if (user == null || !user.getPassword().equals(password)) {
            // 登录失败，重定向回登录页面并显示错误
            return "redirect:/oauth/authorize?client_id=" + client_id +
                    "&redirect_uri=" + redirect_uri + "&response_type=code&error=invalid_user";
        }

        if (codeChallenge == null || codeChallenge.isBlank()) {
            return "redirect:/oauth/authorize?client_id=" + client_id +
                    "&redirect_uri=" + redirect_uri + "&response_type=code&error=invalid_request";
        }

        String normalizedMethod = codeChallengeMethod == null
                ? CodeChallengeMethod.S256.name()
                : codeChallengeMethod.toUpperCase(Locale.ROOT);

        if (!CodeChallengeMethod.S256.name().equals(normalizedMethod)) {
            return "redirect:/oauth/authorize?client_id=" + client_id +
                    "&redirect_uri=" + redirect_uri + "&response_type=code&error=unsupported_code_challenge_method";
        }

        CodeChallengeMethod method = CodeChallengeMethod.valueOf(normalizedMethod);

        // 【核心逻辑1】生成授权码 - OAuth2的关键机制
        String code = UUID.randomUUID().toString();  // 生成随机授权码
        AuthCode authCode = new AuthCode(code, client_id, username,
                System.currentTimeMillis() + 600000,
                codeChallenge,
                method
                ); // 10分钟过期
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
                                     @RequestParam String client_secret,
                                     HttpServletRequest request) {  // 客户端密钥

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

        String codeVerifier = request.getParameter("code_verifier");
        if (!PkceVerifier.matches(codeVerifier, authCode.getCodeChallenge(), authCode.getCodeChallengeMethod())) {
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
