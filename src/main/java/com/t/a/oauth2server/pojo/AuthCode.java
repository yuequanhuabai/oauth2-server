package com.t.a.oauth2server.pojo;

import com.t.a.oauth2server.enums.CodeChallengeMethod;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class AuthCode {
    private String code;
    private String clientId;
    private String username;
    private long expireTime;

    // 引入pkce
    private String codeChallenge;
    private CodeChallengeMethod codeChallengeMethod;


}
