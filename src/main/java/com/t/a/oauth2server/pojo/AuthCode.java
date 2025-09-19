package com.t.a.oauth2server.pojo;

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
}
