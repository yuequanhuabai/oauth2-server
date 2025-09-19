package com.t.a.oauth2server.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class ClientInfo {
    private String clientId;
    private String clientSecret;
    private String redirectUri;
}
