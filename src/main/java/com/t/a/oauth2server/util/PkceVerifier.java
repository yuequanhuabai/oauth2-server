package com.t.a.oauth2server.util;

import com.t.a.oauth2server.enums.CodeChallengeMethod;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public final class PkceVerifier {

    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    public static boolean matches(String codeVerifier, String expectedChallenge, CodeChallengeMethod method) {
        if (codeVerifier == null || codeVerifier.length() < 43 || codeVerifier.length() > 128) {
            return false;
        }
        if (expectedChallenge == null || expectedChallenge.isBlank() || method == null) {
            return false;
        }
        String actual;
        if (method == CodeChallengeMethod.S256) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256")
                        .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                actual = BASE64_URL.encodeToString(digest);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 algorithm is not available", e);
            }
        } else {
            actual = codeVerifier;
        }
        return expectedChallenge.equals(actual);
    }
    private PkceVerifier() {}
}
