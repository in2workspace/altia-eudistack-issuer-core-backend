package es.in2.issuer.backend.signing.domain.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class Base64UrlUtils {
    private Base64UrlUtils() {}

    public static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String encodeUtf8(String s) {
        return encode(s.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decode(String b64url) {
        return Base64.getUrlDecoder().decode(b64url);
    }
}
