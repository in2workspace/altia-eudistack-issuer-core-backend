package es.in2.issuer.backend.signing.domain.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import es.in2.issuer.backend.signing.infrastructure.qtsp.signhash.QtspSignHashClient;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwsSignHashServiceImpl implements JwsSignHashService {

    public static final String HASH_ALGO_OID_SHA256 = "2.16.840.1.101.3.4.2.1";
    public static final String SIGN_ALGO_OID_ES256 = "1.2.840.10045.4.3.2";

    private final ObjectMapper objectMapper;
    private final HashGeneratorService hashGeneratorService;
    private final QtspSignHashClient qtspSignHashClient;

    /**
     * @param accessToken QTSP bearer token
     * @param headerJson JWS header as JSON string (must contain at least alg/typ and optionally x5c)
     * @param payloadJson JWT payload as JSON string
     */
    @Override
    public Mono<String> signJwtWithSignHash(String accessToken, String headerJson, String payloadJson) {
        final String headerB64Url;
        final String payloadB64Url;

        try {
            headerB64Url = Base64UrlUtils.encodeUtf8(headerJson);
            payloadB64Url = Base64UrlUtils.encodeUtf8(payloadJson);
        } catch (Exception e) {
            return Mono.error(new RemoteSignatureException("Failed to build JWS header/payload", e));
        }

        String signingInput = headerB64Url + "." + payloadB64Url;
        byte[] signingInputBytes = signingInput.getBytes(StandardCharsets.US_ASCII);

        final String hashB64Url;
        try {
            byte[] digest = hashGeneratorService.sha256Digest(signingInputBytes);
            hashB64Url = Base64UrlUtils.encode(digest);
        } catch (Exception e) {
            return Mono.error(new RemoteSignatureException("Failed to compute signingInput digest", e));
        }

        return qtspSignHashClient.authorizeForHash(accessToken, hashB64Url, HASH_ALGO_OID_SHA256)
                .flatMap(sad ->
                        qtspSignHashClient.signHash(
                                accessToken,
                                sad,
                                hashB64Url,
                                HASH_ALGO_OID_SHA256,
                                SIGN_ALGO_OID_ES256
                        )
                )
                .map(signatureB64Url -> signingInput + "." + signatureB64Url);
    }

    private String buildHeaderJson(List<String> x5cChainBase64) throws JsonProcessingException {
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "ES256");
        header.put("typ", "JWT");
        if (x5cChainBase64 != null && !x5cChainBase64.isEmpty()) {
            header.put("x5c", x5cChainBase64);
        }
        return objectMapper.writeValueAsString(header);
    }
}