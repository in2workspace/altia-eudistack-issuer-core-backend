package es.in2.issuer.backend.signing.infrastructure.qtsp.signhash;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import es.in2.issuer.backend.signing.domain.model.dto.CscAuthorizeResponse;
import es.in2.issuer.backend.signing.domain.model.dto.CscSignHashResponse;
import es.in2.issuer.backend.signing.infrastructure.config.RemoteSignatureConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.*;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class QtspSignHashClient {

    private static final String AUTHORIZE_PATH = "/csc/v2/credentials/authorize";
    private static final String SIGN_HASH_PATH = "/csc/v2/signatures/signHash";

    private final ObjectMapper objectMapper;
    private final RemoteSignatureConfig remoteSignatureConfig;
    private final HttpUtils httpUtils;

    /**
     * CSC v2: credentials/authorize for signHash.
     */
    public Mono<String> authorizeForHash(String accessToken, String hashB64Url, String hashAlgoOid) {
        String endpoint = remoteSignatureConfig.getRemoteSignatureDomain() + AUTHORIZE_PATH;

        Map<String, Object> body = new HashMap<>();
        body.put(CREDENTIAL_ID, remoteSignatureConfig.getRemoteSignatureCredentialId());
        body.put(NUM_SIGNATURES, 1);

        // IMPORTANT: signHash authorization uses hash + hashAlgo (array)
        body.put("hash", List.of(hashB64Url));
        body.put("hashAlgo", hashAlgoOid);

        // authData: password
        Map<String, String> authEntry = new HashMap<>();
        authEntry.put(AUTH_DATA_ID, "password");
        authEntry.put(AUTH_DATA_VALUE, remoteSignatureConfig.getRemoteSignatureCredentialPassword());
        body.put(AUTH_DATA, List.of(authEntry));

        String json;
        try {
            json = objectMapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException("Error serializing authorize(signHash) body", e));
        }

        List<Map.Entry<String, String>> headers = List.of(
                new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken),
                new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
        );

        return httpUtils.postRequest(endpoint, headers, json)
                .flatMap(respJson -> Mono.fromCallable(() -> objectMapper.readValue(respJson, CscAuthorizeResponse.class)))
                .map(CscAuthorizeResponse::SAD)
                .switchIfEmpty(Mono.error(new RemoteSignatureException("Empty authorize response (missing SAD)")))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized on authorize(signHash)"));
                    }
                    return Mono.error(new RemoteSignatureException("QTSP authorize(signHash) failed", ex));
                });
    }

    /**
     * CSC v2: signatures/signHash.
     * Returns raw signature (first element of 'signatures').
     */
    public Mono<String> signHash(String accessToken, String sad, String hashB64Url, String hashAlgoOid, String signAlgoOid) {
        String endpoint = remoteSignatureConfig.getRemoteSignatureDomain() + SIGN_HASH_PATH;

        Map<String, Object> body = new HashMap<>();
        body.put(CREDENTIAL_ID, remoteSignatureConfig.getRemoteSignatureCredentialId());
        body.put("SAD", sad);
        body.put("hash", List.of(hashB64Url));
        body.put("hashAlgo", hashAlgoOid);

        // IMPORTANT: CSC expects signAlgo OID (e.g. ES256 -> 1.2.840.10045.4.3.2)
        body.put("signAlgo", signAlgoOid);

        String json;
        try {
            json = objectMapper.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException("Error serializing signHash body", e));
        }

        List<Map.Entry<String, String>> headers = List.of(
                new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken),
                new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
        );

        return httpUtils.postRequest(endpoint, headers, json)
                .flatMap(respJson -> Mono.fromCallable(() -> objectMapper.readValue(respJson, CscSignHashResponse.class)))
                .flatMap(resp -> {
                    if (resp.signatures() == null || resp.signatures().isEmpty() || resp.signatures().get(0) == null) {
                        return Mono.error(new RemoteSignatureException("signHash response missing signatures[0]"));
                    }
                    return Mono.just(resp.signatures().get(0));
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized on signHash"));
                    }
                    return Mono.error(new RemoteSignatureException("QTSP signHash failed", ex));
                });
    }
}
