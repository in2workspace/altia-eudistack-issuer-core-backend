package es.in2.issuer.backend.signing.infrastructure.qtsp.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.exception.SadException;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
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
public class QtspSadClient  {

    private static final String SAD_NAME = "SAD";

    private final ObjectMapper objectMapper;
    private final RemoteSignatureConfig remoteSignatureConfig;
    private final HttpUtils httpUtils;

    public Mono<String> requestSad(String accessToken) {
        String credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        String signatureGetSadEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/csc/v2/credentials/authorize";

        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put(CREDENTIAL_ID, credentialID);
        requestBody.put(NUM_SIGNATURES, 1);

        Map<String, String> authEntry = new HashMap<>();
        authEntry.put(AUTH_DATA_ID, "password");
        authEntry.put(AUTH_DATA_VALUE, remoteSignatureConfig.getRemoteSignatureCredentialPassword());
        requestBody.put(AUTH_DATA, List.of(authEntry));

        final String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(requestBody);
        } catch (JsonProcessingException e) {
            return Mono.error(new RemoteSignatureException("Error serializing SAD request body", e));
        }

        List<Map.Entry<String, String>> headers = new ArrayList<>();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + accessToken));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE));

        return httpUtils.postRequest(signatureGetSadEndpoint, headers, jsonBody)
                .flatMap(responseJson -> Mono.fromCallable(() -> {
                    Map<String, Object> responseMap = objectMapper.readValue(responseJson, Map.class);
                    Object sad = responseMap.get(SAD_NAME);
                    if (sad == null) {
                        throw new SadException("SAD missing in response");
                    }
                    return sad.toString();
                }))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized: Invalid credentials", ex));
                    }
                    return Mono.error(new RemoteSignatureException("Error requesting SAD", ex));
                });
    }
}