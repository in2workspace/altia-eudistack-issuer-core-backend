package es.in2.issuer.backend.signing.infrastructure.qtsp.auth;

import java.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.exception.AccessTokenException;
import es.in2.issuer.backend.signing.domain.exception.AuthorizationDetailsException;
import es.in2.issuer.backend.signing.domain.exception.HashGenerationException;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.shared.domain.model.dto.SignatureRequest;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
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

import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.CREDENTIAL_ID;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;

@Slf4j
@Component
@RequiredArgsConstructor
public class QtspAuthClient {

    private final ObjectMapper objectMapper;
    private final RemoteSignatureConfig remoteSignatureConfig;
    private final HashGeneratorService hashGeneratorService;
    private final Map<String, Object> requestBody = new HashMap<>();
    private final List<Map.Entry<String, String>> headers = new ArrayList<>();
    private final HttpUtils httpUtils;

    private static final String ACCESS_TOKEN_NAME = "access_token";

    private String credentialID;
    private String credentialPassword;

    public Mono<String> requestAccessToken(SignatureRequest signatureRequest, String scope){
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        credentialPassword = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        String clientId = remoteSignatureConfig.getRemoteSignatureClientId();
        String clientSecret = remoteSignatureConfig.getRemoteSignatureClientSecret();
        String grantType = "client_credentials";
        String signatureGetAccessTokenEndpoint = remoteSignatureConfig.getRemoteSignatureDomain() + "/oauth2/token";
        String hashAlgorithmOID = "2.16.840.1.101.3.4.2.1";

        requestBody.clear();
        requestBody.put("grant_type", grantType);
        requestBody.put("scope", scope);
        if (scope.equals(SIGNATURE_REMOTE_SCOPE_CREDENTIAL)) {
            requestBody.put("authorization_details", buildAuthorizationDetails(signatureRequest.data(), hashAlgorithmOID));
        }

        String requestBodyString = requestBody.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .reduce((p1, p2) -> p1 + "&" + p2)
                .orElse("");

        String basicAuthHeader = "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        headers.clear();
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.AUTHORIZATION, basicAuthHeader));
        headers.add(new AbstractMap.SimpleEntry<>(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE));
        return httpUtils.postRequest(signatureGetAccessTokenEndpoint, headers, requestBodyString)
                .flatMap(responseJson -> Mono.fromCallable(() -> {
                    try {
                        Map<String, Object> responseMap = objectMapper.readValue(responseJson, Map.class);
                        if (!responseMap.containsKey(ACCESS_TOKEN_NAME)) {
                            throw new AccessTokenException("Access token missing in response");
                        }
                        return (String) responseMap.get(ACCESS_TOKEN_NAME);
                    } catch (JsonProcessingException e) {
                        throw new AccessTokenException("Error parsing access token response", e);
                    }
                }))
                .onErrorResume(WebClientResponseException.class, ex -> {
                    log.error("Access token endpoint [{}] returned {} {}",
                            signatureGetAccessTokenEndpoint, ex.getStatusCode(), ex.getStatusText());
                    if (ex.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new RemoteSignatureException("Unauthorized: Invalid credentials"));
                    }
                    return Mono.error(new RemoteSignatureException("Remote service error while retrieving access token", ex));
                })
                .onErrorResume(UnknownHostException.class, ex -> {
                    log.error("Could not resolve host [{}] - check DNS or VPN", signatureGetAccessTokenEndpoint);
                    return Mono.error(new RemoteSignatureException("Signature service unreachable: DNS resolution failed", ex));
                })
                .onErrorResume(Exception.class, ex -> {
                    log.error("Unexpected error accessing [{}]: {}", signatureGetAccessTokenEndpoint, ex.getMessage());
                    return Mono.error(new RemoteSignatureException("Unexpected error retrieving access token", ex));
                });
    }

    private String buildAuthorizationDetails(String unsignedCredential, String hashAlgorithmOID) {
        credentialID = remoteSignatureConfig.getRemoteSignatureCredentialId();
        credentialPassword = remoteSignatureConfig.getRemoteSignatureCredentialPassword();
        try {
            Map<String, Object> authorizationDetails = new HashMap<>();
            authorizationDetails.put("type", SIGNATURE_REMOTE_SCOPE_CREDENTIAL);
            authorizationDetails.put(CREDENTIAL_ID, credentialID);
            authorizationDetails.put("credentialPassword", credentialPassword);
            String hashedCredential = hashGeneratorService.generateHash(unsignedCredential, hashAlgorithmOID);
            List<Map<String, String>> documentDigests = null;
            if (hashedCredential != null) {
                documentDigests = List.of(
                        Map.of("hash", hashedCredential, "label", "Issued Credential")
                );
            }
            authorizationDetails.put("documentDigests", documentDigests);
            authorizationDetails.put("hashAlgorithmOID", hashAlgorithmOID);

            return objectMapper.writeValueAsString(List.of(authorizationDetails));
        } catch (JsonProcessingException | HashGenerationException e) {
            throw new AuthorizationDetailsException("Error generating authorization details", e);
        }
    }

}
