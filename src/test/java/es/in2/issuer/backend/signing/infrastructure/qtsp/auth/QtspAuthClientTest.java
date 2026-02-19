package es.in2.issuer.backend.signing.infrastructure.qtsp.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import es.in2.issuer.backend.signing.domain.model.SigningRequest;
import es.in2.issuer.backend.signing.domain.service.HashGeneratorService;
import es.in2.issuer.backend.signing.infrastructure.config.RemoteSignatureConfig;
import es.in2.issuer.backend.shared.domain.util.HttpUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static es.in2.issuer.backend.backoffice.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;


@ExtendWith(MockitoExtension.class)
class QtspAuthClientTest {

    @Mock private RemoteSignatureConfig remoteSignatureConfig;
    @Mock private HashGeneratorService hashGeneratorService;
    @Mock private HttpUtils httpUtils;

    private QtspAuthClient client;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = new ObjectMapper();
        client = new QtspAuthClient(objectMapper, remoteSignatureConfig, hashGeneratorService, httpUtils);

        when(remoteSignatureConfig.getRemoteSignatureDomain()).thenReturn("https://qtsp");
        when(remoteSignatureConfig.getRemoteSignatureClientId()).thenReturn("clientId");
        when(remoteSignatureConfig.getRemoteSignatureClientSecret()).thenReturn("clientSecret");
    }

    @Test
    void requestAccessToken_returnsToken_whenAccessTokenPresent() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{\"access_token\":\"tok123\"}"));

        StepVerifier.create(client.requestAccessToken(SigningRequest.builder().data("x").build(), "some-scope"))
                .assertNext(token -> assertEquals("tok123", token))
                .verifyComplete();

        verify(httpUtils).postRequest(eq("https://qtsp/oauth2/token"), anyList(), anyString());
    }

    @Test
    void requestAccessToken_errors_whenAccessTokenMissing() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{\"token_type\":\"bearer\"}"));

        StepVerifier.create(client.requestAccessToken(SigningRequest.builder().data("x").build(), "some-scope"))
                .expectErrorMatches(e ->
                        e instanceof RemoteSignatureException &&
                                e.getMessage().contains("Unexpected error retrieving access token"))
                .verify();
    }

    @Test
    void requestAccessToken_includesAuthorizationDetails_whenScopeIsCredential() throws Exception {
        when(hashGeneratorService.generateHash(anyString(), anyString()))
                .thenReturn("HASHED");

        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.just("{\"access_token\":\"tok123\"}"));

        SigningRequest sr = SigningRequest.builder().data("{\"vc\":1}").build();

        StepVerifier.create(client.requestAccessToken(sr, SIGNATURE_REMOTE_SCOPE_CREDENTIAL))
                .assertNext(token -> assertEquals("tok123", token))
                .verifyComplete();

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<List> headersCaptor = ArgumentCaptor.forClass(List.class);

        verify(httpUtils).postRequest(eq("https://qtsp/oauth2/token"), headersCaptor.capture(), bodyCaptor.capture());

        String body = bodyCaptor.getValue();
        assertTrue(body.contains("grant_type=client_credentials"));
        assertTrue(body.contains("scope=" + SIGNATURE_REMOTE_SCOPE_CREDENTIAL));
        assertTrue(body.contains("authorization_details=")); // se mete como JSON string

        @SuppressWarnings("unchecked")
        List<Map.Entry<String, String>> headers = (List<Map.Entry<String, String>>) headersCaptor.getValue();

        String expectedBasic = "Basic " + Base64.getEncoder().encodeToString(
                ("clientId:clientSecret").getBytes(StandardCharsets.UTF_8)
        );

        boolean hasAuth = headers.stream().anyMatch(e -> e.getKey().equals(HttpHeaders.AUTHORIZATION) && e.getValue().equals(expectedBasic));
        boolean hasCt = headers.stream().anyMatch(e -> e.getKey().equals(HttpHeaders.CONTENT_TYPE) && e.getValue().contains("application/x-www-form-urlencoded"));

        assertTrue(hasAuth);
        assertTrue(hasCt);

        verify(hashGeneratorService).generateHash("{\"vc\":1}", "2.16.840.1.101.3.4.2.1");
    }

    @Test
    void requestAccessToken_mapsUnauthorizedToRemoteSignatureException() {
        WebClientResponseException unauthorized =
                WebClientResponseException.create(
                        HttpStatus.UNAUTHORIZED.value(),
                        "Unauthorized",
                        null,
                        null,
                        null
                );

        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.error(unauthorized));

        StepVerifier.create(client.requestAccessToken(SigningRequest.builder().data("x").build(), "some-scope"))
                .expectErrorMatches(e ->
                        e instanceof RemoteSignatureException &&
                                e.getMessage().contains("Unexpected error retrieving access token"))
                .verify();
    }

    @Test
    void requestAccessToken_mapsGenericExceptionToRemoteSignatureException() {
        when(httpUtils.postRequest(anyString(), anyList(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(client.requestAccessToken(SigningRequest.builder().data("x").build(), "some-scope"))
                .expectErrorMatches(e ->
                        e instanceof RemoteSignatureException &&
                                e.getMessage().contains("Unexpected error retrieving access token"))
                .verify();
    }
}
