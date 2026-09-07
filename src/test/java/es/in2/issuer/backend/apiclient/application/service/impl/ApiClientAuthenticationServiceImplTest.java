package es.in2.issuer.backend.apiclient.application.service.impl;

import es.in2.issuer.backend.apiclient.domain.exception.ApiClientAuthenticationException;
import es.in2.issuer.backend.apiclient.domain.model.ApiClient;
import es.in2.issuer.backend.apiclient.domain.model.AuthenticatedApiClient;
import es.in2.issuer.backend.apiclient.domain.model.AuthorizationStatus;
import es.in2.issuer.backend.apiclient.domain.spi.ApiClientRepository;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApiClientAuthenticationServiceImplTest {

    private static final String TENANT = "acme";
    private static final String CLIENT_ID = "acme-hr";
    private static final String RAW_SECRET = "s3cr3t-value";
    private static final String DUMMY_HASH = "$2a$10$rCk2.19r3MaYAe4KZkmvIOXv6FBRCMvaKH9FG7txMfvek27a45y26";

    @Mock
    private ApiClientRepository apiClientRepository;

    @Mock
    private AuditService auditService;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private ApiClientAuthenticationServiceImpl service;

    private void init() {
        service = new ApiClientAuthenticationServiceImpl(apiClientRepository, passwordEncoder, auditService, DUMMY_HASH);
    }

    private ApiClient clientWith(AuthorizationStatus status, boolean canTriggerIssuance) {
        return new ApiClient(CLIENT_ID, status, canTriggerIssuance, passwordEncoder.encode(RAW_SECRET));
    }

    @Test
    void authenticateForToken_activeClientValidSecret_returnsAuthenticatedApiClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectNextMatches(client -> client.clientId().equals(CLIENT_ID) && client.canTriggerIssuance())
                .verifyComplete();
        verify(auditService).auditSuccess(eq("intake.auth.success"), eq(CLIENT_ID), anyString(), anyString(), anyMapArg());
    }

    @Test
    void authenticateForToken_unknownClientId_deniesInvalidClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID)).thenReturn(Mono.empty());

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("client_not_found"), anyMapArg());
    }

    @Test
    void authenticateForToken_wrongSecret_deniesInvalidClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, "wrong-secret");

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("invalid_secret"), anyMapArg());
    }

    @Test
    void authenticateForToken_revokedClient_deniesInvalidClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.REVOKED, true)));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("client_not_active"), anyMapArg());
    }

    @Test
    void authenticateForToken_suspendedClient_deniesInvalidClient() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.SUSPENDED, true)));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
    }

    @Test
    void authenticateForToken_repositoryFailure_failsClosed() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.error(new RuntimeException("connection refused")));

        Mono<AuthenticatedApiClient> result = service.authenticateForToken(TENANT, CLIENT_ID, RAW_SECRET);

        StepVerifier.create(result)
                .expectError(ApiClientAuthenticationException.class)
                .verify();
        verify(auditService).auditFailure(eq("intake.auth.failure"), eq(CLIENT_ID), eq("repository_error"), anyMapArg());
    }

    @Test
    void authenticateForToken_unknownClientAndWrongSecret_produceIdenticalExceptionMessage() {
        init();
        when(apiClientRepository.findByClientId("unknown-client")).thenReturn(Mono.empty());
        String unknownClientMessage = captureDenialMessage(
                service.authenticateForToken(TENANT, "unknown-client", RAW_SECRET));

        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));
        String wrongSecretMessage = captureDenialMessage(
                service.authenticateForToken(TENANT, CLIENT_ID, "wrong-secret"));

        assertThat(unknownClientMessage).isEqualTo(wrongSecretMessage);
    }

    private String captureDenialMessage(Mono<AuthenticatedApiClient> result) {
        try {
            result.block();
            throw new AssertionError("expected ApiClientAuthenticationException");
        } catch (ApiClientAuthenticationException ex) {
            return ex.getMessage();
        }
    }

    @Test
    void authenticateForToken_deniedPaths_neverIncludeClientSecretInAuditDetails() {
        init();
        when(apiClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(Mono.just(clientWith(AuthorizationStatus.ACTIVE, true)));

        StepVerifier.create(service.authenticateForToken(TENANT, CLIENT_ID, "wrong-secret"))
                .expectError(ApiClientAuthenticationException.class)
                .verify();

        ArgumentCaptor<Map<String, Object>> detailsCaptor = mapCaptor();
        verify(auditService).auditFailure(anyString(), anyString(), anyString(), detailsCaptor.capture());
        assertThat(detailsCaptor.getValue()).doesNotContainKey("client_secret");
        assertThat(detailsCaptor.getValue().values()).noneMatch(v -> RAW_SECRET.equals(v) || "wrong-secret".equals(v));
        verify(auditService, never()).auditSuccess(anyString(), anyString(), anyString(), anyString(), anyMapArg());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> anyMapArg() {
        return org.mockito.ArgumentMatchers.anyMap();
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Map<String, Object>> mapCaptor() {
        return ArgumentCaptor.forClass(Map.class);
    }
}
