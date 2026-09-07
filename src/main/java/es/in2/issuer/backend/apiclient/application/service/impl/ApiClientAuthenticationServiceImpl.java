package es.in2.issuer.backend.apiclient.application.service.impl;

import es.in2.issuer.backend.apiclient.domain.exception.ApiClientAuthenticationException;
import es.in2.issuer.backend.apiclient.domain.model.ApiClient;
import es.in2.issuer.backend.apiclient.domain.model.AuthenticatedApiClient;
import es.in2.issuer.backend.apiclient.domain.service.ApiClientAuthenticationService;
import es.in2.issuer.backend.apiclient.domain.spi.ApiClientRepository;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Map;

@Slf4j
@Service
public class ApiClientAuthenticationServiceImpl implements ApiClientAuthenticationService {

    private static final String AUDIT_SUCCESS_EVENT = "intake.auth.success";
    private static final String AUDIT_FAILURE_EVENT = "intake.auth.failure";
    private static final String RESOURCE_TYPE = "api_client";

    private final ApiClientRepository apiClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    // Valid-format BCrypt hash that matches no real secret. Compared against
    // on every "client not found" path so that an unknown client_id costs
    // the same wall-clock time as a wrong secret (ES-03, NFR-S-EUD75-02) —
    // otherwise the early return would be a timing oracle for enumeration.
    private final String dummySecretHash;

    public ApiClientAuthenticationServiceImpl(
            ApiClientRepository apiClientRepository,
            PasswordEncoder passwordEncoder,
            AuditService auditService,
            @Value("${app.security.dummy-secret-hash}") String dummySecretHash) {
        this.apiClientRepository = apiClientRepository;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.dummySecretHash = dummySecretHash;
    }

    @Override
    public Mono<AuthenticatedApiClient> authenticateForToken(String tenant, String clientId, String clientSecret) {
        return apiClientRepository.findByClientId(clientId)
                .flatMap(client -> verify(tenant, clientId, clientSecret, client))
                .switchIfEmpty(Mono.defer(() -> denyUnknownClient(tenant, clientId, clientSecret)))
                .onErrorResume(
                        ex -> !(ex instanceof ApiClientAuthenticationException),
                        ex -> denyRepositoryFailure(tenant, clientId, ex)
                );
    }

    private Mono<AuthenticatedApiClient> verify(String tenant, String clientId, String clientSecret, ApiClient client) {
        return matches(clientSecret, client.secretHash())
              .flatMap(secretMatches -> {
                if (!Boolean.TRUE.equals(secretMatches)) {
                  return deny(tenant, clientId, "invalid_secret");
                }

                if (!client.isActive()) {
                  return deny(tenant, clientId, "client_not_active");
                }

                auditService.auditSuccess(
                        AUDIT_SUCCESS_EVENT,
                        clientId,
                        RESOURCE_TYPE,
                        tenant,
                        Map.of("tenant", tenant, "grant_type", "client_credentials"));

                return Mono.just(
                        new AuthenticatedApiClient(
                                client.clientId(),
                                client.canTriggerIssuance()));
              });
    }

    private Mono<AuthenticatedApiClient> denyUnknownClient(String tenant, String clientId, String clientSecret) {
        // Burn the same BCrypt cost as a real comparison before denying.
        return matches(clientSecret, dummySecretHash)
                .then(deny(tenant, clientId, "client_not_found"));
    }

    private Mono<AuthenticatedApiClient> denyRepositoryFailure(String tenant, String clientId, Throwable cause) {
        log.error("api_client lookup failed for tenant={}", tenant, cause);
        return deny(tenant, clientId, "repository_error");
    }

    private Mono<AuthenticatedApiClient> deny(String tenant, String clientId, String cause) {
        auditService.auditFailure(AUDIT_FAILURE_EVENT, clientId, cause, Map.of("tenant", tenant));
        return Mono.error(ApiClientAuthenticationException.invalidClient());
    }

    private Mono<Boolean> matches(String rawSecret, String hash) {
        return Mono.fromCallable(() -> passwordEncoder.matches(rawSecret == null ? "" : rawSecret, hash))
                .subscribeOn(Schedulers.boundedElastic());
    }
}
