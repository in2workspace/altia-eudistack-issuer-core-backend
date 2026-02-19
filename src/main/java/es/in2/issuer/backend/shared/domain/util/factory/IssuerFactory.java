package es.in2.issuer.backend.shared.domain.util.factory;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.service.impl.SigningRecoveryServiceImpl;
import es.in2.issuer.backend.signing.domain.service.impl.QtspIssuerServiceImpl;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import es.in2.issuer.backend.signing.infrastructure.config.DefaultSignerConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Date;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.*;

@Component
@RequiredArgsConstructor
@Slf4j
public class IssuerFactory {

    private final DefaultSignerConfig defaultSignerConfig;
    private final SigningRecoveryServiceImpl signingRecoveryServiceImpl;
    private final QtspIssuerServiceImpl qtspIssuerServiceImpl;

    /**
     * Detailed issuer creation without post-recover side-effects.
     * - Server mode: local issuer
     * - Remote mode: remote flow, retries, errors are propagated
     */
    public Mono<DetailedIssuer> createDetailedIssuer() {
        log.debug("🔐: createDetailedIssuer");
        return qtspIssuerServiceImpl.isServerMode()
                ? Mono.just(buildLocalDetailedIssuer())
                : createRemoteDetailedIssuer();
    }

    /**
     * Simple issuer creation without post-recover side-effects.
     * - Server mode: local issuer
     * - Remote mode: remote flow, retries, errors are propagated
     */
    public Mono<SimpleIssuer> createSimpleIssuer() {
        log.debug("🔐: createSimpleIssuer");
        return qtspIssuerServiceImpl.isServerMode()
                ? Mono.just(buildLocalSimpleIssuer())
                : createRemoteDetailedIssuer()
                .map(detailed -> SimpleIssuer.builder()
                        .id(detailed.getId())
                        .build());
    }

    /**
     * Detailed issuer creation with post-recover side-effects on error:
     * - If remote flow fails after retries, it executes handlePostRecoverError(procedureId, email)
     *   and completes empty.
     */
    public Mono<DetailedIssuer> createDetailedIssuerAndNotifyOnError(String procedureId, String email) {
        log.debug("🔐: createDetailedIssuerAndNotifyOnError");
        return qtspIssuerServiceImpl.isServerMode()
                ? Mono.just(buildLocalDetailedIssuer())
                : createRemoteDetailedIssuerNotifyOnError(procedureId, email);
    }

    /**
     * Simple issuer creation with post-recover side-effects on error:
     * - If remote flow fails after retries, it executes handlePostRecoverError(procedureId, email)
     *   and completes empty.
     */
    public Mono<SimpleIssuer> createSimpleIssuerAndNotifyOnError(String procedureId, String email) {
        log.debug("🔐: createSimpleIssuerAndNotifyOnError");
        return qtspIssuerServiceImpl.isServerMode()
                ? Mono.just(buildLocalSimpleIssuer())
                : createRemoteDetailedIssuerNotifyOnError(procedureId, email)
                .map(detailed -> SimpleIssuer.builder()
                        .id(detailed.getId())
                        .build());
    }

    private DetailedIssuer buildLocalDetailedIssuer() {
        return DetailedIssuer.builder()
                .id(DID_ELSI + defaultSignerConfig.getOrganizationIdentifier())
                .organizationIdentifier(defaultSignerConfig.getOrganizationIdentifier())
                .organization(defaultSignerConfig.getOrganization())
                .country(defaultSignerConfig.getCountry())
                .commonName(defaultSignerConfig.getCommonName())
                .serialNumber(defaultSignerConfig.getSerialNumber())
                .build();
    }

    private SimpleIssuer buildLocalSimpleIssuer() {
        return SimpleIssuer.builder()
                .id(DID_ELSI + defaultSignerConfig.getOrganizationIdentifier())
                .build();
    }

    /**
     * Remote flow used by the "no notify on error" methods:
     * - retries recoverable errors
     * - propagates the error downstream if it still fails
     */
    private Mono<DetailedIssuer> createRemoteDetailedIssuer() {
        log.debug("🔐: createRemoteDetailedIssuer");
        return remoteIssuerCoreFlow()
                .retryWhen(buildRetrySpec())
                .doOnError(err ->
                        log.error("Error during remote issuer creation at {}: {}", new Date(), err.getMessage())
                );
    }

    /**
     * Remote flow used by the "notify on error" methods:
     * - retries recoverable errors
     * - if it still fails, executes handlePostRecoverError(procedureId, email) and completes empty
     */
    private Mono<DetailedIssuer> createRemoteDetailedIssuerNotifyOnError(String procedureId, String email) {
        log.debug("🔐: createRemoteDetailedIssuerNotifyOnError");
        return remoteIssuerCoreFlow()
                .retryWhen(buildRetrySpec())
                .onErrorResume(err -> {
                    log.error("Error during remote issuer creation at {}: {}", new Date(), err.getMessage());
                    return signingRecoveryServiceImpl.handlePostRecoverError(procedureId, email)
                            .then(Mono.empty());
                });
    }

    /**
     * Core remote signature flow: validate -> token -> certInfo -> extract issuer
     */
    private Mono<DetailedIssuer> remoteIssuerCoreFlow() {
        return qtspIssuerServiceImpl.resolveRemoteDetailedIssuer();
    }

    private Retry buildRetrySpec() {
        return Retry.backoff(3, Duration.ofSeconds(1))
                .maxBackoff(Duration.ofSeconds(5))
                .jitter(0.5)
                .filter(QtspRetryPolicy::isRecoverable)
                .doBeforeRetry(rs -> log.info("Retry #{} for remote signature", rs.totalRetries() + 1));
    }
}