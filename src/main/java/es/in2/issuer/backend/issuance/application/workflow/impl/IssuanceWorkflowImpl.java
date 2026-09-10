package es.in2.issuer.backend.issuance.application.workflow.impl;

import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialBuildResult;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;
import es.in2.issuer.backend.issuance.domain.model.HolderKey;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.shared.domain.service.TenantConfigService;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import io.micrometer.observation.annotation.Observed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class IssuanceWorkflowImpl implements IssuanceWorkflow {

    private static final String DEFAULT_DELIVERY = "email";
    private static final String DELIVERY_MODES_CONFIG_PREFIX = "issuer.delivery.modes.";

    private final IssuanceService issuanceService;
    private final CredentialOfferService credentialOfferService;
    private final IssuancePdpService issuancePdpService;
    private final PayloadSchemaValidator payloadSchemaValidator;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final IssuanceMetrics issuanceMetrics;
    private final CredentialIssuedLogger credentialIssuedLogger;
    private final AuditService auditService;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final StatusListWorkflow statusListWorkflow;
    private final TenantConfigService tenantConfigService;
    private final IssuanceProperties issuanceProperties;

    @Override
    @Observed(name = "issuance.issue-credential", contextualName = "issuance-issue-credential")
    public Mono<IssuanceResponse> issueCredential(
            String processId,
            IssuanceRequest request,
            String idToken,
            String publicIssuerBaseUrl,
            String publicWalletBaseUrl) {

        var sample = issuanceMetrics.startTimer();
        String configId = request.credentialConfigurationId();
        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;

        return requireResolvedTenant()
                .then(Mono.defer(() -> validateRequest(request, idToken)))
                .then(Mono.defer(() -> payloadSchemaValidator.validate(configId, request.payload())))
                .then(Mono.defer(() -> issuancePdpService.authorize(configId, request.payload(), idToken)))
                .then(Mono.defer(() -> performIssuanceFlow(processId, request, idToken, publicIssuerBaseUrl, publicWalletBaseUrl, delivery)))
                .transformDeferredContextual((flow, ctx) -> {
                    String tenant = ctx.hasKey(TENANT_DOMAIN_CONTEXT_KEY) ? ctx.get(TENANT_DOMAIN_CONTEXT_KEY) : null;
                    return flow
                            .doOnSuccess(r -> {
                                issuanceMetrics.recordSuccess(sample, configId, delivery);
                                // tenant is guaranteed resolved here (requireResolvedTenant already fail-closed
                                // upstream); the blank check is defense-in-depth so a broken context never
                                // fabricates a trace attributed to a default tenant (AC-05/ES-02).
                                if (tenant != null && !tenant.isBlank()) {
                                    auditDeliveryBestEffort(tenant, processId, r != null ? r.deliveryResults() : null);
                                }
                            })
                            .doOnError(e -> {
                                issuanceMetrics.recordError(sample, configId, delivery);
                                log.error(
                                        "ProcessId: {} - Credential issuance failed for credentialConfigurationId={} delivery={}",
                                        processId, configId, delivery, e);
                                if (tenant != null && !tenant.isBlank()) {
                                    auditDeliveryFailureBestEffort(tenant, processId);
                                }
                            });
                });
    }

    /** Early guard (AC-05/ES-02): fails closed before anything is validated, built or delivered. */
    private Mono<Void> requireResolvedTenant() {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.hasKey(TENANT_DOMAIN_CONTEXT_KEY) ? ctx.get(TENANT_DOMAIN_CONTEXT_KEY) : null;
            if (tenant == null || tenant.isBlank()) {
                return Mono.error(new TenantNotResolvedException(
                        "Cannot process credential issuance without a resolved tenant"));
            }
            return Mono.empty();
        });
    }

    /** Best-effort (ES-03/ES-04): a broken audit channel never reverts an already-completed delivery. */
    private void auditDeliveryBestEffort(String tenant, String processId, List<DeliveryResult> results) {
        try {
            Set<DeliveryResult> resultSet = (results == null || results.isEmpty())
                    ? Set.of(DeliveryResult.failed("unknown", "indeterminate_result"))
                    : Set.copyOf(results);
            auditService.auditDelivery(DeliveryTrace.of(tenant, processId, resultSet));
        } catch (RuntimeException e) {
            log.warn("ProcessId: {} - Failed to build/emit delivery audit trace", processId, e);
        }
    }

    /** Best-effort (ES-03/ES-04). Failure path has no per-mode result (ES-01: indeterminate). */
    private void auditDeliveryFailureBestEffort(String tenant, String processId) {
        try {
            auditService.auditDelivery(DeliveryTrace.of(tenant, processId,
                    Set.of(DeliveryResult.failed("unknown", "indeterminate_result"))));
        } catch (RuntimeException e) {
            log.warn("ProcessId: {} - Failed to build/emit delivery audit trace", processId, e);
        }
    }

    @Override
    @Observed(name = "issuance.execute-bootstrap", contextualName = "issuance-execute-bootstrap")
    public Mono<IssuanceResponse> issueCredentialWithoutAuthorization(
            String processId,
            IssuanceRequest request,
            String token,
            String publicIssuerBaseUrl,
            String publicWalletBaseUrl) {

        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;
        String safeDelivery = keepOnlyOid4vciDeliveryModes(delivery);

        return validateRequest(request, null)
                .then(Mono.defer(() -> payloadSchemaValidator.validate(request.credentialConfigurationId(), request.payload())))
                .then(Mono.defer(() -> performIssuanceFlow(processId, request, token, publicIssuerBaseUrl, publicWalletBaseUrl, safeDelivery)));
    }

    private Mono<Void> validateRequest(IssuanceRequest request, String idToken) {
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(request.credentialConfigurationId());
        if (profile == null) {
            return Mono.error(new CredentialTypeUnsupportedException(
                    "Unknown credential_configuration_id: " + request.credentialConfigurationId()));
        }
        if (requiresIdToken(profile) && idToken == null) {
            return Mono.error(new MissingIdTokenHeaderException(
                    "Missing required ID Token header for VerifiableCertification issuance."));
        }
        return Mono.empty();
    }

    private Mono<IssuanceResponse> performIssuanceFlow(String processId, IssuanceRequest request, String idToken,
                                                        String publicIssuerBaseUrl, String publicWalletBaseUrl, String delivery) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);

        return resolveAndValidateDeliveryModes(configId, profile, delivery)
                .flatMap(modes -> {
                    boolean hasDirect = modes.stream().anyMatch(DeliveryMode::isDirect);
                    Map<String, Object> cnf = (hasDirect && profile.cnfRequired())
                            ? HolderKey.fromJson(request.holderKey()).cnf() : null;
                    return executeIssuanceForModes(processId, request, idToken,
                            publicIssuerBaseUrl, publicWalletBaseUrl, delivery, modes, cnf);
                });
    }

    /**
     * Early guard (ES-01 / AC-05): normalizes the declared delivery modes and validates their eligibility
     * before anything is signed, dispatched or persisted.
     *
     * <p>Eligibility is read per tenant from {@code issuer.delivery.modes.{credentialConfigurationId}}
     * (same key managed by the TenantAdmin-facing {@code DeliveryConfigController}, EUD-169).
     * When the tenant has no configuration, a safe default derived from {@code cnfRequired()} applies:
     * credential types requiring cryptographic holder binding are not eligible for direct delivery
     * by default (they resolve to {@code email,ui}).
     *
     * <p>Since EUD-168 that exclusion is a <em>default</em>, not a hard rule: a tenant admin may
     * explicitly enable {@code direct} for a {@code cnfRequired} credential type, because the direct
     * path can now carry the cryptographic holder binding via a holder key supplied in the request
     * (validated fail-fast in {@link #performIssuanceFlow}, before any delivery leg runs).
     * Eligibility here decides policy
     * (config) and returns {@link DeliveryModeNotEligibleException} when a mode is not eligible; the
     * presence and shape of the holder key is a separate, request-level check enforced later.
     */
    private Mono<Set<DeliveryMode>> resolveAndValidateDeliveryModes(
            String configId, CredentialProfile profile, String delivery) {

        final Set<DeliveryMode> modes;
        try {
            modes = DeliveryMode.parse(delivery);
        } catch (IllegalArgumentException ex) {
            return Mono.error(new InvalidDeliveryModeException(ex.getMessage()));
        }

        String defaultEligible = profile.cnfRequired() ? "email,ui" : "direct,email,ui";
        return tenantConfigService.getStringOrDefault(DELIVERY_MODES_CONFIG_PREFIX + configId, defaultEligible)
                .map(csv -> Arrays.stream(csv.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet()))
                .flatMap(eligibleValues -> {
                    for (DeliveryMode mode : modes) {
                        if (!eligibleValues.contains(mode.value)) {
                            return Mono.error(new DeliveryModeNotEligibleException(
                                    "Delivery mode '" + mode.value + "' is not eligible for credential type: "
                                            + configId));
                        }
                    }
                    return Mono.just(modes);
                });
    }

    private Mono<IssuanceResponse> executeIssuanceForModes(String processId, IssuanceRequest request, String idToken,
                                                            String publicIssuerBaseUrl, String publicWalletBaseUrl,
                                                            String delivery, Set<DeliveryMode> modes,
                                                            Map<String, Object> cnf) {

        boolean hasDirect  = modes.stream().anyMatch(DeliveryMode::isDirect);
        boolean hasOid4vci = modes.stream().anyMatch(m -> m.isOid4vci);
        String oid4vciDelivery = extractOid4vciDelivery(modes);

        Mono<DirectDeliveryOutcome> directOutcome = hasDirect
                ? performDirectIssuance(processId, request, idToken, publicIssuerBaseUrl, delivery, cnf)
                .map(r -> new DirectDeliveryOutcome(r.signedCredential(),
                        DeliveryResult.delivered(DeliveryMode.DIRECT.value)))
                .doOnSuccess(outcome -> {
                    if (outcome != null) {
                        credentialIssuedLogger.logIssued(request.credentialConfigurationId());
                    }
                })
                .doOnError(e -> {
                    credentialIssuedLogger.logFailed(request.credentialConfigurationId(), e);
                    log.error(
                            "ProcessId: {} - Direct issuance failed for credentialConfigurationId={} delivery={}",
                            processId,
                            request.credentialConfigurationId(),
                            delivery,
                            e
                    );
                })
                : Mono.just(DirectDeliveryOutcome.empty());

        Mono<WalletDeliveryOutcome> walletOutcome = hasOid4vci
                ? performOid4VciIssuanceResilient(processId, request, publicIssuerBaseUrl, publicWalletBaseUrl, oid4vciDelivery)
                : Mono.just(WalletDeliveryOutcome.empty());

        return Mono.zip(directOutcome, walletOutcome)
                .map(tuple -> assembleResponse(tuple.getT1(), tuple.getT2()));
    }

    private Mono<WalletDeliveryOutcome> performOid4VciIssuanceResilient(
            String processId, IssuanceRequest request,
            String publicIssuerBaseUrl, String publicWalletBaseUrl, String oid4vciDelivery) {

        return performOid4VciIssuance(processId, request, publicIssuerBaseUrl, publicWalletBaseUrl, oid4vciDelivery)
                .map(r -> WalletDeliveryOutcome.success(r.credentialOfferUri(), oid4vciDelivery))
                .timeout(Duration.ofSeconds(issuanceProperties.hybridWalletTimeoutSeconds()))
                .onErrorResume(ex -> {
                    log.warn("ProcessId: {} - Wallet delivery failed (isolated): {}", processId, ex.toString());
                    return Mono.just(WalletDeliveryOutcome.failed(oid4vciDelivery, resolveWalletErrorDetail(ex)));
                });
    }

    private String resolveWalletErrorDetail(Throwable ex) {
        if (ex instanceof TimeoutException) {
            return "Wallet delivery timed out";
        }
        return ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();
    }

    private IssuanceResponse assembleResponse(DirectDeliveryOutcome direct, WalletDeliveryOutcome wallet) {
        List<DeliveryResult> results = new ArrayList<>();
        if (direct.deliveryResult() != null) {
            results.add(direct.deliveryResult());
        }
        results.addAll(wallet.deliveryResults());

        return IssuanceResponse.builder()
                .signedCredential(direct.signedCredential())
                .credentialOfferUri(wallet.credentialOfferUri())
                .deliveryResults(results.isEmpty() ? null : results)
                .build();
    }

    /** Internal outcome of the direct path (not exposed in the API). */
    private record DirectDeliveryOutcome(String signedCredential, DeliveryResult deliveryResult) {
        static DirectDeliveryOutcome empty() {
            return new DirectDeliveryOutcome(null, null);
        }
    }

    /** Internal outcome of the wallet path — supports multi-mode CSV (email,ui). */
    private record WalletDeliveryOutcome(String credentialOfferUri, List<DeliveryResult> deliveryResults) {
        static WalletDeliveryOutcome empty() {
            return new WalletDeliveryOutcome(null, List.of());
        }

        static WalletDeliveryOutcome success(String uri, String oid4vciDelivery) {
            List<DeliveryResult> results = Arrays.stream(oid4vciDelivery.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(DeliveryResult::dispatched)
                    .toList();
            return new WalletDeliveryOutcome(uri, results);
        }

        static WalletDeliveryOutcome failed(String oid4vciDelivery, String error) {
            List<DeliveryResult> results = Arrays.stream(oid4vciDelivery.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(mode -> DeliveryResult.failed(mode, error))
                    .toList();
            return new WalletDeliveryOutcome(null, results);
        }
    }

    private Mono<IssuanceResponse> performDirectIssuance(String processId, IssuanceRequest request, String token,
                                                          String publicIssuerBaseUrl, String originalDelivery,
                                                          Map<String, Object> cnf) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String credentialFormat = profile.format() != null ? profile.format() : JWT_VC_JSON;
        StatusListFormat statusFormat = DC_SD_JWT.equals(credentialFormat)
                ? StatusListFormat.TOKEN_JWT : StatusListFormat.BITSTRING_VC;

        UUID issuanceId = UUID.randomUUID();

        return genericCredentialBuilder.buildCredential(profile, request.payload())
                .flatMap(buildResult ->
                        genericCredentialBuilder.bindIssuer(profile, buildResult.credentialDataSet(),
                                        issuanceId.toString(), request.email())
                                .flatMap(enrichedDataSet ->
                                        statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, statusFormat,
                                                        issuanceId.toString(), token, publicIssuerBaseUrl)
                                                .map(entry -> {
                                                    CredentialStatus credStatus = CredentialStatus.fromStatusListEntry(entry);
                                                    return genericCredentialBuilder.injectCredentialStatus(
                                                            enrichedDataSet, credStatus, credentialFormat);
                                                })
                                )
                                .flatMap(enrichedWithStatus ->
                                        credentialSignerWorkflow.signCredential(
                                                        token, enrichedWithStatus, configId, credentialFormat,
                                                        cnf, issuanceId.toString(), request.email())
                                                .flatMap(signedCredential -> {
                                                    CredentialStatusEnum finalStatus = determineFinalStatus(buildResult);
                                                    Issuance issuance = buildDirectIssuanceEntity(
                                                            issuanceId, configId, credentialFormat,
                                                            buildResult, enrichedWithStatus,
                                                            request.email(), originalDelivery, finalStatus);
                                                    return issuanceService.saveIssuance(issuance)
                                                            .doOnSuccess(saved -> log.debug(
                                                                    "ProcessId: {} - Direct issuance saved: {} status={}",
                                                                    processId, saved.getIssuanceId(), finalStatus))
                                                            .thenReturn(IssuanceResponse.builder()
                                                                    .signedCredential(signedCredential)
                                                                    .build());
                                                })
                                )
                );
    }

    private Mono<IssuanceResponse> performOid4VciIssuance(String processId, IssuanceRequest request,
                                                           String publicIssuerBaseUrl, String publicWalletBaseUrl,
                                                           String oid4vciDelivery) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String grantType = request.grantType() != null ? request.grantType() : AUTHORIZATION_CODE;

        return genericCredentialBuilder.buildCredential(profile, request.payload())
                .flatMap(buildResult -> {
                    UUID issuanceId = UUID.randomUUID();
                    Issuance issuance = buildIssuanceEntity(issuanceId, configId, profile.format(),
                            buildResult, request.email(), oid4vciDelivery, grantType);

                    return issuanceService.saveIssuance(issuance)
                            .doOnSuccess(saved -> log.debug("ProcessId: {} - Created OID4VCI issuance: {}", processId, saved.getIssuanceId()))
                            .flatMap(saved -> credentialOfferService.createAndDeliverCredentialOffer(
                                            saved.getIssuanceId().toString(), configId, grantType, request.email(),
                                            oid4vciDelivery, saved.getCredentialOfferRefreshToken(),
                                            publicIssuerBaseUrl, publicWalletBaseUrl)
                                    .map(offerResult -> IssuanceResponse.builder()
                                            .credentialOfferUri(offerResult.credentialOfferUri())
                                            .build())
                            );
                });
    }

    private Issuance buildIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                          CredentialBuildResult buildResult, String email, String delivery,
                                          String grantType) {
        return Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialDataSet(buildResult.credentialDataSet())
                .credentialFormat(credentialFormat)
                .organizationIdentifier(buildResult.organizationIdentifier())
                .credentialType(credentialType)
                .subject(buildResult.subject())
                .validFrom(buildResult.validFrom())
                .validUntil(buildResult.validUntil())
                .email(email)
                .delivery(delivery)
                .grantType(grantType)
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .build();
    }

    private Issuance buildDirectIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                                CredentialBuildResult buildResult, String enrichedDataSet,
                                                String email, String delivery, CredentialStatusEnum status) {
        return Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(status)
                .credentialDataSet(enrichedDataSet)
                .credentialFormat(credentialFormat)
                .organizationIdentifier(buildResult.organizationIdentifier())
                .credentialType(credentialType)
                .subject(buildResult.subject())
                .validFrom(buildResult.validFrom())
                .validUntil(buildResult.validUntil())
                .email(email)
                .delivery(delivery)
                .grantType(AUTHORIZATION_CODE)
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .build();
    }

    private CredentialStatusEnum determineFinalStatus(CredentialBuildResult buildResult) {
        if (buildResult.validFrom() != null
                && buildResult.validFrom().toInstant().isAfter(Instant.now())) {
            return CredentialStatusEnum.ISSUED;
        }
        return CredentialStatusEnum.VALID;
    }

    private String extractOid4vciDelivery(Set<DeliveryMode> modes) {
        return modes.stream()
                .filter(m -> m.isOid4vci)
                .map(m -> m.value)
                .collect(Collectors.joining(","));
    }

    private String keepOnlyOid4vciDeliveryModes(String delivery) {
        String oid4vciDelivery = DeliveryMode.parse(delivery).stream()
                .filter(m -> m.isOid4vci)
                .map(m -> m.value)
                .collect(Collectors.joining(","));

        if (oid4vciDelivery.isBlank()) {
            throw new IllegalArgumentException(
                    "Bootstrap issuance requires at least one OID4VCI delivery mode."
            );
        }

        return oid4vciDelivery;
    }

    private boolean requiresIdToken(CredentialProfile profile) {
        return profile.issuancePolicy() != null
                && profile.issuancePolicy().rules() != null
                && profile.issuancePolicy().rules().contains("RequireCertificationIssuance");
    }
}
