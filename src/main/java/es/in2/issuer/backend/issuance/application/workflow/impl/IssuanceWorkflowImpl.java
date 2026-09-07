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
import es.in2.issuer.backend.shared.domain.model.dto.credential.HolderCnfJson;
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
import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;
import es.in2.issuer.backend.issuance.domain.model.HolderKey;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.HolderBindingExemption;
import es.in2.issuer.backend.shared.domain.service.SchemaDeliveryCeiling;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
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
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class IssuanceWorkflowImpl implements IssuanceWorkflow {

    private static final String DEFAULT_GRANT_TYPE = "authorization_code";
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
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;
    private final HolderDidFallbackAuditor holderDidFallbackAuditor;

    @Override
    @Observed(name = "issuance.issue-credential", contextualName = "issuance-issue-credential")
    public Mono<IssuanceResponse> issueCredential(
            String processId,
            IssuanceRequest request,
            String idToken,
            String bearerToken,
            String publicIssuerBaseUrl,
            String publicWalletBaseUrl) {

        var sample = issuanceMetrics.startTimer();
        String configId = request.credentialConfigurationId();
        String delivery = request.delivery() != null ? request.delivery() : DEFAULT_DELIVERY;

        return requireResolvedTenant()
                .then(Mono.defer(() -> validateRequest(request, idToken)))
                .then(Mono.defer(() -> payloadSchemaValidator.validate(configId, request.payload())))
                .then(Mono.defer(() -> issuancePdpService.authorize(configId, request.payload(), idToken)))
                .then(Mono.defer(() -> performIssuanceFlow(processId, request, bearerToken, publicIssuerBaseUrl, publicWalletBaseUrl, delivery)))
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

    /**
     * @param bearerToken the caller's token, used by the direct mode alone: it signs the credential and
     *                    may have to sign a new status list inside this same request. Not the
     *                    {@code X-Id-Token}, which is an optional identity assertion for the PDP and is
     *                    absent on every profile that does not require it (EUD-168).
     */
    private Mono<IssuanceResponse> performIssuanceFlow(String processId, IssuanceRequest request, String bearerToken,
                                                        String publicIssuerBaseUrl, String publicWalletBaseUrl, String delivery) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);

        return resolveAndValidateDeliveryModes(configId, delivery)
                .flatMap(modes -> {
                    // Scoped exception (AD-8): the machine LEARCredential types keep a cnf even though
                    // their schema declares no binding, sourced from the request holder_key. Not gated on
                    // the direct mode -- with proof_types_supported gone no key proof arrives through the
                    // wallet flow either, so the request is the only source of a holder key there is.
                    //
                    // Gated on !profile.requiresHolderBinding() as well as the id prefix (F4/S4): the
                    // prefix match alone would also fire for a future profile of the same family that
                    // recovers proof_types_supported, which would make holder_key required again for a
                    // type the schema now binds through a real key proof -- exactly the invariant AD-9
                    // exists to protect.
                    // HolderKey.fromJson requires the jwk member (code-review F1a/D3): kid/x5c carry
                    // no key material this path -- no wallet, no OID4VCI proof -- could ever verify.
                    Map<String, Object> cnf = HolderBindingExemption.isExempt(configId) && !profile.requiresHolderBinding()
                            ? HolderKey.fromJson(request.holderKey()).cnf() : null;
                    return executeIssuanceForModes(processId, request, bearerToken,
                            new BaseUrls(publicIssuerBaseUrl, publicWalletBaseUrl), delivery, modes, cnf);
                });
    }

    /**
     * Early guard: normalizes the declared delivery modes and validates their eligibility before
     * anything is signed, dispatched or persisted.
     *
     * <p>Eligibility resolves as {@code tenant configuration ∩ schema ceiling}, with the ceiling as the
     * default when no configuration exists. The ceiling ({@link SchemaDeliveryCeiling}) derives from
     * {@code proof_types_supported}, the single signal of holder binding (ADR-110): direct delivery has
     * no wallet and therefore no proof-of-possession, so a bound type cannot be delivered that way.
     *
     * <p>The intersection is what makes this a ceiling rather than a default. Tenant configuration can
     * only narrow it -- a stored configuration listing {@code direct} for a bound type, written before
     * this rule existed, is intersected away instead of honoured.
     *
     * <p>This decides mode eligibility only. Whether a holder key is present and well-formed is a
     * separate, request-level check made right after in {@link #performIssuanceFlow}; keeping that order
     * means an ineligible mode is reported as such even when a valid holder key was supplied.
     */
    private Mono<Set<DeliveryMode>> resolveAndValidateDeliveryModes(
            String configId, String delivery) {

        final Set<DeliveryMode> modes;
        try {
            modes = DeliveryMode.parse(delivery);
        } catch (IllegalArgumentException ex) {
            return Mono.error(new InvalidDeliveryModeException(ex.getMessage()));
        }

        // The schema ceiling is checked first and unconditionally: no stored configuration can widen it,
        // so a configuration predating this rule cannot resurrect direct delivery for a bound type.
        try {
            schemaDeliveryCeiling.validateWithinCeiling(configId, modes);
        } catch (DeliveryModeNotEligibleException ex) {
            return Mono.error(ex);
        }

        Set<DeliveryMode> ceiling = schemaDeliveryCeiling.resolveEligibleModes(configId);
        String defaultEligible = DeliveryMode.toCanonicalCsv(ceiling);
        return tenantConfigService.getStringOrDefault(DELIVERY_MODES_CONFIG_PREFIX + configId, defaultEligible)
                .map(csv -> Arrays.stream(csv.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toSet()))
                .flatMap(eligibleValues -> {
                    // The effective set is what the error message must report: the schema ceiling alone
                    // overstates what is actually available whenever tenant configuration narrows it
                    // further, which would mislead the caller about what to retry with.
                    Set<DeliveryMode> effectiveEligible = ceiling.stream()
                            .filter(mode -> eligibleValues.contains(mode.value))
                            .collect(Collectors.toCollection(() -> EnumSet.noneOf(DeliveryMode.class)));
                    String effectiveEligibleCsv = effectiveEligible.isEmpty()
                            ? "none"
                            : DeliveryMode.toCanonicalCsv(effectiveEligible);
                    for (DeliveryMode mode : modes) {
                        // Tenant configuration narrows the ceiling, never widens it: a mode must clear
                        // both. The ceiling was already checked above, so this can only reject a mode the
                        // tenant itself has disabled.
                        if (!eligibleValues.contains(mode.value) || !ceiling.contains(mode)) {
                            return Mono.error(new DeliveryModeNotEligibleException(
                                    "Delivery mode '" + mode.value + "' is not eligible for credential type '"
                                            + configId + "'. Eligible modes: "
                                            + effectiveEligibleCsv));
                        }
                    }
                    return Mono.just(modes);
                });
    }

    private Mono<IssuanceResponse> executeIssuanceForModes(String processId, IssuanceRequest request, String bearerToken,
                                                            BaseUrls baseUrls, String delivery, Set<DeliveryMode> modes,
                                                            Map<String, Object> cnf) {

        boolean hasDirect  = modes.stream().anyMatch(DeliveryMode::isDirect);
        boolean hasOid4vci = modes.stream().anyMatch(m -> m.isOid4vci);
        String oid4vciDelivery = extractOid4vciDelivery(modes);

        Mono<DirectDeliveryOutcome> directOutcome = hasDirect
                ? performDirectIssuance(processId, request, bearerToken, baseUrls.issuerBaseUrl(), delivery, cnf)
                .map(r -> new DirectDeliveryOutcome(r.signedCredential(),
                        DeliveryResult.delivered(DeliveryMode.DIRECT.value), null))
                .doOnSuccess(outcome -> {
                    if (outcome != null) {
                        credentialIssuedLogger.logIssued(request.credentialConfigurationId());
                    }
                })
                // Isolated the same way the wallet leg already is (FR-11): a direct failure used to
                // abort the whole response, discarding the per-mode results and the credential offer
                // URI of a wallet leg that had already dispatched. The error is carried, not lost --
                // assembleOutcome re-raises it when nothing else was delivered.
                .onErrorResume(e -> resolveDirectFailureOutcome(processId, request, delivery, e))
                : Mono.just(DirectDeliveryOutcome.empty());

        Mono<WalletDeliveryOutcome> walletOutcome = hasOid4vci
                ? performOid4VciIssuanceResilient(processId, request, baseUrls.issuerBaseUrl(), baseUrls.walletBaseUrl(),
                        oid4vciDelivery, cnf)
                : Mono.just(WalletDeliveryOutcome.empty());

        return Mono.zip(directOutcome, walletOutcome)
                .flatMap(tuple -> assembleOutcome(tuple.getT1(), tuple.getT2()));
    }

    private Mono<DirectDeliveryOutcome> resolveDirectFailureOutcome(String processId, IssuanceRequest request,
                                                                      String delivery, Throwable e) {
        credentialIssuedLogger.logFailed(request.credentialConfigurationId(), e);
        log.error(
                "ProcessId: {} - Direct issuance failed for credentialConfigurationId={} delivery={}",
                processId,
                request.credentialConfigurationId(),
                delivery,
                e
        );
        // The stage tag (DeliveryStageFailure) exists only to pick a safe code; when nothing else was
        // delivered, assembleOutcome re-raises the original exception so it keeps being handled (and
        // typed) exactly as it was before F3/W1.
        Throwable original = e instanceof DeliveryStageFailure dsf ? dsf.getCause() : e;
        return Mono.just(DirectDeliveryOutcome.failed(resolveErrorDetail(e), original));
    }

    /**
     * A mode that completed is reported as completed even when a sibling mode failed (FR-11) -- but a
     * request where <em>nothing</em> was delivered is not a partial success, and answering it with a
     * body full of failures would hide the cause behind a 5xx with no problem detail. So the direct
     * error is re-raised in that case and handled as any other error, and only a genuine partial
     * outcome comes back as a response: per-mode results, the signed credential if there is one, and
     * the credential offer URI if a mode that produces one completed.
     */
    private Mono<IssuanceResponse> assembleOutcome(DirectDeliveryOutcome direct, WalletDeliveryOutcome wallet) {
        IssuanceResponse response = assembleResponse(direct, wallet);
        if (direct.error() != null && !hasAnyCompletedMode(response)) {
            return Mono.error(direct.error());
        }
        return Mono.just(response);
    }

    private boolean hasAnyCompletedMode(IssuanceResponse response) {
        List<DeliveryResult> results = response.deliveryResults();
        return results != null && results.stream()
                .anyMatch(r -> r.status() != DeliveryResult.DeliveryOutcome.FAILED);
    }

    private Mono<WalletDeliveryOutcome> performOid4VciIssuanceResilient(
            String processId, IssuanceRequest request,
            String publicIssuerBaseUrl, String publicWalletBaseUrl, String oid4vciDelivery,
            Map<String, Object> cnf) {

        return performOid4VciIssuance(processId, request, publicIssuerBaseUrl, publicWalletBaseUrl, oid4vciDelivery, cnf)
                .map(r -> WalletDeliveryOutcome.success(r.credentialOfferUri(), oid4vciDelivery, r.emailError()))
                .timeout(Duration.ofSeconds(issuanceProperties.hybridWalletTimeoutSeconds()))
                .onErrorResume(ex -> {
                    log.warn("ProcessId: {} - Wallet delivery failed (isolated): {}", processId, ex.toString());
                    return Mono.just(WalletDeliveryOutcome.failed(oid4vciDelivery, resolveWalletErrorDetail(ex)));
                });
    }

    private String resolveWalletErrorDetail(Throwable ex) {
        if (ex instanceof TimeoutException) {
            return DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT.value();
        }
        return resolveErrorDetail(ex);
    }

    /**
     * Closed set of codes, never {@code Throwable.getMessage()} (F3/W1): a raw message from the
     * signing provider, the status list or an R2DBC failure can carry an internal URL or the tenant's
     * schema name. The direct leg tags which stage failed via {@link DeliveryStageFailure}; anything
     * else (the wallet leg's own failures, or an untagged direct-leg stage) falls back to the generic
     * code. The full detail is not lost -- it is already in the log line the caller emitted.
     */
    private String resolveErrorDetail(Throwable ex) {
        if (ex instanceof DeliveryStageFailure stageFailure) {
            return stageFailure.code.value();
        }
        return DeliveryErrorCode.DELIVERY_FAILED.value();
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

    /**
     * What the wallet leg produced: the offer URI, and the email failure the offer service reported
     * rather than threw. Kept apart from {@link IssuanceResponse} because a reported email failure is
     * per-mode detail, not a field of the API response.
     */
    private record Oid4VciLegResult(String credentialOfferUri, String emailError) {}

    /** The issuer/wallet public base URL pair that every issuance leg needs, grouped to stay within the 7-parameter limit. */
    private record BaseUrls(String issuerBaseUrl, String walletBaseUrl) {}

    /**
     * Internal outcome of the direct path (not exposed in the API). {@code error} is the failure the
     * leg was isolated from, kept so it can be re-raised when no other mode delivered.
     */
    private record DirectDeliveryOutcome(String signedCredential, DeliveryResult deliveryResult, Throwable error) {
        static DirectDeliveryOutcome empty() {
            return new DirectDeliveryOutcome(null, null, null);
        }

        static DirectDeliveryOutcome failed(String detail, Throwable error) {
            return new DirectDeliveryOutcome(null, DeliveryResult.failed(DeliveryMode.DIRECT.value, detail), error);
        }
    }

    /** Internal outcome of the wallet path — supports multi-mode CSV (email,ui). */
    private record WalletDeliveryOutcome(String credentialOfferUri, List<DeliveryResult> deliveryResults) {
        static WalletDeliveryOutcome empty() {
            return new WalletDeliveryOutcome(null, List.of());
        }

        /**
         * The email and the QR/URI are separate modes of one offer (FR-11): a bounced email is reported
         * on the {@code email} mode alone and leaves {@code ui} dispatched, with its URI in the
         * response. Before this, both modes were reported failed and the URI was dropped.
         */
        static WalletDeliveryOutcome success(String uri, String oid4vciDelivery, String emailError) {
            List<DeliveryResult> results = Arrays.stream(oid4vciDelivery.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(mode -> DeliveryMode.EMAIL.value.equals(mode) && emailError != null
                            ? DeliveryResult.failed(mode, emailError)
                            : DeliveryResult.dispatched(mode))
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

    /**
     * {@code cnf} is only ever non-null here for an AD-8 exempt type (F4), and only ever jwk-shaped for
     * one (kid/x5c never reach this leg -- see {@link es.in2.issuer.backend.issuance.domain.model.HolderKey}).
     * Deriving the did:key from it (delegated to {@link HolderDidFallbackAuditor}, shared with
     * {@link Oid4VciCredentialWorkflowImpl}'s wallet leg) is what lets the direct leg enforce the same
     * cnf-mandatee.id invariant the wallet leg already does from a key proof (F2).
     */
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
                                .map(enrichedDataSet -> {
                                    // AD-8 exempt types take no key proof (F2, S2): derive the holder DID
                                    // from the cnf.jwk the exemption already resolved, so cnf and
                                    // mandatee.id agree on the same key pair -- the same invariant the
                                    // wallet leg enforces via Oid4VciCredentialWorkflowImpl.
                                    String holderDid = holderDidFallbackAuditor.deriveFromJwkCnf(
                                            processId, issuanceId.toString(), cnf);
                                    return holderDid != null
                                            ? genericCredentialBuilder.bindHolderDid(enrichedDataSet, holderDid)
                                            : enrichedDataSet;
                                })
                                .flatMap(enrichedDataSet ->
                                        statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, statusFormat,
                                                        issuanceId.toString(), token, publicIssuerBaseUrl)
                                                .map(entry -> {
                                                    CredentialStatus credStatus = CredentialStatus.fromStatusListEntry(entry);
                                                    return genericCredentialBuilder.injectCredentialStatus(
                                                            enrichedDataSet, credStatus, credentialFormat);
                                                })
                                                .onErrorMap(DeliveryStageFailure.wrapUnlessAlready(DeliveryErrorCode.STATUS_LIST_UNAVAILABLE))
                                )
                                .flatMap(enrichedWithStatus ->
                                        credentialSignerWorkflow.signCredential(
                                                        token, enrichedWithStatus, configId, credentialFormat,
                                                        cnf, issuanceId.toString(), request.email())
                                                .onErrorMap(DeliveryStageFailure.wrapUnlessAlready(DeliveryErrorCode.SIGNING_FAILED))
                                                .flatMap(signedCredential -> {
                                                    CredentialStatusEnum finalStatus = determineFinalStatus(buildResult);
                                                    Issuance issuance = buildDirectIssuanceEntity(
                                                            issuanceId, configId, credentialFormat,
                                                            buildResult, enrichedWithStatus,
                                                            request.email(), originalDelivery, finalStatus, cnf);
                                                    return issuanceService.saveIssuance(issuance)
                                                            .doOnSuccess(saved -> log.debug(
                                                                    "ProcessId: {} - Direct issuance saved: {} status={}",
                                                                    processId, saved.getIssuanceId(), finalStatus))
                                                            .onErrorMap(DeliveryStageFailure.wrapUnlessAlready(DeliveryErrorCode.PERSISTENCE_FAILED))
                                                            .thenReturn(IssuanceResponse.builder()
                                                                    .signedCredential(signedCredential)
                                                                    .build());
                                                })
                                )
                );
    }

    /**
     * Tags which stage of the direct leg failed, so {@link #resolveErrorDetail} can answer with a
     * closed code instead of {@code Throwable.getMessage()} (F3/W1) -- a {@code WebClientResponseException}
     * from the signing provider or the status list carries its method/URL, and an R2DBC failure carries
     * table/column/schema names (the schema name <em>is</em> the tenant). The original exception is kept
     * as the cause; it is what gets logged.
     */
    private static final class DeliveryStageFailure extends RuntimeException {
        private final DeliveryErrorCode code;

        private DeliveryStageFailure(DeliveryErrorCode code, Throwable cause) {
            super(cause);
            this.code = code;
        }

        static Function<Throwable, Throwable> wrapUnlessAlready(DeliveryErrorCode code) {
            return ex -> ex instanceof DeliveryStageFailure ? ex : new DeliveryStageFailure(code, ex);
        }
    }

    private Mono<Oid4VciLegResult> performOid4VciIssuance(String processId, IssuanceRequest request,
                                                           String publicIssuerBaseUrl, String publicWalletBaseUrl,
                                                           String oid4vciDelivery, Map<String, Object> cnf) {
        String configId = request.credentialConfigurationId();
        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(configId);
        String grantType = request.grantType() != null ? request.grantType() : DEFAULT_GRANT_TYPE;

        return genericCredentialBuilder.buildCredential(profile, request.payload())
                .flatMap(buildResult -> {
                    UUID issuanceId = UUID.randomUUID();
                    // The cnf travels on the row, not in this request: the wallet legs sign in a
                    // later request to the Credential Endpoint, where the holder key of an exempt
                    // type has no other source (AD-8).
                    Issuance issuance = buildIssuanceEntity(issuanceId, configId, profile.format(),
                            buildResult, request.email(), oid4vciDelivery, cnf);

                    return issuanceService.saveIssuance(issuance)
                            .doOnSuccess(saved -> log.debug("ProcessId: {} - Created OID4VCI issuance: {}", processId, saved.getIssuanceId()))
                            .flatMap(saved -> credentialOfferService.createAndDeliverCredentialOffer(
                                            saved.getIssuanceId().toString(), configId, grantType, request.email(),
                                            oid4vciDelivery, saved.getCredentialOfferRefreshToken(),
                                            publicIssuerBaseUrl, publicWalletBaseUrl)
                                    .map(offerResult -> new Oid4VciLegResult(
                                            offerResult.credentialOfferUri(), offerResult.emailError()))
                            );
                });
    }

    private Issuance buildIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                          CredentialBuildResult buildResult, String email, String delivery,
                                          Map<String, Object> cnf) {
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
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .holderCnf(HolderCnfJson.write(cnf))
                .build();
    }

    private Issuance buildDirectIssuanceEntity(UUID issuanceId, String credentialType, String credentialFormat,
                                                CredentialBuildResult buildResult, String enrichedDataSet,
                                                String email, String delivery, CredentialStatusEnum status,
                                                Map<String, Object> cnf) {
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
                .credentialOfferRefreshToken(UUID.randomUUID().toString())
                .holderCnf(HolderCnfJson.write(cnf))
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
