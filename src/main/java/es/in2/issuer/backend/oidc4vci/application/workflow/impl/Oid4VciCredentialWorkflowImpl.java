package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.exception.*;
import es.in2.issuer.backend.shared.domain.model.dto.*;

import com.nimbusds.jose.JWSObject;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import es.in2.issuer.backend.oidc4vci.application.workflow.Oid4VciCredentialWorkflow;
import es.in2.issuer.backend.oidc4vci.domain.exception.CredentialRequestDeniedException;
import es.in2.issuer.backend.oidc4vci.domain.exception.UnknownCredentialIdentifierException;
import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.CredentialRequest;
import es.in2.issuer.backend.oidc4vci.domain.model.dto.CredentialResponse;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.HolderCnfJson;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.HolderBindingExemption;
import es.in2.issuer.backend.shared.domain.model.entities.BindingInfo;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuedLogger;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.service.HolderDidFallbackAuditor;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.ProofValidationService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import es.in2.issuer.backend.shared.domain.util.DidKeyDerivation;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.naming.ConfigurationException;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Slf4j
@Service
public class Oid4VciCredentialWorkflowImpl implements Oid4VciCredentialWorkflow {

    private final CredentialSignerWorkflow credentialSignerWorkflow;
    private final ProofValidationService proofValidationService;
    private final IssuanceService issuanceService;
    private final CredentialIssuerMetadataService credentialIssuerMetadataService;
    private final GenericCredentialBuilder genericCredentialBuilder;
    private final CredentialProfileRegistry credentialProfileRegistry;
    private final StatusListWorkflow statusListWorkflow;
    private final TransientStore<String> enrichmentCacheStore;
    private final TransientStore<String> notificationCacheStore;
    private final CredentialIssuedLogger credentialIssuedLogger;
    private final HolderDidFallbackAuditor holderDidFallbackAuditor;
    private final AuditService auditService;

    public Oid4VciCredentialWorkflowImpl(
            CredentialSignerWorkflow credentialSignerWorkflow,
            ProofValidationService proofValidationService,
            IssuanceService issuanceService,
            CredentialIssuerMetadataService credentialIssuerMetadataService,
            GenericCredentialBuilder genericCredentialBuilder,
            CredentialProfileRegistry credentialProfileRegistry,
            StatusListWorkflow statusListWorkflow,
            @Qualifier("enrichmentCacheStore") TransientStore<String> enrichmentCacheStore,
            @Qualifier("notificationCacheStore") TransientStore<String> notificationCacheStore,
            CredentialIssuedLogger credentialIssuedLogger,
            HolderDidFallbackAuditor holderDidFallbackAuditor,
            AuditService auditService
    ) {
        this.credentialSignerWorkflow = credentialSignerWorkflow;
        this.proofValidationService = proofValidationService;
        this.issuanceService = issuanceService;
        this.credentialIssuerMetadataService = credentialIssuerMetadataService;
        this.genericCredentialBuilder = genericCredentialBuilder;
        this.credentialProfileRegistry = credentialProfileRegistry;
        this.statusListWorkflow = statusListWorkflow;
        this.enrichmentCacheStore = enrichmentCacheStore;
        this.notificationCacheStore = notificationCacheStore;
        this.credentialIssuedLogger = credentialIssuedLogger;
        this.holderDidFallbackAuditor = holderDidFallbackAuditor;
        this.auditService = auditService;
    }

    /**
     * OID4VCI credential issuance flow:
     * 1. Load issuance (verify DRAFT status)
     * 2. Validate proof if required → extract BindingInfo (cnf)
     * 3. Enrich credential in memory (bind issuer) — NOT persisted to DB
     * 4. Allocate status list entry (revocation) and inject credentialStatus
     * 5. Cache enriched dataSet for later persistence on credential_accepted
     * 6. Sign credential (builds JWT/SD-JWT payload with cnf, signs)
     * 7. Generate notification_id, cache mapping notificationId → issuanceId
     * 8. Return CredentialResponse with signed credential + notification_id
     *
     * Status stays DRAFT until wallet confirms via credential_accepted notification.
     */
    @Override
    @Observed(name = "oid4vci.generate-vc-response", contextualName = "oid4vci-generate-vc-response")
    public Mono<CredentialResponse> createCredentialResponse(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext,
            String publicIssuerBaseUrl) {

        final String issuanceId = accessTokenContext.issuanceId();

        return Mono.defer(() -> {
            AtomicReference<String> configurationId =
                    new AtomicReference<>(knownRequestedConfigurationId(credentialRequest));

            return buildCredentialPipeline(processId, credentialRequest, accessTokenContext, publicIssuerBaseUrl, issuanceId, configurationId)
                    .doOnSuccess(response -> {
                        if (response != null) {
                            credentialIssuedLogger.logIssued(configurationId.get());
                        }
                    })
                    .doOnError(e -> credentialIssuedLogger.logFailed(configurationId.get(), e));
        });
    }

    // Both request-level guards below short-circuit before the Issuance is even loaded; the
    // mismatch check in processIssuance needs the Issuance's own type, so it runs after.
    private Mono<CredentialResponse> buildCredentialPipeline(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext,
            String publicIssuerBaseUrl,
            String issuanceId,
            AtomicReference<String> configurationId) {

        // OID4VCI 1.0 SS8.2: credential_identifier is the alternative addressing mode to
        // credential_configuration_id, used only when the Token Response returned
        // authorization_details with credential_identifiers - this Issuer only implements the
        // scope-based flow and never does, so any credential_identifier a client sends is
        // unrecognized by construction.
        String requestedCredentialIdentifier = credentialRequest != null ? credentialRequest.credentialIdentifier() : null;
        if (hasValue(requestedCredentialIdentifier)) {
            return Mono.error(new UnknownCredentialIdentifierException(
                    "Unknown credential_identifier: " + requestedCredentialIdentifier));
        }

        // A credential_configuration_id that isn't one of ours must be rejected outright, not
        // silently ignored in favor of whatever the Issuance record already says. The
        // knownRequestedConfigurationId helper computed the lookup above purely for logging
        // before this check existed - reuse its result here instead of querying the registry a
        // second time.
        String requestedConfigurationId = credentialRequest != null ? credentialRequest.credentialConfigurationId() : null;
        if (hasValue(requestedConfigurationId) && configurationId.get() == null) {
            return Mono.error(new UnknownCredentialConfigurationException(
                    "Unknown credential_configuration_id: " + requestedConfigurationId));
        }

        return issuanceService.getIssuanceById(issuanceId)
                .switchIfEmpty(Mono.error(new InvalidTokenException("Procedure not found: " + issuanceId)))
                .doOnNext(proc -> setConfigurationId(proc, configurationId))
                .flatMap(proc -> processIssuance(processId, credentialRequest, accessTokenContext, publicIssuerBaseUrl, issuanceId, requestedConfigurationId, proc));
    }

    private Mono<CredentialResponse> processIssuance(
            String processId,
            CredentialRequest credentialRequest,
            AccessTokenContext accessTokenContext,
            String publicIssuerBaseUrl,
            String issuanceId,
            String requestedConfigurationId,
            Issuance proc) {

        if (isMismatchedConfigurationId(requestedConfigurationId, proc)) {
            return Mono.error(new UnknownCredentialConfigurationException(
                    "Unsupported credential_configuration_id for this issuance: " + requestedConfigurationId));
        }
        return validateProcedureState(proc)
                .then(credentialIssuerMetadataService.getCredentialIssuerMetadata(publicIssuerBaseUrl))
                .flatMap(metadata -> {
                    log.info("[{}] Processing credential request: issuanceId={}, type={}, format={}",
                            processId, issuanceId, proc.getCredentialType(), proc.getCredentialFormat());

                    return validateAndDetermineBindingInfo(proc, metadata, credentialRequest)
                            .defaultIfEmpty(new BindingInfo(null, null))
                            .flatMap(bindingInfo -> enrichAndSign(processId, proc, bindingInfo, accessTokenContext.rawToken(), publicIssuerBaseUrl));
                });
    }

    // credential_configuration_id is a valid, registered configuration (the caller already
    // ruled out "unknown") but doesn't match what this Issuance/token was actually authorized
    // for - e.g. requesting PID with a LEAR Employee token. A well-behaved wallet never
    // triggers this: the credential offer service always advertises exactly the Issuance's own
    // credential type in the offer.
    private boolean isMismatchedConfigurationId(String requestedConfigurationId, Issuance proc) {
        return hasValue(requestedConfigurationId)
                && hasValue(proc.getCredentialType())
                && !requestedConfigurationId.equals(proc.getCredentialType());
    }

    private boolean hasValue(String value) {
        return value != null && !value.isBlank();
    }

    private String knownRequestedConfigurationId(CredentialRequest credentialRequest) {
        String requested = credentialRequest != null ? credentialRequest.credentialConfigurationId() : null;
        if (requested == null || requested.isBlank()
                || credentialProfileRegistry.getByConfigurationId(requested) == null) {
            return null;
        }
        return requested;
    }

    private void setConfigurationId(Issuance proc, AtomicReference<String> configurationId) {
        if (proc.getCredentialType() != null && !proc.getCredentialType().isBlank()) {
            configurationId.set(proc.getCredentialType());
        }
    }

    // OID4VCI 1.0 Final §8.3 gives the Credential Endpoint two success codes and no notion of a
    // one-shot access token: while the token lives, a repeated request for the Credential it
    // authorizes has to be served. Restricting issuance to DRAFT made every request after the
    // Wallet's credential_accepted notification fail, because that notification moves the
    // Issuance to ISSUED and then VALID — the OIDF conformance suite hits exactly this
    // (LOG-0302 / LOG-0348, EnsureHttpStatusCodeIsAnyOf 200/202, got 400).
    //
    // Re-issuing is safe: the status list allocation is keyed by issuanceId and returns the
    // index already reserved, and bindIssuer overwrites the issuer field rather than appending,
    // so running it over the dataset persisted at credential_accepted is idempotent.
    private static final Set<CredentialStatusEnum> ISSUABLE_STATUSES =
            EnumSet.of(CredentialStatusEnum.DRAFT, CredentialStatusEnum.ISSUED, CredentialStatusEnum.VALID);

    private Mono<Void> validateProcedureState(Issuance proc) {
        if (!ISSUABLE_STATUSES.contains(proc.getCredentialStatus())) {
            // Withdrawn, revoked, expired or archived: the credential is dead, and no retry can
            // revive it — which is precisely what credential_request_denied means.
            return Mono.error(new CredentialRequestDeniedException(
                    "Issuance is no longer issuable: " + proc.getCredentialStatus()));
        }
        return Mono.empty();
    }

    /**
     * The key proof is the binding whenever one arrives. When none does -- a credential type exempt
     * from ADR-110 declares no {@code proof_types_supported}, so {@code resolveBinding} returns empty
     * and no proof is ever requested (EUD-168 AD-8) -- the holder key persisted with the issuance
     * request is the only source of a cnf left, and the profile still requires one. Reading it here
     * keeps the two sources ordered by strength: cryptographic evidence first, issuer assertion second.
     *
     * <p>Gated on the same condition as the write side (F4/F5, code-review L10: the two gates read
     * alike on purpose): the write side only ever populates {@code holder_cnf} for a type that is
     * both AD-8 exempt and still unbound, but this is the last checkpoint before a persisted
     * {@code cnf} reaches a signed credential, and defense-in-depth here costs one profile lookup.
     */
    private Map<String, Object> resolveCnf(String processId, BindingInfo bindingInfo, Issuance proc, CredentialProfile profile) {
        Map<String, Object> fromProof = bindingInfo.cnf();
        if (fromProof != null && !fromProof.isEmpty()) {
            return fromProof;
        }
        if (!HolderBindingExemption.isExempt(proc.getCredentialType()) || profile.requiresHolderBinding()) {
            return Map.of();
        }
        try {
            return HolderCnfJson.readValidated(proc.getHolderCnf());
        } catch (InvalidHolderKeyException e) {
            // EUD-168 TD-14: the derivation-fallback audit event this used to trigger
            // (HolderDidFallbackAuditor, TD-09) is unreachable now that TD-13 fails closed here,
            // before that code is ever reached -- without this, a corrupted stored cnf would leave
            // no correlatable trace at all, only a generic warn/error log with no issuanceId.
            auditInvalidPersistedCnf(processId, proc.getIssuanceId().toString());
            throw e;
        }
    }

    /** Best-effort (ES-03/ES-04, same pattern as {@link HolderDidFallbackAuditor}): a broken audit
     *  channel must never mask the real failure -- log and let the original exception propagate. */
    private void auditInvalidPersistedCnf(String processId, String issuanceId) {
        try {
            auditService.auditFailure("credential.holder_cnf.invalid", null,
                    "persisted_holder_cnf_failed_revalidation",
                    Map.of("processId", processId, "issuanceId", issuanceId));
        } catch (RuntimeException e) {
            log.warn("processId={} issuanceId={} action=resolveCnf step=auditFailureFailed error={}",
                    processId, issuanceId, e.getMessage(), e);
        }
    }

    /**
     * The proof supplies the holder DID whenever one arrives. An AD-8 exempt type never takes that
     * path (no {@code proof_types_supported}, so no proof is ever requested), so its only source of a
     * holder identifier is the jwk that {@code resolveCnf} already resolved -- deriving the did:key
     * from it (delegated to {@link HolderDidFallbackAuditor}, shared with {@code IssuanceWorkflowImpl}'s
     * direct leg) is what makes {@code cnf} and {@code mandatee.id} agree on the same key pair (F2).
     */
    private String resolveHolderDid(String processId, String issuanceId, BindingInfo bindingInfo, Map<String, Object> cnf) {
        String fromProof = bindingInfo.subjectId();
        if (fromProof != null) {
            return fromProof.startsWith("did:") ? fromProof : null;
        }
        return holderDidFallbackAuditor.deriveFromJwkCnf(processId, issuanceId, cnf);
    }

    private Mono<CredentialResponse> enrichAndSign(
            String processId,
            Issuance proc,
            BindingInfo bindingInfo,
            String rawToken,
            String publicIssuerBaseUrl) {

        String issuanceId = proc.getIssuanceId().toString();
        String credentialType = proc.getCredentialType();
        String email = proc.getEmail();

        CredentialProfile profile = credentialProfileRegistry.getByConfigurationId(credentialType);
        if (profile == null) {
            return Mono.error(new FormatUnsupportedException("No profile for credential type: " + credentialType));
        }

        // The profile is the authority on the format, not the stored issuance row: the wallet asked
        // by credential_configuration_id and the Credential Issuer Metadata advertises
        // profile.format() for it, so that is what has to come back. A row written before the
        // profile carried a format (or before the profile was switched to dc+sd-jwt) leaves
        // credential_format NULL or jwt_vc_json, and honouring it silently downgrades the whole
        // chain: BITSTRING_VC instead of TOKEN_JWT for the status list, and a W3C
        // `credentialStatus` object instead of `status.status_list` inside an SD-JWT VC.
        String credentialFormat = firstNonBlank(profile.format(), proc.getCredentialFormat(), JWT_VC_JSON);
        if (proc.getCredentialFormat() != null && !credentialFormat.equals(proc.getCredentialFormat())) {
            log.warn(
                    "[{}] issuanceId={} configurationId={} stored credential_format={} differs from the profile's {}; issuing as {}",
                    processId, issuanceId, credentialType, proc.getCredentialFormat(), profile.format(), credentialFormat
            );
        }

        Map<String, Object> cnf = resolveCnf(processId, bindingInfo, proc, profile);
        String token = BEARER_PREFIX + rawToken;
        StatusListFormat statusFormat = DC_SD_JWT.equals(credentialFormat)
                ? StatusListFormat.TOKEN_JWT : StatusListFormat.BITSTRING_VC;

        // Step 1: Bind issuer to the credential dataSet (in memory, NOT persisted)
        return genericCredentialBuilder.bindIssuer(profile, proc.getCredentialDataSet(), issuanceId, email)
                .map(enrichedDataSet -> {
                    // Inject derived holder DID into mandatee.id when proof supplied a did:key-bound
                    // subject, or -- an AD-8 exempt type never takes the proof path (F2, S2) -- derive it
                    // from the cnf.jwk that resolveCnf sourced from the request instead. Either way,
                    // cnf.jwk and mandatee.id end up naming the same key pair.
                    String holderDid = resolveHolderDid(processId, issuanceId, bindingInfo, cnf);
                    return holderDid != null
                            ? genericCredentialBuilder.bindHolderDid(enrichedDataSet, holderDid)
                            : enrichedDataSet;
                })
                // Step 2: Allocate status list entry and inject credentialStatus
                .flatMap(enrichedDataSet -> statusListWorkflow.allocateEntry(StatusPurpose.REVOCATION, statusFormat, issuanceId, token, publicIssuerBaseUrl)
                        .map(entry -> {
                            CredentialStatus status = CredentialStatus.fromStatusListEntry(entry);
                            return genericCredentialBuilder.injectCredentialStatus(
                                    enrichedDataSet, status, credentialFormat);
                        })
                )
                .flatMap(enrichedWithStatus ->
                        // Step 3: Cache enriched dataSet for later persistence on credential_accepted
                        enrichmentCacheStore.add(issuanceId, enrichedWithStatus)
                                // Step 4: Sign using enriched data directly (no DB read)
                                .then(credentialSignerWorkflow.signCredential(
                                        token, enrichedWithStatus, credentialType,
                                        credentialFormat, cnf, issuanceId, email))
                )
                .flatMap(signedCredential -> {
                    // Step 5: Generate notification_id and cache mapping
                    String notificationId = UUID.randomUUID().toString();
                    return notificationCacheStore.add(notificationId, issuanceId)
                            // Step 5b: Mark delivery attempt timestamp for timeout detection
                            .then(issuanceService.getIssuanceById(issuanceId))
                            .flatMap(issuance -> {
                                issuance.setDeliveryAttemptedAt(Instant.now());
                                return issuanceService.updateIssuance(issuance);
                            })
                            .thenReturn(CredentialResponse.builder()
                                    .credentials(List.of(CredentialResponse.Credential.builder()
                                            .credential(signedCredential)
                                            .build()))
                                    .notificationId(notificationId)
                                    .build());
                })
                .doOnSuccess(resp -> log.info("[{}] Credential signed successfully for issuanceId={}", processId, issuanceId));
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return null;
    }

    // --- Proof validation logic (kept from existing implementation) ---

    private Mono<BindingInfo> validateAndDetermineBindingInfo(
            Issuance issuance,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest) {

        return resolveConfigurationId(issuance)
                .flatMap(configId -> findIssuerConfig(metadata, configId)
                        .flatMap(cfg -> evaluateCryptographicBinding(cfg, configId, metadata, credentialRequest))
                );
    }

    private Mono<String> resolveConfigurationId(Issuance issuance) {
        String configId = issuance.getCredentialType();
        if (configId == null || configId.isBlank()) {
            return Mono.error(new FormatUnsupportedException("Missing credential type in issuance"));
        }
        return Mono.just(configId);
    }

    private Mono<CredentialIssuerMetadata.CredentialConfiguration> findIssuerConfig(
            CredentialIssuerMetadata metadata, String configId) {
        return Mono.justOrEmpty(metadata.credentialConfigurationsSupported().get(configId))
                .switchIfEmpty(Mono.error(new FormatUnsupportedException(
                        "No configuration for configId: " + configId)));
    }

    private Mono<BindingInfo> evaluateCryptographicBinding(
            CredentialIssuerMetadata.CredentialConfiguration cfg,
            String credentialType,
            CredentialIssuerMetadata metadata,
            CredentialRequest credentialRequest) {

        // proof_types_supported, not cryptographic_binding_methods_supported (ADR-110): the former is
        // what obliges the wallet to send a proof -- OID4VCI 1.0 §8.2.6 makes `proofs` REQUIRED in the
        // Credential Request exactly when it is present. The latter describes how key material is
        // represented and is OPTIONAL, so reading it as a requirement confused format with obligation.
        // Deciding here on the same field the issuance path uses means the two cannot drift apart.
        var proofTypes = cfg.proofTypesSupported();
        boolean needsProof = proofTypes != null && !proofTypes.isEmpty();
        log.info("Binding requirement for {}: needsProof={}", credentialType, needsProof);

        if (!needsProof) {
            return Mono.empty();
        }

        Set<String> proofSigningAlgs = resolveProofSigningAlgorithms(cfg);
        String jwtProof = extractFirstJwtProof(credentialRequest);
        String expectedAudience = metadata.credentialIssuer();

        return validateProofAndExtractBindingInfo(jwtProof, proofSigningAlgs, expectedAudience, credentialType);
    }

    private Set<String> resolveProofSigningAlgorithms(CredentialIssuerMetadata.CredentialConfiguration cfg) {
        var proofTypes = cfg.proofTypesSupported();
        var jwtProofConfig = (proofTypes != null) ? proofTypes.get("jwt") : null;
        return (jwtProofConfig != null) ? jwtProofConfig.proofSigningAlgValuesSupported() : null;
    }

    // OID4VCI 1.0 Final §8.2 sends "proofs" (plural, batch-capable); older clients -
    // e.g. our own Wallet PWA, not yet migrated - still send "proof" (singular).
    // Prefer proofs when present, falling back to proof for backward compatibility.
    private String extractFirstJwtProof(CredentialRequest credentialRequest) {
        if (credentialRequest.proofs() != null
                && credentialRequest.proofs().jwt() != null
                && !credentialRequest.proofs().jwt().isEmpty()) {
            return credentialRequest.proofs().jwt().get(0);
        }
        return credentialRequest.proof() != null ? credentialRequest.proof().jwt() : null;
    }

    private Mono<BindingInfo> validateProofAndExtractBindingInfo(
            String jwtProof,
            Set<String> proofSigningAlgs,
            String expectedAudience,
            String credentialType) {

        if (proofSigningAlgs == null || proofSigningAlgs.isEmpty()) {
            return Mono.error(new ConfigurationException(
                    "No proof_signing_alg_values_supported for credential type " + credentialType));
        }

        if (jwtProof == null) {
            return Mono.error(new InvalidOrMissingProofException(
                    "Missing proof for type " + credentialType));
        }

        return proofValidationService.verifyProof(jwtProof, proofSigningAlgs, expectedAudience)
                .flatMap(valid -> {
                    if (!Boolean.TRUE.equals(valid)) {
                        return Mono.error(new InvalidOrMissingProofException("Invalid proof"));
                    }
                    return extractBindingInfoFromJwtProof(jwtProof);
                });
    }

    private Mono<BindingInfo> extractBindingInfoFromJwtProof(String jwtProof) {
        return Mono.fromCallable(() -> {
            JWSObject jws = JWSObject.parse(jwtProof);
            var header = jws.getHeader().toJSONObject();

            Object kid = header.get("kid");
            Object jwk = header.get("jwk");
            Object x5c = header.get("x5c");

            int count = (kid != null ? 1 : 0) + (jwk != null ? 1 : 0) + (x5c != null ? 1 : 0);
            if (count != 1) {
                throw new ProofValidationException("Expected exactly one of kid/jwk/x5c in proof header");
            }

            if (kid != null) {
                return buildFromKid(kid);
            } else if (x5c != null) {
                throw new ProofValidationException("x5c not supported yet");
            } else if (jwk != null) {
                return buildFromJwk(jwk);
            }

            throw new ProofValidationException("No key material found in proof header");
        });
    }

    private BindingInfo buildFromKid(Object kid) {
        String kidStr = kid.toString();
        String subjectId = kidStr.contains("#") ? kidStr.split("#")[0] : kidStr;
        log.info("Binding from proof: cnfType=kid, subjectId={}", subjectId);
        return new BindingInfo(subjectId, Map.of("kid", kidStr));
    }

    @SuppressWarnings("unchecked")
    private BindingInfo buildFromJwk(Object jwk) throws ProofValidationException {
        if (!(jwk instanceof Map<?, ?> jwkMap)) {
            throw new ProofValidationException("jwk must be a JSON object");
        }
        var jwkObj = (Map<String, Object>) jwkMap;
        String subjectId = DidKeyDerivation.deriveDidKeyFromJwk(jwkObj);
        log.info("Binding from proof: cnfType=jwk, subjectId={}", subjectId);
        return new BindingInfo(subjectId, Map.of("jwk", jwkObj));
    }

}
