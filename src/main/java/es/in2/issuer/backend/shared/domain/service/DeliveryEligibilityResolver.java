package es.in2.issuer.backend.shared.domain.service;

import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resolves the delivery modes effectively eligible for a {@code credential_configuration_id}:
 * {@code tenant configuration ∩ schema ceiling}, with the ceiling as the default when no
 * configuration exists (ADR-110, EUD-168).
 *
 * <p>Intersecting rather than merely defaulting is the point. A configuration stored before the
 * ceiling existed may still list {@code direct} for a type whose schema forbids it; honouring it would
 * show the admin a mode that issuance rejects, which is exactly the divergence this replaces.
 *
 * <p>Issuance-time enforcement lives in {@code IssuanceWorkflowImpl#resolveAndValidateDeliveryModes}
 * and applies the same two rules in the same order, so the admin view can never promise what issuance
 * would refuse.
 */
@Service
@RequiredArgsConstructor
public class DeliveryEligibilityResolver {

    private final TenantCredentialProfileService tenantCredentialProfileService;
    private final SchemaDeliveryCeiling schemaDeliveryCeiling;

    public Mono<Set<DeliveryMode>> resolveEligibleModes(String credentialConfigurationId) {
        // Deferred rather than resolved eagerly above: schemaDeliveryCeiling.resolveEligibleModes can
        // throw for an unknown configuration ID, and a caller composing this Mono outside a defer of its
        // own must still see that failure as an onError signal, not an assembly-time exception.
        return Mono.fromSupplier(() -> schemaDeliveryCeiling.resolveEligibleModes(credentialConfigurationId))
                .flatMap(ceiling -> tenantCredentialProfileService.findConfiguredDeliveryModes(credentialConfigurationId)
                        // findConfiguredDeliveryModes emits an empty Set for "enabled but unconfigured"
                        // (AD-8 sentinel, defaults to the ceiling below) -- never an empty Mono for that
                        // case, so the ceiling fallback branches on Set emptiness here, not on
                        // Mono#switchIfEmpty (which would never fire and would incorrectly return an
                        // empty result instead of the ceiling, EC-09 vs P-1). A genuinely not-enabled
                        // type instead errors (security review, F6) and propagates untouched here --
                        // fail-closed, no onErrorReturn/onErrorResume.
                        .map(configured -> configured.isEmpty()
                                ? ceiling
                                : configured.stream()
                                        .filter(ceiling::contains)
                                        .collect(Collectors.toCollection(() -> EnumSet.noneOf(DeliveryMode.class)))));
    }

}
